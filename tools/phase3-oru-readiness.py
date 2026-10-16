#!/usr/bin/env python3
"""Scoped O-RU readiness gate. Retained recovery never replays ONAP or setup."""
import argparse
from contextlib import nullcontext
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import yaml

import phase3_oru_readiness as contract

ROOT=Path(__file__).resolve().parents[1]
CONTEXT=Path('/local/setup/phase3-smo/fresh-start/context.json')
ACCEPTED_COMMIT='f952ce58fc5b671a8b296274690455949f1c5d16'
PREFIX='oru-readiness-'


def command(args,data=None,timeout=90):
    result=subprocess.run(args,input=data,capture_output=True,timeout=timeout)
    if result.returncode:raise contract.Blocked('Required private diagnostic failed: '+Path(args[0]).name)
    return result.stdout


def get(kind,name=None,namespace='onap',optional=False):
    args=['kubectl']+(['-n',namespace] if namespace else [])+['get',kind]+([name] if name else [])
    blob=command(args+(['--ignore-not-found'] if optional else [])+['-o','json'])
    return json.loads(blob) if blob.strip() else None


def digest(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise contract.Blocked('Evidence must be regular and not symlinked')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    digest(path)
    return json.loads(Path(path).read_bytes())


def write(path,value):
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(contract.canonical(value));stream.flush();os.fsync(stream.fileno())
    fd=os.open(str(Path(path).parent),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def load(root,name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(root)/'bin'/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def accepted_checkout(path,fresh=False):
    path=Path(path).resolve()
    if not fresh:
        if (command(['git','-C',str(path),'rev-parse','HEAD']).decode().strip()!=ACCEPTED_COMMIT
                or command(['git','-C',str(path),'status','--porcelain','--untracked-files=no']).strip()):
            raise contract.Blocked('Historical acceptance checkout must remain clean at its exact pin')
    sys.path.insert(0,str(path/'bin'))
    return load(path,'oru_accepted_dmaap','phase3-dmaap-recovery.py')


def targets():
    return contract.dependencies(get('pods')['items'],get('replicasets')['items'],get('deployments')['items'])


def oru_pod():
    pods=[p for p in get('pods',namespace='nonrtric')['items'] if p['metadata'].get('labels',{}).get('name')=='oru-app']
    if len(pods)!=1:raise contract.Blocked('Expected the one retained O-RU Pod')
    return pods[0]


def seal(directory):
    write(directory/'SHA256SUMS.json',{p.name:digest(p) for p in directory.iterdir()})
    return {'directory':str(directory),'ledger_sha256':digest(directory/'SHA256SUMS.json')}


def verify_archive(record):
    directory=Path(record['directory']);ledger=read(directory/'SHA256SUMS.json')
    if (directory.is_symlink() or digest(directory/'SHA256SUMS.json')!=record['ledger_sha256']
            or set(ledger)!={p.name for p in directory.iterdir() if p.name!='SHA256SUMS.json'}
            or any(Path(n).name!=n or digest(directory/n)!=h for n,h in ledger.items())):
        raise contract.Blocked('Private evidence archive changed')


def preserve(path,gate,pod=None,label='snapshot'):
    directory=Path(tempfile.mkdtemp(prefix=PREFIX+label+'-',dir=str(path.parent.parent)))
    objects={'onap-resources.json':get('deployments,statefulsets,jobs,pvc'),
             'onap-rbac.json':get('roles,rolebindings'),
             'nonrtric-resources.json':get('deployments,statefulsets,pods,serviceaccounts,roles,rolebindings',namespace='nonrtric'),
             'dmaap-journal.json':get('configmap','phase3-dmaap-journal')}
    if pod:objects['pod.json']=pod
    for name,obj in objects.items():write(directory/name,obj)
    for name in ('context.json','sms-backend-acceptance.json','sms-preload-acceptance.json',
                 'dmaap-postexecution-acceptance.json','dmaap-acceptance.json','onap-acceptance.json'):
        if (path.parent/name).is_file():
            fd=os.open(str(directory/name),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as out:out.write((path.parent/name).read_bytes())
    if pod:
        for container in pod['spec'].get('initContainers',[]):
            status=next((s for s in pod['status'].get('initContainerStatuses',[]) if s['name']==container['name']),{})
            if status.get('state',{}).get('running') or status.get('state',{}).get('terminated'):
                blob=command(['kubectl','-n','nonrtric','logs',pod['metadata']['name'],'-c',container['name'],'--timestamps=true'])
                (directory/(container['name']+'.log')).write_bytes(blob);os.chmod(directory/(container['name']+'.log'),0o600)
    return seal(directory)


def history(path,gate,pod,allow_restarts):
    count=pod['status']['initContainerStatuses'][0].get('restartCount',0)
    if count and not allow_restarts:raise contract.Blocked('Readiness-only restart needs explicit reviewed opt-in')
    if not count:return []
    # Collect the currently available previous attempt, then require continuous
    # archive coverage back to attempt zero. Missing rotated logs are a hard stop.
    directory=Path(tempfile.mkdtemp(prefix='oru-readonly-history-',dir=str(path.parent.parent)))
    write(directory/'pod.json',pod)
    for previous,name in ((False,'current'),(True,'previous')):
        blob=command(['kubectl','-n','nonrtric','logs',pod['metadata']['name'],'-c',
                     'oru-app-cert-initializer-readiness','--timestamps=true']+(['--previous'] if previous else []))
        (directory/(name+'.stdout')).write_bytes(blob);os.chmod(directory/(name+'.stdout'),0o600)
    for name,remote in (('ready.py','/app/ready.py'),('wrapper.py','/phase3-helpers/phase3-readiness-wrapper.py')):
        blob=command(['kubectl','-n','nonrtric','exec',pod['metadata']['name'],'-c',
                      'oru-app-cert-initializer-readiness','--','cat',remote])
        (directory/name).write_bytes(blob);os.chmod(directory/name,0o600)
    seal(directory)
    covered={}
    for directory in sorted(path.parent.parent.glob('oru-readonly-history-*')):
        saved=read(directory/'pod.json')
        if saved['metadata']['uid']!=pod['metadata']['uid']:continue
        record={'directory':str(directory),'ledger_sha256':digest(directory/'SHA256SUMS.json')};verify_archive(record)
        if (digest(directory/'ready.py')!=contract.SOURCE_SHA256
                or digest(directory/'wrapper.py')!=digest(gate.ROOT/'bin/phase3-readiness-wrapper.py')):
            raise contract.Blocked('Readiness restart source changed')
        status=saved['status']['initContainerStatuses'][0];index=status.get('restartCount',0)-1
        terminated=status.get('lastState',{}).get('terminated',{})
        logs=(directory/'previous.stdout').read_bytes();lines=logs.decode().splitlines()
        if (index<0 or index>=count or not lines or terminated.get('exitCode')!=1
                or terminated.get('reason')!='Error' or not terminated.get('startedAt') or not terminated.get('finishedAt')):
            raise contract.Blocked('Incomplete readiness-only termination history')
        first=gate.timestamp(lines[0].split()[0]);last=gate.timestamp(lines[-1].split()[0])
        start=gate.timestamp(terminated['startedAt']);end=gate.timestamp(terminated['finishedAt'])
        if (abs((first-start).total_seconds())>3 or not 0<=(end-last).total_seconds()<=5
                or b'403' not in logs or b'Forbidden' not in logs):
            raise contract.Blocked('Readiness log does not cover the full denied-read attempt')
        covered.setdefault(index,record)
    if set(covered)!=set(range(count)):raise contract.Blocked('Rotated readiness history has a gap; no replay')
    return [covered[i] for i in range(count)]


def workload_binding():
    items=get('deployments,statefulsets,pvc',namespace='nonrtric')['items']
    return {o['kind']+'/'+o['metadata']['name']:{'uid':o['metadata']['uid'],'spec_sha256':contract.sha(o['spec'])} for o in items}


def chart_binding(gate,path):
    work=path.parent.parent;lock=read(work/'chart-lock.json');result={}
    for name in ('nonrtric','ru-du-simulators'):
        changes=read(work/'prepared'/(name+'-changes.json'));archive=work/'prepared'/(name+'.tgz')
        if changes['original_sha256']!=lock['charts'][name]['sha256'] or digest(archive)!=changes['prepared_sha256']:
            raise contract.Blocked('Prepared chart/lock changed')
        result[name]=digest(archive)
    values=work/'dep/smo-install/helm-override/powder'
    result['values']={n:digest(values/n) for n in ('oran-override.yaml','network-simulators-override.yaml','network-simulators-topology-override.yaml')}
    return result


def rendered_manifest(gate,path):
    work=path.parent.parent
    blob=command(['helm','template','oran-nonrtric',str(work/'prepared/nonrtric.tgz'),
        '--namespace','nonrtric','--kube-version','v1.34.3','--is-upgrade',
        '-f',str(work/'dep/smo-install/helm-override/powder/oran-override.yaml')],timeout=120)
    env=dict(os.environ,PHASE3_FRESH_CONTEXT=str(path))
    p=subprocess.run([str(gate.ROOT/'bin/phase3-fresh-renderer.py')],input=blob,env=env,capture_output=True,timeout=120)
    if p.returncode:raise contract.Blocked('Private retained render failed')
    return list(yaml.safe_load_all(p.stdout))


def release_binding():
    status=json.loads(command(['helm','status','oran-nonrtric','-n','nonrtric','-o','json']))
    manifest=command(['helm','get','manifest','oran-nonrtric','-n','nonrtric'])
    hooks=list(yaml.safe_load_all(command(['helm','get','hooks','oran-nonrtric','-n','nonrtric'])))
    if any(o and (o.get('metadata',{}).get('annotations') or {}).get('helm.sh/hook')!='test' for o in hooks):
        raise contract.Blocked('Retained release has non-test hooks')
    return {'revision':status['version'],'status':status['info']['status'],
            'manifest_sha256':hashlib.sha256(manifest).hexdigest()},list(yaml.safe_load_all(manifest))


def protected(gate,path,expected_slice):
    context=gate.fresh.verify_context(path)
    if context['slice_urn']!=expected_slice or command(['hostname']).decode().split('.')[0].strip()!='node-0':
        raise contract.Blocked('Recovery allocation/host changed')
    acceptance=gate.verify_acceptance(path)
    if acceptance is None or not (path.parent/'onap-acceptance.json').is_file():
        raise contract.Blocked('Current DMAAP/ONAP acceptance required')
    # Invoke the historically pinned verifier; never rebase its code binding.
    gate.load('oru_onap_gate','phase3-onap-resume-gate.py').check(context_path=str(path))
    inventory,completed=gate.protected()
    return {'slice_urn':expected_slice,'context_sha256':digest(path),'inventory':inventory,'completed_jobs':completed,
        'acceptances':{n:digest(path.parent/n) for n in ('sms-backend-acceptance.json','sms-preload-acceptance.json','onap-acceptance.json')},
        'dmaap_acceptance':acceptance,'accepted_checkout':str(gate.ROOT),'charts':chart_binding(gate,path)}


def review_binding(gate,path,expected_slice,allow_restarts):
    pod=oru_pod();count=pod['status']['initContainerStatuses'][0].get('restartCount',0)
    contract.check_pod(pod,unattempted=True,readiness_restarts=count if allow_restarts else 0)
    archives=history(path,gate,pod,allow_restarts)
    source=command(['kubectl','-n','nonrtric','exec',pod['metadata']['name'],'-c',
                    'oru-app-cert-initializer-readiness','--','cat','/app/ready.py'])
    if hashlib.sha256(source).hexdigest()!=contract.SOURCE_SHA256:raise contract.Blocked('Pinned readiness source changed')
    dependencies=targets();release,manifest=release_binding()
    if release['status']!='failed':raise contract.Blocked('Expected retained failed release')
    contract.identical_manifests(manifest,rendered_manifest(gate,path))
    if get('secret',namespace='network')['items'] or get('deployments,statefulsets,pods',namespace='network')['items']:
        raise contract.Blocked('NTS namespace already has attempted state')
    for obj in contract.resources(dependencies):
        if get(obj['kind'],obj['metadata']['name'],optional=True) is not None:
            raise contract.Blocked('Scoped readiness RBAC already exists; no overwrite')
    sa=get('serviceaccount',contract.SA,namespace='nonrtric')
    stopped=[]
    for directory in path.parent.parent.glob('nonrtric-readiness-blocker-*'):
        receipt=directory/'stop-receipt.json'
        if receipt.is_file():
            record=read(receipt)
            if record.get('blocker_pod_uid')==pod['metadata']['uid'] and record.get('owned_waiter_stopped') is True:
                archive={'directory':str(directory),'ledger_sha256':digest(directory/'SHA256SUMS.json')}
                verify_archive(archive);stopped.append(archive)
    if len(stopped)!=1:raise contract.Blocked('Preserved owned-waiter stop evidence missing or ambiguous')
    return {'schema':1,'protected':protected(gate,path,expected_slice),'targets':dependencies,
        'pod_uid':pod['metadata']['uid'],'pod_name':pod['metadata']['name'],'pod_spec_sha256':contract.sha(pod['spec']),
        'readiness_restarts':count,'readiness_history':archives,'waiter_stop_archive':stopped[0],
        'serviceaccount_uid':sa['metadata']['uid'],
        'release':release,'workloads':workload_binding(),'proposed_rbac':contract.resources(dependencies),
        'code_sha256':{p.name:digest(p) for p in (Path(__file__),ROOT/'tools/phase3_oru_readiness.py')}}


def check_history_binding(before,after):
    # Repeated audit may create an additional equivalent archive. The original
    # continuous-history evidence remains independently bound and verified.
    old=before.pop('readiness_history');new=after.pop('readiness_history')
    for record in old:verify_archive(record)
    if len(old)!=len(new) or before!=after:raise contract.Blocked('Reviewed recovery binding changed')


def probe_identity(binding):
    identity='system:serviceaccount:nonrtric:'+contract.SA
    prefix=['kubectl','--as='+identity,'--as-group=system:serviceaccounts',
            '--as-group=system:serviceaccounts:nonrtric','--as-group=system:authenticated']
    checks=[('list','pods','onap',None,True)]
    for target in binding['targets']:
        checks.extend([('get','replicasets.apps/'+target['replicaset'],'onap','status',True),
                       ('get','deployments.apps/'+target['deployment'],'onap',None,True)])
    checks.extend([('list','secrets','onap',None,False),('create','pods','onap',None,False),
                   ('create','pods','onap','exec',False),('list','pods','kube-system',None,False)])
    for verb,resource,namespace,subresource,expected in checks:
        p=subprocess.run(prefix+['auth','can-i',verb,resource,'-n',namespace]+(
            ['--subresource='+subresource] if subresource else []),capture_output=True,timeout=45)
        if p.returncode not in (0,1) or p.stdout.strip()!=(b'yes' if expected else b'no'):
            raise contract.Blocked('Scoped identity authorization differs from review')


def observed_rbac(binding):
    objects={}
    for expected in binding['proposed_rbac']:
        actual=get(expected['kind'],expected['metadata']['name'])
        objects[expected['kind']]=contract.check_resource(actual,expected)
    return objects


def wait_existing_pod(binding,timeout=600):
    deadline=time.monotonic()+timeout
    while True:
        pod=oru_pod();states=contract.check_pod(pod,binding['pod_uid'],readiness_restarts=binding['readiness_restarts'])
        if contract.sha(pod['spec'])!=binding['pod_spec_sha256']:raise contract.Blocked('O-RU admitted Pod spec changed')
        if all(s.get('terminated',{}).get('exitCode')==0 for s in states.values()):
            statuses=pod['status'].get('containerStatuses',[])
            if any(s.get('restartCount') or s.get('lastState') for s in statuses):
                raise contract.Blocked('O-RU application restarted; separate review required')
            if statuses and all(s.get('ready') for s in statuses):return pod
        if time.monotonic()>=deadline:raise contract.Blocked('O-RU readiness/agent/app deadline elapsed; no replay')
        time.sleep(5)


def apply(gate,path,expected_slice,review_path,allow_restarts):
    approved=read(review_path);created=datetime.fromisoformat(approved['created_utc'])
    if not 0<=(datetime.now(timezone.utc)-created).total_seconds()<=1800:raise contract.Blocked('O-RU review expired')
    latch=path.parent/(PREFIX+'attempt.json')
    if latch.exists() or (path.parent/(PREFIX+'acceptance.json')).exists():raise contract.Blocked('O-RU latch exists; no replay')
    current=review_binding(gate,path,expected_slice,allow_restarts)
    check_history_binding(json.loads(json.dumps(approved['binding'])),json.loads(json.dumps(current)))
    archive=preserve(path,gate,oru_pod(),'before')
    write(latch,{'schema':1,'review_file':str(review_path.resolve()),'review_sha256':digest(review_path),
                 'binding_sha256':contract.sha(approved['binding']),'private_archive':archive})
    created_objects={}
    for obj in current['proposed_rbac']:
        actual=json.loads(command(['kubectl','create','-f','-','-o','json'],contract.canonical(obj)))
        created_objects[obj['kind']]=contract.check_resource(actual,obj)
        write(path.parent/(PREFIX+'created-'+obj['kind'].lower()+'.json'),created_objects[obj['kind']])
    probe_identity(current)
    pod=wait_existing_pod(current)
    if protected(gate,path,expected_slice)!=current['protected'] or workload_binding()!=current['workloads']:
        raise contract.Blocked('Protected state changed during O-RU recovery')
    write(path.parent/(PREFIX+'acceptance.json'),{'schema':1,'passed':True,'accepted_utc':datetime.now(timezone.utc).isoformat(),
        'review_file':str(review_path.resolve()),'review_sha256':digest(review_path),'rbac':created_objects,
        'pod_uid':pod['metadata']['uid'],'latch_sha256':digest(latch),'private_archive':preserve(path,gate,pod,'accepted')})


def verify(gate,path,expected_slice):
    receipt=read(path.parent/(PREFIX+'acceptance.json'));review_path=Path(receipt['review_file']);review=read(review_path)
    binding=review['binding'];latch=read(path.parent/(PREFIX+'attempt.json'))
    if (receipt.get('passed') is not True or digest(review_path)!=receipt['review_sha256']
            or digest(path.parent/(PREFIX+'attempt.json'))!=receipt['latch_sha256']
            or latch['binding_sha256']!=contract.sha(binding) or latch['review_sha256']!=digest(review_path)):
        raise contract.Blocked('O-RU acceptance evidence changed')
    verify_archive(receipt['private_archive']);verify_archive(latch['private_archive'])
    verify_archive(binding['waiter_stop_archive'])
    if binding['code_sha256']!={p.name:digest(p) for p in (Path(__file__),ROOT/'tools/phase3_oru_readiness.py')}:
        raise contract.Blocked('Reviewed O-RU coordinator code changed')
    if protected(gate,path,expected_slice)!=binding['protected'] or targets()!=binding['targets']:
        raise contract.Blocked('O-RU protected acceptance changed')
    if get('serviceaccount',contract.SA,namespace='nonrtric')['metadata']['uid']!=binding['serviceaccount_uid']:
        raise contract.Blocked('O-RU ServiceAccount replaced')
    if observed_rbac(binding)!=receipt['rbac'] or workload_binding()!=binding['workloads']:
        raise contract.Blocked('O-RU workloads/RBAC identity changed')
    pod=wait_existing_pod(binding,timeout=1)
    if pod['metadata']['uid']!=receipt['pod_uid']:raise contract.Blocked('Accepted O-RU Pod replaced')
    return binding


def helm_logged(path,label,args,gate):
    log=path.parent.parent/(PREFIX+label+'-'+str(time.time_ns())+'.log')
    env=dict(os.environ,PHASE3_FRESH_CONTEXT=str(path))
    with log.open('xb') as stream:
        os.chmod(log,0o600)
        p=subprocess.Popen(args,stdout=stream,stderr=subprocess.STDOUT,env=env,start_new_session=True)
        try:
            code=p.wait(timeout=1300)
        except BaseException:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=30)
            except subprocess.TimeoutExpired:raise contract.Blocked('Owned Helm waiter stop unconfirmed')
            raise
    if code:raise contract.Blocked('Normal '+label+' gate failed; private logs preserved')


def continue_startup(gate,path,expected_slice):
    binding=verify(gate,path,expected_slice)
    latch=path.parent/(PREFIX+'continuation-attempt.json')
    if latch.exists():raise contract.Blocked('Retained continuation already attempted; no retry')
    release,manifest=release_binding()
    if release!=binding['release']:raise contract.Blocked('Retained release changed before continuation')
    contract.identical_manifests(manifest,rendered_manifest(gate,path))
    write(latch,{'schema':1,'binding_sha256':contract.sha(binding),'started_utc':datetime.now(timezone.utc).isoformat()})
    work=path.parent.parent;values=work/'dep/smo-install/helm-override/powder';renderer=str(gate.ROOT/'bin/phase3-fresh-renderer.py')
    helm_logged(path,'nonrtric',['helm','upgrade','oran-nonrtric',str(work/'prepared/nonrtric.tgz'),
        '-n','nonrtric','--no-hooks','--post-renderer',renderer,'-f',str(values/'oran-override.yaml'),'--wait','--timeout','10m'],gate)
    after,manifest_after=release_binding()
    if after['status']!='deployed' or after['revision']!=release['revision']+1:
        raise contract.Blocked('Non-RT RIC release reconciliation not established')
    contract.identical_manifests(manifest,manifest_after)
    if workload_binding()!=binding['workloads']:raise contract.Blocked('Non-RT RIC workload rollout/spec changed')
    if get('deployments,statefulsets,pods',namespace='network')['items']:
        raise contract.Blocked('NTS runtime already attempted; no replay')
    helm_logged(path,'simulator',['helm','install','oran-simulator',str(work/'prepared/ru-du-simulators.tgz'),
        '-n','network','--no-hooks','--post-renderer',renderer,'-f',str(values/'network-simulators-override.yaml'),
        '-f',str(values/'network-simulators-topology-override.yaml'),'--wait','--timeout','20m'],gate)
    verify(gate,path,expected_slice)
    # Normal readiness/provenance, executed by the original accepted checkout.
    helm_logged(path,'final-check',[sys.executable,str(gate.ROOT/'bin/collect-phase3-provenance.py'),
        '--output',str(work/'provenance.json'),'--require-ready'],gate)
    helm_logged(path,'completion',[str(gate.ROOT/'setup-end.sh')],gate)
    write(path.parent/(PREFIX+'completion.json'),{'schema':1,'passed':True,'completed_utc':datetime.now(timezone.utc).isoformat(),
        'rbac_acceptance_sha256':digest(path.parent/(PREFIX+'acceptance.json')),'certificate_fault_cases_started':False})
    for name in ('setup-oran-smo-done','setup-driver-done'):
        write(path.parent.parent.parent/name,{'verified_recovery_completion':True})


def fresh(gate,path,expected_slice):
    context=read(path);contract.fresh_contract(context)
    baseline=protected(gate,path,expected_slice)
    if get('deployments,statefulsets,pods',namespace='nonrtric')['items']:
        raise contract.Blocked('Fresh non-RT RIC installation already attempted')
    latch=path.parent/(PREFIX+'fresh-attempt.json')
    if latch.exists():raise contract.Blocked('Fresh readiness RBAC already attempted')
    dep=targets();objects=contract.resources(dep)
    if any(get(o['kind'],contract.NAME,optional=True) for o in objects):raise contract.Blocked('Fresh RBAC name collision')
    write(latch,{'schema':1,'protected':baseline,'targets':dep})
    created={}
    for o in objects:
        actual=json.loads(command(['kubectl','create','-f','-','-o','json'],contract.canonical(o)))
        created[o['kind']]=contract.check_resource(actual,o)
    write(path.parent/(PREFIX+'fresh-grant.json'),{'schema':1,'passed':True,'targets':dep,'rbac':created})


def verify_fresh(path,bind_identity=False):
    contract.fresh_contract(read(path));grant=read(path.parent/(PREFIX+'fresh-grant.json'))
    if grant.get('passed') is not True or targets()!=grant['targets']:
        raise contract.Blocked('Fresh readiness target binding changed')
    if observed_rbac({'proposed_rbac':contract.resources(grant['targets'])})!=grant['rbac']:
        raise contract.Blocked('Fresh readiness RBAC changed')
    pod=oru_pod();states=contract.check_pod(pod)
    statuses=pod['status'].get('containerStatuses',[])
    if (not statuses or not all(s.get('ready') for s in statuses)
            or not all(s.get('terminated',{}).get('exitCode')==0 for s in states.values())):
        raise contract.Blocked('Fresh O-RU app is not Ready')
    sa=get('serviceaccount',contract.SA,namespace='nonrtric');identity=path.parent/(PREFIX+'fresh-identity.json')
    expected={'serviceaccount_uid':sa['metadata']['uid'],'pod_uid':pod['metadata']['uid']}
    if identity.exists():
        if read(identity)!=expected:raise contract.Blocked('Fresh O-RU identity replaced')
    elif bind_identity:write(identity,expected)
    else:raise contract.Blocked('Fresh O-RU identity acceptance missing')
    probe_identity({'targets':grant['targets']})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('audit','apply','continue','verify','fresh','verify-fresh'))
    parser.add_argument('--expected-slice',required=True);parser.add_argument('--context',type=Path,default=CONTEXT)
    parser.add_argument('--review-file',type=Path);parser.add_argument('--accepted-checkout',type=Path)
    parser.add_argument('--allow-readiness-only-restarts',action='store_true')
    parser.add_argument('--bind-fresh-identity',action='store_true')
    args=parser.parse_args();os.umask(0o077)
    def cancelled(signum,frame):raise KeyboardInterrupt('Owned recovery cancelled')
    signal.signal(signal.SIGTERM,cancelled)
    try:
        fresh_mode=args.action in ('fresh','verify-fresh')
        if not fresh_mode and not args.accepted_checkout:raise contract.Blocked('Pinned historical checkout required')
        gate=accepted_checkout(args.accepted_checkout or ROOT,fresh=fresh_mode)
        lock=(nullcontext() if args.action in ('verify','verify-fresh') and not args.bind_fresh_identity
              else gate.backend.driver_lock())
        if args.bind_fresh_identity and args.action!='verify-fresh':raise contract.Blocked('Fresh identity flag requires verify-fresh')
        with lock:
            if args.action=='audit':
                if not args.review_file:raise contract.Blocked('Private review path required')
                binding=review_binding(gate,args.context,args.expected_slice,args.allow_readiness_only_restarts)
                write(args.review_file,{'schema':1,'created_utc':datetime.now(timezone.utc).isoformat(),'binding':binding})
            elif args.action=='apply':
                if not args.review_file:raise contract.Blocked('Private review path required')
                apply(gate,args.context,args.expected_slice,args.review_file,args.allow_readiness_only_restarts)
            elif args.action=='continue':continue_startup(gate,args.context,args.expected_slice)
            elif args.action=='verify':verify(gate,args.context,args.expected_slice)
            elif args.action=='fresh':fresh(gate,args.context,args.expected_slice)
            else:verify_fresh(args.context,args.bind_fresh_identity)
        print('O-RU readiness gate passed; certificate research remains separate');return 0
    except BaseException as error:
        if args.context.parent.is_dir():
            name=PREFIX+'blocked-'+str(time.time_ns())+'.json'
            write(args.context.parent/name,{'schema':1,'stage':args.action,'failure_type':type(error).__name__,
                'reason':str(error) if isinstance(error,contract.Blocked) else 'private-validation-error',
                'provisioning_replayed':False,'certificate_fault_cases_started':False})
            write(args.context.parent/(name+'.private-trace.json'),{'traceback':traceback.format_exc()})
        print('O-RU readiness gate blocked; private evidence retained; no reset/replay');return 2


if __name__=='__main__':raise SystemExit(main())
