#!/usr/bin/env python3
"""Internal-only Kong policy and a separate, no-replay retained recovery."""
import argparse
from contextlib import nullcontext
from datetime import datetime,timezone
import hashlib
import http.client
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
import phase3_kong_proxy as policy

ROOT=Path(__file__).resolve().parents[1]
CONTEXT=Path('/local/setup/phase3-smo/fresh-start/context.json')
ORU_COMMIT='26480b1d0af9ae352172197730d617ad094f93f0'
PREFIX='kong-proxy-'


def load_tool(root,name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(root)/'tools'/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


util=load_tool(ROOT,'kong_runtime_utils','phase3-oru-readiness.py')
read,write,digest,command,get=util.read,util.write,util.digest,util.command,util.get


def pins(args):
    root=args.accepted_oru_checkout.resolve()
    if (command(['git','-C',str(root),'rev-parse','HEAD']).decode().strip()!=ORU_COMMIT
            or command(['git','-C',str(root),'status','--porcelain','--untracked-files=no']).strip()):
        raise policy.Blocked('Historical O-RU acceptance checkout must remain clean at its pin')
    old=load_tool(root,'kong_accepted_oru','phase3-oru-readiness.py')
    return old,old.accepted_checkout(args.accepted_dmaap_checkout)


def endpoints():
    blob=command(['kubectl','-n','nonrtric','get','endpointslice','-l',
                  'kubernetes.io/service-name='+policy.NAME,'-o','json'])
    return json.loads(blob)['items']


def runtime():
    pods=get('pods',namespace='nonrtric')['items']
    return {'pods':policy.pods_binding(pods),'workloads':util.workload_binding(),
            'endpoints':policy.endpoints_binding(endpoints(),pods)}


def service():return get('service',policy.NAME,namespace='nonrtric')


def probe(svc):
    # Payload-free, unauthenticated root request, no redirect or TLS bypass.
    conn=http.client.HTTPConnection(svc['spec']['clusterIP'],80,timeout=10)
    try:
        conn.request('GET','/');response=conn.getresponse();response.read(4096)
        if response.status>=500 or response.status<200:raise policy.Blocked('Kong proxy root probe failed')
        return {'http_status':response.status,'route_or_authenticated_application_validated':False}
    finally:conn.close()


def empty_network():
    if (json.loads(command(['helm','list','-n','network','--all','-o','json']))
            or get('deployments,statefulsets,pods,pvc,secrets',namespace='network')['items']):
        raise policy.Blocked('NTS has existing or attempted state; no replay')


def historical(old,gate,path,slice_urn):
    binding=old.verify(gate,path,slice_urn)
    names=('context.json','sms-backend-acceptance.json','sms-preload-acceptance.json',
        'dmaap-postexecution-acceptance.json','onap-acceptance.json','oru-readiness-attempt.json',
        'oru-readiness-acceptance.json','oru-readiness-continuation-attempt.json')
    return {'oru_binding_sha256':policy.sha(binding),'receipts':{n:digest(path.parent/n) for n in names},
            'oru_checkout':str(old.ROOT),'dmaap_checkout':str(gate.ROOT)}


def render(gate,path,override):
    work=path.parent.parent;values=work/'dep/smo-install/helm-override/powder'
    blob=command(['helm','template','oran-nonrtric',str(work/'prepared/nonrtric.tgz'),
        '-n','nonrtric','--kube-version','v1.34.3','--is-upgrade',
        '-f',str(values/'oran-override.yaml'),'-f',str(override)],timeout=120)
    p=subprocess.run([str(gate.ROOT/'bin/phase3-fresh-renderer.py')],input=blob,
        env=dict(os.environ,PHASE3_FRESH_CONTEXT=str(path)),capture_output=True,timeout=120)
    if p.returncode:raise policy.Blocked('Private Kong comparison render failed')
    return list(yaml.safe_load_all(p.stdout))


def blocker_archive(path,svc,release,selection):
    if (not isinstance(selection,dict) or set(selection)!={'directory','ledger_sha256'}
            or not isinstance(selection['directory'],str)
            or not isinstance(selection['ledger_sha256'],str)
            or len(selection['ledger_sha256'])!=64
            or any(c not in '0123456789abcdef' for c in selection['ledger_sha256'])):
        raise policy.Blocked('Explicit preserved Kong archive path and SHA-256 required')
    selected=Path(selection['directory'])
    if (not selected.is_absolute() or selected.parent!=path.parent.parent
            or not selected.name.startswith('nonrtric-kong-lb-blocker-') or selected.is_symlink()):
        raise policy.Blocked('Selected Kong archive is outside the preserved evidence directory')
    records=[]
    for directory in sorted(path.parent.parent.glob('nonrtric-kong-lb-blocker-*')):
        record={'directory':str(directory),'ledger_sha256':digest(directory/'SHA256SUMS.json')}
        util.verify_archive(record)
        saved=read(directory/'kong-service.json');status=read(directory/'helm-status.json')
        if (saved['metadata']['uid']==svc['metadata']['uid'] and saved['spec']==svc['spec']
                and status['version']==release['revision'] and status['info']['status']=='failed'):
            logs=list(directory.glob('oru-readiness-nonrtric-*.log'))
            if len(logs)!=1:raise policy.Blocked('Preserved Helm blocker log is ambiguous')
            blob=logs[0].read_bytes()
            if b'UPGRADE FAILED' not in blob or b'context deadline exceeded' not in blob:
                raise policy.Blocked('Expected preserved Kong readiness timeout unavailable')
            if digest(path.parent.parent/logs[0].name)!=digest(logs[0]):raise policy.Blocked('Original Helm blocker log changed')
            records.append(record)
    if selection not in records:raise policy.Blocked('Selected Kong archive identity or hash does not match')
    if any(r['ledger_sha256']!=selection['ledger_sha256'] for r in records):
        raise policy.Blocked('Matching Kong blocker archives have conflicting contents')
    result=dict(selection,equivalent_archives=records)
    verify_blocker_archive(result)
    return result


def verify_blocker_archive(record):
    selected={k:record[k] for k in ('directory','ledger_sha256')}
    copies=record.get('equivalent_archives',[])
    if (not copies or any(not isinstance(r,dict) or set(r)!=set(selected) for r in copies)
            or len({r['directory'] for r in copies})!=len(copies)
            or copies.count(selected)!=1
            or any(r['ledger_sha256']!=selected['ledger_sha256'] for r in copies)):
        raise policy.Blocked('Reviewed Kong archive selection or equivalent-copy binding changed')
    for copy in copies:util.verify_archive(copy)


def code_binding():
    return {p.name:digest(p) for p in (Path(__file__),ROOT/'tools/phase3_kong_proxy.py')}


def server_dry_run(svc):
    dry=json.loads(command(['kubectl','-n','nonrtric','patch','service',policy.NAME,'--type=json',
        '--dry-run=server','-p',json.dumps(policy.patch(svc)),'-o','json']))
    identity=policy.check_conversion(svc,dry)
    if service()!=svc:raise policy.Blocked('Live Service changed during server dry-run')
    return identity


def audit_binding(old,gate,path,slice_urn,override,selection):
    baseline=historical(old,gate,path,slice_urn)
    if any((path.parent.parent.parent/n).exists() for n in ('setup-oran-smo-done','setup-driver-done')):
        raise policy.Blocked('Completed setup requires a separate review')
    prior=read(path.parent/'oru-readiness-acceptance.json')
    prior_review=read(Path(prior['review_file']))['binding']
    prior_continuation=read(path.parent/'oru-readiness-continuation-attempt.json')
    if prior_continuation['binding_sha256']!=policy.sha(prior_review):
        raise policy.Blocked('Original failed continuation is not the accepted O-RU binding')
    release,manifest=util.release_binding()
    if (release['status']!='failed' or release['revision']!=prior_review['release']['revision']+1
            or release['manifest_sha256']!=prior_review['release']['manifest_sha256']):
        raise policy.Blocked('Expected the one retained Kong-blocked release')
    if read(override)!=policy.OVERRIDE:raise policy.Blocked('ClusterIP override changed')
    policy.allowed_manifest_change(manifest,render(gate,path,override))
    empty_network();svc=service();policy.check_service(svc,'LoadBalancer')
    server_dry_run(svc)
    current=runtime()
    archived=read(Path(prior['private_archive']['directory'])/'nonrtric-resources.json')['items']
    if current['pods']!=policy.pods_binding([p for p in archived if p['kind']=='Pod']):
        raise policy.Blocked('Existing non-RT RIC Pods differ from accepted O-RU archive')
    return {'schema':1,'slice_urn':slice_urn,'historical':baseline,'release':release,
        'service':svc,'runtime':current,'server_dry_run_verified':True,
        'override':{'path':str(override.resolve()),'sha256':digest(override)},
        'blocker_archive':blocker_archive(path,svc,release,selection),'code_sha256':code_binding()}


def preserve(path,label):
    directory=Path(tempfile.mkdtemp(prefix=PREFIX+label+'-',dir=str(path.parent.parent)))
    objects={'kong-service.json':service(),'nonrtric-resources.json':get('deployments,statefulsets,pods,pvc,services',namespace='nonrtric'),
             'network-resources.json':get('deployments,statefulsets,pods,pvc',namespace='network'),
             'helm-status.json':json.loads(command(['helm','status','oran-nonrtric','-n','nonrtric','-o','json']))}
    for name,value in objects.items():write(directory/name,value)
    prior_status=path.parent.parent/'provenance.json'
    if prior_status.is_file():write(directory/'previous-provenance.json',read(prior_status))
    for pattern in ('kong-proxy-*.json','oru-readiness-acceptance.json','oru-readiness-continuation-attempt.json',
                    'context.json','sms-*-acceptance.json','dmaap-postexecution-acceptance.json','onap-acceptance.json'):
        for source in path.parent.glob(pattern):
            if source.is_file() and not (directory/source.name).exists():write(directory/source.name,read(source))
    for source in path.parent.parent.glob('kong-proxy-*.log'):
        fd=os.open(str(directory/source.name),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(source.read_bytes())
    return util.seal(directory)


def helm_logged(path,label,args,gate):
    log=path.parent.parent/(PREFIX+label+'-'+str(time.time_ns())+'.log')
    with log.open('xb') as out:
        os.chmod(log,0o600)
        p=subprocess.Popen(args,stdout=out,stderr=subprocess.STDOUT,
            env=dict(os.environ,PHASE3_FRESH_CONTEXT=str(path)),start_new_session=True)
        try:code=p.wait(timeout=1300)
        except BaseException:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=30)
            except subprocess.TimeoutExpired:raise policy.Blocked('Owned Kong recovery waiter stop unconfirmed')
            raise
    if code:raise policy.Blocked('Normal '+label+' gate failed; private logs preserved')


def review(path,review_path,old,gate,slice_urn,selection=None):
    override=review_path.with_suffix('.clusterip.json')
    if review_path.exists() or override.exists():raise policy.Blocked('Review path already used; no overwrite')
    write(override,policy.OVERRIDE)
    binding=audit_binding(old,gate,path,slice_urn,override,selection)
    write(review_path,{'schema':1,'created_utc':datetime.now(timezone.utc).isoformat(),'binding':binding})


def apply(path,review_path,old,gate,slice_urn):
    approved=read(review_path);age=(datetime.now(timezone.utc)-datetime.fromisoformat(approved['created_utc'])).total_seconds()
    if not 0<=age<=1800:raise policy.Blocked('Kong review expired')
    latch=path.parent/(PREFIX+'attempt.json')
    if latch.exists() or (path.parent/(PREFIX+'acceptance.json')).exists():raise policy.Blocked('Kong attempt already exists; no replay')
    binding=approved['binding'];override=Path(binding['override']['path'])
    selection={k:binding['blocker_archive'][k] for k in ('directory','ledger_sha256')}
    if audit_binding(old,gate,path,slice_urn,override,selection)!=binding:raise policy.Blocked('Reviewed Kong recovery binding changed')
    archive=preserve(path,'before');latest=service()
    if latest!=binding['service']:raise policy.Blocked('Kong Service changed immediately before transition')
    write(latch,{'schema':1,'review_file':str(review_path.resolve()),'review_sha256':digest(review_path),
        'binding_sha256':policy.sha(binding),'private_archive':archive})
    patch=policy.patch(latest)
    converted=json.loads(command(['kubectl','-n','nonrtric','patch','service',policy.NAME,
        '--type=json','-p',json.dumps(patch),'-o','json']))
    transition=policy.check_conversion(latest,converted)
    write(path.parent/(PREFIX+'service-transition.json'),{'schema':1,'identity':transition,
        'review_sha256':digest(review_path),'latch_sha256':digest(latch)})
    work=path.parent.parent;values=work/'dep/smo-install/helm-override/powder'
    helm_logged(path,'nonrtric',['helm','upgrade','oran-nonrtric',str(work/'prepared/nonrtric.tgz'),
        '-n','nonrtric','--no-hooks','--post-renderer',str(gate.ROOT/'bin/phase3-fresh-renderer.py'),
        '-f',str(values/'oran-override.yaml'),'-f',str(override),'--wait','--timeout','10m'],gate)
    if historical(old,gate,path,slice_urn)!=binding['historical']:raise policy.Blocked('Historical acceptance changed during recovery')
    after,manifest=util.release_binding()
    if after['status']!='deployed' or after['revision']!=binding['release']['revision']+1:
        raise policy.Blocked('Kong Helm reconciliation not established')
    original=list(yaml.safe_load_all(command(['helm','get','manifest','oran-nonrtric','-n','nonrtric',
                                             '--revision',str(binding['release']['revision'])])))
    policy.allowed_manifest_change(original,manifest)
    util.contract.identical_manifests(manifest,render(gate,path,override))
    svc=service();identity=policy.check_conversion(binding['service'],svc)
    if runtime()!=binding['runtime']:raise policy.Blocked('Retained non-RT RIC Pod, workload or endpoint changed')
    control=probe(svc)
    if policy.check_conversion(binding['service'],service())!=identity or runtime()!=binding['runtime']:
        raise policy.Blocked('Kong Service or retained runtime changed during final probe')
    write(path.parent/(PREFIX+'acceptance.json'),{'schema':1,'passed':True,'accepted_utc':datetime.now(timezone.utc).isoformat(),
        'review_file':str(review_path.resolve()),'review_sha256':digest(review_path),'latch_sha256':digest(latch),
        'transition_sha256':digest(path.parent/(PREFIX+'service-transition.json')),'service_identity':identity,
        'release':after,'probe':control,'private_archive':preserve(path,'accepted')})


def verify(path,old,gate,slice_urn):
    receipt=read(path.parent/(PREFIX+'acceptance.json'));review_path=Path(receipt['review_file'])
    binding=read(review_path)['binding'];latch=read(path.parent/(PREFIX+'attempt.json'))
    if (receipt.get('passed') is not True or digest(review_path)!=receipt['review_sha256']
            or digest(path.parent/(PREFIX+'attempt.json'))!=receipt['latch_sha256']
            or digest(path.parent/(PREFIX+'service-transition.json'))!=receipt['transition_sha256']
            or latch['binding_sha256']!=policy.sha(binding) or latch['review_sha256']!=digest(review_path)
            or binding['code_sha256']!=code_binding()):raise policy.Blocked('Kong acceptance binding changed')
    util.verify_archive(receipt['private_archive']);util.verify_archive(latch['private_archive']);verify_blocker_archive(binding['blocker_archive'])
    if digest(Path(binding['override']['path']))!=binding['override']['sha256']:
        raise policy.Blocked('Reviewed ClusterIP override changed')
    if historical(old,gate,path,slice_urn)!=binding['historical']:raise policy.Blocked('Historical acceptance changed')
    release,manifest=util.release_binding()
    if release!=receipt['release']:raise policy.Blocked('Accepted Kong release changed')
    util.contract.identical_manifests(manifest,render(gate,path,Path(binding['override']['path'])))
    if policy.check_conversion(binding['service'],service())!=receipt['service_identity'] or runtime()!=binding['runtime']:
        raise policy.Blocked('Accepted Kong Service or retained runtime changed')
    return binding


def normal_health(gate):
    # Repeat the original pure readiness assessment on a fresh metadata snapshot
    # after the historically pinned, slower private acceptance verification.
    assessor=util.load(gate.ROOT,'kong_normal_health','collect-phase3-provenance.py')
    nodes=[{'ready':any(c['type']=='Ready' and c['status']=='True' for c in n['status']['conditions'])}
           for n in get('nodes',namespace=None)['items']]
    workloads=[]
    for w in json.loads(command(['kubectl','get','deployments,statefulsets','-A','-o','json']))['items']:
        status=w.get('status',{});meta=w['metadata']
        workloads.append({'namespace':meta['namespace'],'name':meta['name'],
            'ready':status.get('readyReplicas',0)==w['spec'].get('replicas',1)
                and status.get('observedGeneration',0)>=meta.get('generation',1)})
    pods=[{'namespace':p['metadata']['namespace'],'name':p['metadata']['name'],'phase':p['status']['phase'],
           'ready':any(c['type']=='Ready' and c['status']=='True' for c in p['status'].get('conditions',[]))}
          for p in json.loads(command(['kubectl','get','pods','-A','-o','json']))['items']]
    pvcs=[{'namespace':p['metadata']['namespace'],'name':p['metadata']['name'],'phase':p['status'].get('phase')}
          for p in json.loads(command(['kubectl','get','pvc','-A','-o','json']))['items']]
    releases=json.loads(command(['helm','list','--all','-A','-o','json']))
    services=[{'namespace':s['metadata']['namespace'],'name':s['metadata']['name']}
              for s in json.loads(command(['kubectl','get','services','-A','-o','json']))['items']]
    kafkas=[{'namespace':k['metadata']['namespace'],'name':k['metadata']['name'],
        'generation':k['metadata'].get('generation',1),'observed_generation':k.get('status',{}).get('observedGeneration',0),
        'ready':any(c['type']=='Ready' and c['status']=='True' for c in k.get('status',{}).get('conditions',[]))}
        for k in json.loads(command(['kubectl','get','kafkas.kafka.strimzi.io','-A','-o','json']))['items']]
    jobs=[{'namespace':j['metadata']['namespace'],'name':j['metadata']['name'],
        'complete':any(c['type']=='Complete' and c['status']=='True' for c in j.get('status',{}).get('conditions',[]))}
        for j in json.loads(command(['kubectl','get','jobs','-A','-o','json']))['items']]
    errors=assessor.assess(nodes,workloads,pods,pvcs,releases,services,kafkas,jobs)
    if errors:raise policy.Blocked('Current normal full-SMO readiness assessment failed')
    return {'passed':True,'observed_utc':datetime.now(timezone.utc).isoformat(),'ready_nodes':len(nodes),
        'ready_pods':{ns:sum(p['namespace']==ns and p['phase']=='Running' and p['ready'] for p in pods)
                      for ns in sorted(assessor.SMO_NAMESPACES)}}


def write_status(path,value):
    if path.is_symlink() or path.exists() and not path.is_file():raise policy.Blocked('Status report target is not regular')
    fd,temporary=tempfile.mkstemp(prefix='.kong-proxy-status-',dir=str(path.parent))
    with os.fdopen(fd,'wb') as stream:
        stream.write(policy.canonical(value));stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    parent=os.open(str(path.parent),os.O_RDONLY)
    try:os.fsync(parent)
    finally:os.close(parent)


def continue_startup(path,old,gate,slice_urn):
    binding=verify(path,old,gate,slice_urn);empty_network()
    latch=path.parent/(PREFIX+'continuation-attempt.json')
    if latch.exists():raise policy.Blocked('Kong continuation already attempted; no retry')
    write(latch,{'schema':1,'binding_sha256':policy.sha(binding),'started_utc':datetime.now(timezone.utc).isoformat()})
    work=path.parent.parent;values=work/'dep/smo-install/helm-override/powder'
    helm_logged(path,'simulator',['helm','install','oran-simulator',str(work/'prepared/ru-du-simulators.tgz'),
        '-n','network','--no-hooks','--post-renderer',str(gate.ROOT/'bin/phase3-fresh-renderer.py'),
        '-f',str(values/'network-simulators-override.yaml'),'-f',str(values/'network-simulators-topology-override.yaml'),
        '--wait','--timeout','20m'],gate)
    verify(path,old,gate,slice_urn)
    legacy_output=path.parent/(PREFIX+'legacy-provenance.json')
    if legacy_output.exists():raise policy.Blocked('Legacy final provenance already attempted')
    helm_logged(path,'full-readiness',[sys.executable,str(gate.ROOT/'bin/collect-phase3-provenance.py'),
        '--output',str(legacy_output),'--require-ready'],gate)
    helm_logged(path,'normal-completion',[str(gate.ROOT/'setup-end.sh')],gate)
    verify(path,old,gate,slice_urn)
    current_health=normal_health(gate)
    provenance=read(legacy_output)
    if provenance['readiness_errors']:raise policy.Blocked('Normal full-SMO checks did not pass')
    provenance.update(kong_proxy_current={'verified':True,'acceptance_sha256':digest(path.parent/(PREFIX+'acceptance.json'))},
        oru_readiness_current={'verified':True,'historical_checkout':str(old.ROOT)},
        completion_health=current_health,
        retained_recovery={'commit':command(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip(),
            'legacy_provenance_sha256':digest(legacy_output),'certificate_fault_cases_started':False})
    # This is the normal mutable status report, never a historical acceptance receipt.
    write_status(work/'provenance.json',provenance)
    write(path.parent/(PREFIX+'completion.json'),{'schema':1,'passed':True,'completed_utc':datetime.now(timezone.utc).isoformat(),
        'acceptance_sha256':digest(path.parent/(PREFIX+'acceptance.json')),'provenance_sha256':digest(work/'provenance.json'),
        'certificate_fault_cases_started':False})
    for name in ('setup-oran-smo-done','setup-driver-done'):
        write(path.parent.parent.parent/name,{'verified_kong_recovery_completion':True})


def verify_fresh(path,slice_urn,bind_identity=False):
    context=read(path);policy.fresh_contract(context)
    if context['slice_urn']!=slice_urn or command(['geni-get','slice_urn']).decode().strip()!=slice_urn:
        raise policy.Blocked('Fresh Kong allocation changed')
    svc=service();identity=policy.check_service(svc)
    pods=get('pods',namespace='nonrtric')['items'];ep=policy.endpoints_binding(endpoints(),pods)
    receipt=path.parent/(PREFIX+'fresh-acceptance.json')
    expected={'schema':1,'context_sha256':digest(path),'service_identity':identity,'endpoints':ep}
    if receipt.exists():
        if read(receipt)!=expected:raise policy.Blocked('Fresh Kong Service or endpoint identity changed')
    elif bind_identity:
        policy.pods_binding(pods);probe(svc);write(receipt,expected)
    else:raise policy.Blocked('Fresh Kong acceptance is missing')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('audit','apply','verify','continue','verify-fresh'))
    parser.add_argument('--expected-slice',required=True);parser.add_argument('--context',type=Path,default=CONTEXT)
    parser.add_argument('--review-file',type=Path);parser.add_argument('--accepted-dmaap-checkout',type=Path)
    parser.add_argument('--accepted-oru-checkout',type=Path);parser.add_argument('--bind-identity',action='store_true')
    parser.add_argument('--blocker-archive',type=Path);parser.add_argument('--blocker-archive-sha256')
    args=parser.parse_args();os.umask(0o077)
    def cancelled(signum,frame):raise KeyboardInterrupt('Owned Kong recovery cancelled')
    signal.signal(signal.SIGTERM,cancelled)
    try:
        if args.bind_identity and args.action!='verify-fresh':raise policy.Blocked('Fresh identity flag requires verify-fresh')
        selection=None
        if args.action=='audit':
            if not args.blocker_archive or not args.blocker_archive_sha256:
                raise policy.Blocked('Audit requires the reviewed blocker archive path and SHA-256')
            selection={'directory':str(args.blocker_archive),'ledger_sha256':args.blocker_archive_sha256}
        elif args.blocker_archive or args.blocker_archive_sha256:
            raise policy.Blocked('Archive selection is audit-only; apply uses the recorded review')
        fresh=args.action=='verify-fresh'
        if fresh:
            gate=util.accepted_checkout(ROOT,fresh=True);old=None
        else:
            if not args.accepted_dmaap_checkout or not args.accepted_oru_checkout:raise policy.Blocked('Both historical checkouts required')
            old,gate=pins(args)
        lock=nullcontext() if args.action=='verify' or fresh and not args.bind_identity else gate.backend.driver_lock()
        with lock:
            if args.action in ('audit','apply'):
                if not args.review_file:raise policy.Blocked('Separate private review path required')
                if args.action=='audit':review(args.context,args.review_file,old,gate,args.expected_slice,selection)
                else:apply(args.context,args.review_file,old,gate,args.expected_slice)
            elif args.action=='verify':verify(args.context,old,gate,args.expected_slice)
            elif args.action=='continue':continue_startup(args.context,old,gate,args.expected_slice)
            else:verify_fresh(args.context,args.expected_slice,args.bind_identity)
        print('Kong policy gate passed; certificate testing remains separate');return 0
    except BaseException as error:
        if args.context.parent.is_dir():
            name=PREFIX+'blocked-'+str(time.time_ns())+'.json'
            write(args.context.parent/name,{'schema':1,'stage':args.action,'failure_type':type(error).__name__,
                'reason':str(error) if isinstance(error,policy.Blocked) else 'private-validation-error',
                'provisioning_replayed':False,'certificate_fault_cases_started':False})
            write(args.context.parent/(name+'.private-trace.json'),{'traceback':traceback.format_exc()})
            if args.action in ('apply','continue'):
                try:write(args.context.parent/(name+'.preservation.json'),preserve(args.context,'failed'))
                except Exception:pass
        print('Kong policy gate blocked; private evidence retained; no reset/replay');return 2


if __name__=='__main__':raise SystemExit(main())
