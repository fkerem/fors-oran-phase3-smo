#!/usr/bin/env python3
"""Audit by default; explicit apply upgrades four releases and recreates only six guarded Jobs."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
import yaml
from phase3_images import LOCK_PATH, load_lock, replacements, run as original_run
from phase3_recovery_guards import JOBS, PRESERVE_JOBS, job_guard, recovery_diff

ROOT=Path(__file__).resolve().parents[1]
RELEASES={'onap-mariadb-galera':'mariadb-galera','onap-policy':'policy','onap-dmaap':'dmaap','onap-sdnc':'sdnc'}
TRACE=None
TRACE_COUNT=0

def run(args,timeout=120):
    global TRACE_COUNT
    if TRACE is None:return original_run(args,timeout)
    TRACE_COUNT+=1
    result=subprocess.run(args,capture_output=True,timeout=timeout)
    prefix=TRACE/('command-%04d'%TRACE_COUNT)
    sensitive='secrets' in args
    record={'argv':args,'returncode':result.returncode,'captured_utc':datetime.now(timezone.utc).isoformat(),
            'secret_body_retained':False,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest()}
    prefix.with_suffix('.json').write_text(json.dumps(record,indent=2)+'\n')
    if not sensitive:
        prefix.with_suffix('.stdout').write_bytes(result.stdout);prefix.with_suffix('.stderr').write_bytes(result.stderr)
    if result.returncode:raise RuntimeError('Command failed; private trace: '+prefix.name)
    return result.stdout

def get(kind, name=None, namespace='onap'):
    args=['kubectl']+(['-n',namespace] if namespace else [])+['get',kind]+([name] if name else [])+['-o','json','--request-timeout=30s']
    return json.loads(run(args))

def store(path,data):
    if Path(path).exists():raise ValueError('Refusing to overwrite recovery evidence')
    Path(path).write_text(json.dumps(data,indent=2)+'\n')

def operator_gate():
    spec=importlib.util.spec_from_file_location('resume_gate',ROOT/'bin/phase3-onap-resume-gate.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    record,gate=helper.acceptance_record('/local/setup/phase3-smo/compatibility')
    sample=helper.compat.operator_sample(get('deployment','strimzi-cluster-operator','strimzi-system'),get('pods',namespace='strimzi-system')['items'],record)
    if sample is None or any(sample[k]!=gate['observations'][-1][k] for k in sample):raise ValueError('Operator changed after its one-hour gate')
    runtime=helper.compat.runtime_sample(sample['pod']);helper.compat.kafka_sample()
    if runtime['memory_current_bytes']>=runtime['memory_limit_bytes']*0.9:raise ValueError('Operator is under memory pressure before mutation')
    return {'operator':sample,'runtime':runtime,'accepted_stability_seconds':gate['stability_seconds']}

def identity(expected_slice,expected_commit):
    if run(['geni-get','slice_urn']).decode().strip()!=expected_slice:raise ValueError('Unexpected experiment identity')
    if run(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip()!=expected_commit:raise ValueError('Unexpected profile revision')
    status=run(['git','-C',str(ROOT),'status','--porcelain=v1']).decode().strip()
    if status not in ('','M test-common.py'):raise ValueError('Unexpected source edit')
    original=run(['git','-C',str(ROOT),'show','HEAD:test-common.py'])
    expected=original.replace(b'2.25.305821105408246119474742976030998643995',b'2.25.305821105.408246119.47474297.603099864.3995')
    if (ROOT/'test-common.py').read_bytes()!=expected:raise ValueError('Unexpected portal edit')
    nodes=get('nodes',namespace=None)['items']
    if len(nodes)!=3 or not all(n['status']['nodeInfo']['kubeletVersion']=='v1.34.3' and any(c['type']=='Ready' and c['status']=='True' for c in n['status']['conditions']) for n in nodes):raise ValueError('Expected three Ready pinned Kubernetes nodes')

def prerequisites(cache_path,rehearsal_path,worker_path,expected_slice):
    digest=hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
    cache=json.loads(Path(cache_path).read_text());rehearsal=json.loads(Path(rehearsal_path).read_text());workers=json.loads(Path(worker_path).read_text())
    if not all(r.get('ready') and r.get('lock_sha256')==digest for r in (cache,rehearsal,workers)):raise ValueError('Missing/mismatched successful prerequisite receipts')
    refs=set(replacements().values())
    if workers.get('expected_slice_urn')!=expected_slice:raise ValueError('Worker pulls belong to a different experiment')
    if {r['cache'] for r in cache.get('cache_receipts',[])}!=refs:raise ValueError('Cache receipt is incomplete')
    if rehearsal.get('mysql_up')!=1 or {r['image'] for r in rehearsal.get('versions',[])}!=refs or not rehearsal.get('owned_resources_cleaned'):raise ValueError('Isolated runtime/exporter rehearsal is incomplete')
    if len(workers.get('workers',[]))!=2 or {w['node'] for w in workers['workers']}!={'node-1','node-2'} or any(set(w['images'])!=refs for w in workers['workers']):raise ValueError('Worker pull receipt is incomplete')

def chart_source(chart):
    base=Path('/local/setup/phase3-smo')
    lock=json.loads((base/'chart-lock.json').read_text());record=json.loads((base/'prepared/onap-changes.json').read_text())
    archive=base/'prepared/onap.tgz'
    if record['original_sha256']!=lock['charts']['onap']['sha256'] or hashlib.sha256(archive.read_bytes()).hexdigest()!=record['prepared_sha256']:raise ValueError('ONAP archive differs from chart pin')
    directory=Path.home()/'.local/share/helm/plugins/deploy/cache/onap-subcharts'/chart
    expected={}
    prefix='onap/charts/'+chart+'/'
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.startswith(prefix):
                name=member.name[len(prefix):]
                if '..' in Path(name).parts:raise ValueError('Unexpected chart archive path')
                expected[name]=hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    actual={str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.rglob('*') if p.is_file() and p.name not in ('subchart-overrides.yaml','global-overrides.yaml')}
    if not expected or actual!=expected:raise ValueError('Retained subchart differs from pinned archive: '+chart)
    return directory

def protections():
    objects=get('pvc')['items']+get('pv',namespace=None)['items']
    secrets=get('secrets')['items']
    excluded=[get('job',name) for name in sorted(PRESERVE_JOBS)]
    return {'storage':{x['kind']+'/'+x['metadata']['name']:{'uid':x['metadata']['uid'],'spec':x['spec']} for x in objects},
            'secret_data_hashes':{x['metadata']['name']:hashlib.sha256(json.dumps(x.get('data',{}),sort_keys=True).encode()).hexdigest() for x in secrets if x.get('type')!='helm.sh/release.v1'},
            'excluded_jobs':{x['metadata']['name']:{'uid':x['metadata']['uid'],'spec':x['spec']} for x in excluded}}

def snapshot(work):
    objects=get('jobs')['items'];pods=get('pods')['items']
    proofs=[]
    for name in JOBS:
        selected=[j for j in objects if j['metadata']['name']==name]
        if len(selected)!=1:raise ValueError('Missing/ambiguous eligible Job: '+name)
        proofs.append(job_guard(selected[0],pods))
    unknown=[j['metadata']['name'] for j in objects if j['metadata']['name'] not in set(JOBS)|PRESERVE_JOBS and any(c['type']=='Failed' and c['status']=='True' for c in j.get('status',{}).get('conditions',[]))]
    if unknown:raise ValueError('Unreviewed additional failed Jobs')
    store(work/'original-jobs.json',objects);store(work/'original-pods.json',pods);store(work/'job-eligibility.json',proofs)
    protected=protections();store(work/'protections.json',protected)
    previews={};changes={}
    for release,chart in RELEASES.items():
        directory=chart_source(chart)
        old=run(['helm','-n','onap','get','manifest',release]).decode()
        values=run(['helm','-n','onap','get','values',release,'-o','json']).decode()
        (work/(release+'-original.yaml')).write_text(old);(work/(release+'-values.json')).write_text(values)
        response=json.loads(run(['helm','upgrade',release,str(directory),'-n','onap','--reuse-values','--dry-run=server','-o','json','--post-renderer',str(ROOT/'bin/phase3-recovery-renderer.py')],timeout=240))
        rendered=response['manifest'];(work/(release+'-held.yaml')).write_text(rendered)
        changes[release]=recovery_diff([r for r in yaml.safe_load_all(old) if r],[r for r in yaml.safe_load_all(rendered) if r])
        previews[release]=directory
    store(work/'render-differences.json',changes)
    return proofs,protected,previews

def hold_and_delete(proof,work):
    name=proof['name'];job=get('job',name);pods=get('pods')['items'];fresh=job_guard(job,pods)
    if fresh!=proof:raise ValueError('Job changed since archived eligibility proof')
    patch=[{'op':'test','path':'/metadata/uid','value':proof['uid']},{'op':'test','path':'/metadata/resourceVersion','value':proof['resource_version']},
           {'op':'add','path':'/spec/suspend','value':True}]
    run(['kubectl','-n','onap','patch','job',name,'--type=json','-p',json.dumps(patch)])
    held=get('job',name);job_guard(held,get('pods')['items'])
    if held['metadata']['uid']!=proof['uid']:raise ValueError('Job identity changed during suspension')
    body={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':proof['uid'],'resourceVersion':held['metadata']['resourceVersion']}}
    path=work/(name+'-delete-options.json');store(path,body)
    run(['kubectl','delete','--raw','/apis/batch/v1/namespaces/onap/jobs/'+name,'-f',str(path)])
    run(['kubectl','-n','onap','wait','--for=delete','job/'+name,'--timeout=60s'],timeout=90)

def dependencies_ready(job):
    pods=get('pods')['items'];jobs=get('jobs')['items']
    for init in job['spec']['template']['spec'].get('initContainers',[]):
        command=(init.get('command') or [])+(init.get('args') or [])
        if not command or command[0]!='/app/ready.py':continue
        for option in ('--container-name','--job-name'):
            names=[command[i+1] for i,word in enumerate(command[:-1]) if word==option]
            for name in names:
                if option=='--job-name':
                    found=[j for j in jobs if j['metadata']['name']==name]
                    if not found or not all(any(c['type']=='Complete' and c['status']=='True' for c in j.get('status',{}).get('conditions',[])) for j in found):return False
                else:
                    found=[c for p in pods if p.get('status',{}).get('phase')=='Running' for c in p['status'].get('containerStatuses',[]) if c['name']==name]
                    if not found or not all(c.get('ready') for c in found):return False
    return True

def activate_job(job):
    metadata=job['metadata']
    patch=[{'op':'test','path':'/metadata/uid','value':metadata['uid']},
           {'op':'test','path':'/metadata/resourceVersion','value':metadata['resourceVersion']},
           {'op':'test','path':'/spec/backoffLimit','value':0},
           {'op':'test','path':'/spec/template/spec/restartPolicy','value':'Never'},
           {'op':'test','path':'/spec/suspend','value':True},
           {'op':'replace','path':'/spec/suspend','value':False}]
    run(['kubectl','-n','onap','patch','job',metadata['name'],'--type=json','-p',json.dumps(patch)])

def apply(args):
    global TRACE
    os.umask(0o077)
    work=Path(args.work_dir)
    if work.exists():raise ValueError('Recovery work directory already exists; no implicit retry')
    work.mkdir(parents=True,mode=0o700)
    TRACE=work/'trace';TRACE.mkdir(mode=0o700)
    result={'started_utc':datetime.now(timezone.utc).isoformat(),'ready':False,'apply':args.apply,'jobs_removed':[],'releases_upgraded':[],
            'excluded_jobs':sorted(PRESERVE_JOBS),'certificate_cases_started':False}
    try:
        identity(args.expected_slice_urn,args.expected_commit);store(work/'operator-before.json',operator_gate())
        proofs,protected,previews=snapshot(work)
        if not args.apply:result['audit_passed']=True;return result
        prerequisites(args.cache_record,args.rehearsal_record,args.worker_record,args.expected_slice_urn)
        if protections()!=protected:raise ValueError('Protected storage/Secrets/Jobs changed during preview')
        for proof in proofs:
            identity(args.expected_slice_urn,args.expected_commit);operator_gate();hold_and_delete(proof,work);result['jobs_removed'].append(proof['name'])
        for release,directory in previews.items():
            operator_gate()
            run(['helm','upgrade',release,str(directory),'-n','onap','--reuse-values','--post-renderer',str(ROOT/'bin/phase3-recovery-renderer.py'),'--timeout','10m'],timeout=660)
            result['releases_upgraded'].append(release)
        pending=set(JOBS);deadline=time.monotonic()+1800
        while pending:
            operator_gate()
            if protections()!=protected:raise ValueError('Protected storage/Secrets/excluded Jobs changed')
            progress=False
            for name in sorted(pending):
                job=get('job',name)
                if any(c['type']=='Failed' and c['status']=='True' for c in job.get('status',{}).get('conditions',[])):raise ValueError('Single-attempt Job failed: '+name)
                if any(c['type']=='Complete' and c['status']=='True' for c in job.get('status',{}).get('conditions',[])):
                    pending.remove(name);progress=True;continue
                if job['spec'].get('suspend') and dependencies_ready(job):
                    activate_job(job);progress=True
            print('Pending eligible Jobs: '+', '.join(sorted(pending)),flush=True)
            if time.monotonic()>=deadline:raise ValueError('Bounded Job/dependency readiness gate timed out')
            if pending:time.sleep(15)
        result['ready']=True;result['full_smo_baseline_ready']=False
        store(work/'operator-after.json',operator_gate());store(work/'final-jobs.json',get('jobs')['items'])
        return result
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.SubprocessError) as error:
        result['failure']=str(error);return result
    finally:
        result['finished_utc']=datetime.now(timezone.utc).isoformat();store(work/'result.json',result)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true');parser.add_argument('--work-dir',required=True)
    parser.add_argument('--expected-slice-urn',required=True);parser.add_argument('--expected-commit',required=True)
    for flag in ('cache-record','rehearsal-record','worker-record'):parser.add_argument('--'+flag)
    args=parser.parse_args()
    if args.apply and not all((args.cache_record,args.rehearsal_record,args.worker_record)):parser.error('Apply requires successful cache, isolated rehearsal and worker receipts')
    result=apply(args);print('Guarded recovery '+('passed' if result.get('ready') or result.get('audit_passed') else 'stopped')+'; private result: '+str(Path(args.work_dir)/'result.json'))
    raise SystemExit(0 if result.get('ready') or result.get('audit_passed') else 1)
