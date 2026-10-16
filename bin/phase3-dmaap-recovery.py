#!/usr/bin/env python3
"""Allocation-bound DMAAP recovery; no stock replay, write retry or reset."""
import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import subprocess
import tempfile
import time

import phase3_dmaap as dmaap

ROOT=Path(__file__).resolve().parents[1]
CONTEXT=Path('/local/setup/phase3-smo/fresh-start/context.json')
CM_PREFIX='onap-dmaap-bc-'
POSTEXEC_RECEIPT='dmaap-postexecution-acceptance.json'
POSTEXEC_LATCH='dmaap-postexecution-attempt.json'
# Only the inspected host-comparator defect is eligible, not arbitrary uncertainty.
COMPARATOR_SOURCE_SHA256='fc682f8dd9f2bd507c685d9a4391d36c0126dcde9da918f8eb5a8d81fabc240f'
POSTEXEC_CODE_CHANGES={
    'bin/phase3-dmaap-recovery.py','bin/phase3-fresh-start.py',
    'bin/phase3-onap-resume-gate.py','bin/collect-phase3-provenance.py'}
INPUT_HASHES={
    ('dbc-dmaap','onap.json'):'16b5c0d9ca0f7b19b509f6c0a13377dcf1317bdf7dbad24ef9c3a226df82853f',
    ('dbc-dcaelocations','san-francisco.json'):'63df351809f7bf23627113aee419b849b7c575459d5b0bbb87657cecb0eb5081',
    ('mr-clusters','san-francisco.json'):'9ae3fa259955c91bcf46baf3fb64a7a56b7927f452f7710af83d3cc7d5791054',
    ('topics','PNF_READY.json'):'08c03f47acf5e32853cb66e795cad66c7eff7c3e6e1d8599e6b873e1bc2fefdc',
    ('topics','PNF_REGISTRATION.json'):'4781a5fd58af3a3aa9cb759465aa62fa594ae78560549202fb37fb0f087b67fb',
    ('topics','mirrormakeragent.json'):'7fb32a4c0b909413c8395a809fe3ef329b3096eb022807a2595038dc6baa4990'}


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'bin'/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


preload=load('dmaap_sms_preload','phase3-sms-preload.py')
backend=preload.backend
fresh=load('dmaap_fresh','phase3-fresh-start.py')
resume=load('dmaap_old_resume','phase3-onap-deploy-resume.py')
durable_write=preload.durable_write
get=preload.get
create=preload.create
kubectl=preload.kubectl


def sha(value):return hashlib.sha256(dmaap.canonical(value)).hexdigest()


def digest(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise dmaap.Blocked('Evidence must be a regular non-symlink file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def timestamp(value):
    if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)',value):
        raise dmaap.Blocked('Original startup timestamp unavailable')
    value=re.sub(r'(\.\d{6})\d+(?=Z|[+-])',r'\1',value)
    return datetime.fromisoformat(value.replace('Z','+00:00'))


def sources():
    maps={};plan=[];bindings={}
    for route,suffix,filename in dmaap.INVENTORY:
        if suffix not in maps:
            obj=get('configmap/'+CM_PREFIX+suffix);maps[suffix]=obj
            bindings[suffix]={'uid':obj['metadata']['uid'],'data_sha256':sha(obj.get('data',{}))}
        data=maps[suffix].get('data',{})
        expected={f for r,s,f in dmaap.INVENTORY if s==suffix}
        if maps[suffix].get('binaryData') or set(data)!=expected or hashlib.sha256(data[filename].encode()).hexdigest()!=INPUT_HASHES[(suffix,filename)]:
            raise dmaap.Blocked('Pinned DMAAP ConfigMap input changed')
        plan.append({'route':route,'file':filename,'body':dmaap.strict_json(data[filename])})
    for suffix in dmaap.EMPTY_MAPS:
        obj=get('configmap/'+CM_PREFIX+suffix)
        if obj.get('data') or obj.get('binaryData'):raise dmaap.Blocked('Unexpected data-router provisioning input')
        bindings[suffix]={'uid':obj['metadata']['uid'],'data_sha256':sha(obj.get('data',{}))}
    return dmaap.validate_plan(plan),bindings


def default_credential(script):
    if hashlib.sha256(script).hexdigest()!=dmaap.STOCK_SCRIPT_SHA256:
        raise dmaap.Blocked('Stock client source changed')
    values={}
    for key in ('BA_IDENTITY','BA_PWD'):
        match=re.search(r'^'+key+r'=\$\{'+key+r':-([^\n]*)\}$',script.decode(),re.M)
        if not match:raise dmaap.Blocked('Stock basic credential syntax changed')
        parsed=shlex.split(match[1])
        if len(parsed)!=1 or any(c in parsed[0] for c in ('\r','\n','\0')):
            raise dmaap.Blocked('Unreviewed stock basic credential encoding')
        values[key]=parsed[0]
    return values['BA_IDENTITY']+':'+values['BA_PWD']


def stock_script():
    prefix=(['sudo'] if os.geteuid()!=0 else [])+['docker']
    p=subprocess.run(prefix+['run','--rm','--network','none','--entrypoint','cat',dmaap.STOCK_IMAGE,
        '/opt/app/dbc-client/bin/dbc-client'],capture_output=True,timeout=90)
    if p.returncode:raise dmaap.Blocked('Exact stock client source unavailable')
    default_credential(p.stdout)
    return p.stdout


def protected():
    resources=get('deployments,statefulsets,jobs,pvc')['items']
    claims=[r for r in resources if r['kind']=='PersistentVolumeClaim']
    if not claims or any(r.get('status',{}).get('phase')!='Bound' for r in claims):
        raise dmaap.Blocked('ONAP storage is not Bound')
    names={r['spec']['volumeName'] for r in claims}
    resources += [r for r in get('pv')['items'] if r['metadata']['name'] in names]
    result={}
    for r in resources:
        spec=copy.deepcopy(r['spec'])
        if r['kind']=='Job' and r['metadata']['name']==preload.preload.JOB:spec.pop('suspend',None)
        result[r['kind']+'/'+r['metadata']['name']]={'uid':r['metadata']['uid'],'spec_sha256':sha(spec)}
    completed=resume.job_inventory(resources)
    return result,completed


def environment(path,expected_slice,allow_transition=False,completed_job=None,allow_completed_setup=False):
    context=fresh.verify_context(path)
    if (context['slice_urn']!=expected_slice or backend.command(['hostname']).decode().split('.')[0].strip()!='node-0'
            or backend.verify_acceptance(path) is None or preload.verify_acceptance(path) is None):
        raise dmaap.Blocked('Current allocation/backend/preload acceptance unavailable')
    if any(not (path.parent.parent.parent/n).is_file() for n in resume.PREREQUISITES):
        raise dmaap.Blocked('Infrastructure prerequisite missing; no replay')
    if not allow_completed_setup and any((path.parent.parent.parent/n).exists() for n in ('setup-oran-smo-done','setup-driver-done')):
        raise dmaap.Blocked('Completed setup requires separate review')
    if not all(any(c['type']=='Ready' and c['status']=='True' for c in n['status']['conditions']) for n in fresh.cluster_nodes()):
        raise dmaap.Blocked('All allocated Nodes must remain Ready')
    objects,completed=protected()
    operator=backend.operator_binding()
    releases=json.loads(backend.command(['helm','list','--all','-n','onap','-o','json']))
    releases=sorted([{k:r[k] for k in ('name','revision','chart','app_version','status')} for r in releases],key=lambda r:r['name'])
    if not releases or any(r['status']!='deployed' for r in releases):raise dmaap.Blocked('ONAP release changed or failed')
    original=path.parent/'onap-deploy-resume-review.json'
    if original.exists():
        old=dmaap.strict_json(original.read_bytes());binding=old['binding']
        expected=copy.deepcopy(binding['protected'])
        if allow_transition:
            transition=dmaap.strict_json((path.parent/'dmaap-transition.json').read_bytes())
            if transition.get('original_review_sha256')!=digest(original):raise dmaap.Blocked('Original continuation review changed')
            expected['Job/'+dmaap.JOB]=transition['replacement']
            if completed_job is not None:
                expected['Job/'+dmaap.JOB]=held_job_binding(completed_job,transition)
        if (objects!=expected or operator!=binding['operator'] or releases!=binding['releases']
                or digest(path)!=binding['context_sha256']
                or any(completed.get(k)!=v for k,v in old['completed_jobs'].items())):
            raise dmaap.Blocked('Original protected inventory/operator/completed Jobs changed')
    code=[ROOT/'setup-driver.sh',ROOT/'setup-oran-smo.sh',*sorted((ROOT/'bin').glob('*.py'))]
    return context,{'protected':objects,'completed_jobs':completed,'operator':operator,'releases':releases,
        'context_sha256':digest(path),'slice_urn':expected_slice,
        'sms_receipts':{n:digest(path.parent/n) for n in ('sms-backend-acceptance.json','sms-preload-acceptance.json')},
        'code_sha256':{str(p.relative_to(ROOT)):digest(p) for p in code}}


def server(original_job_uid=None):
    service=get('service/dmaap-bc');deployment=get('deployment/onap-dmaap-bc')
    selector=service['spec'].get('selector',{})
    pods=[p for p in get('pods')['items'] if selector and all(p['metadata'].get('labels',{}).get(k)==v for k,v in selector.items())]
    if original_job_uid:
        original=[p for p in pods if any(o.get('kind')=='Job' and o.get('uid')==original_job_uid for o in p['metadata'].get('ownerReferences',[]))]
        if len(original)!=1:raise dmaap.Blocked('Original selected provisioning endpoint changed')
        pods=[p for p in pods if p not in original]
    if len(pods)!=1 or not pods[0]['status'].get('containerStatuses') or not all(c.get('ready') for c in pods[0]['status']['containerStatuses']):
        raise dmaap.Blocked('DMAAP must have one current Ready endpoint Pod')
    pod=pods[0];statuses=pod['status']['containerStatuses']
    if len(statuses)!=1 or not statuses[0]['imageID'].endswith(dmaap.SERVER_IMAGE.split('@')[1]):
        raise dmaap.Blocked('DMAAP exact server image changed')
    return {'service_uid':service['metadata']['uid'],'deployment_uid':deployment['metadata']['uid'],
        'pod_uid':pod['metadata']['uid'],'restarts':statuses[0]['restartCount'],
        'address':pod['status']['podIP'] if original_job_uid else service['spec']['clusterIP'],
        'service_address':service['spec']['clusterIP']}


def prewrite_proof(job,pod,script,logs,cmdline):
    default_credential(script)
    m=job['metadata'];status=job.get('status',{})
    containers=job['spec']['template']['spec'].get('containers',[])
    if (m.get('namespace')!='onap' or m.get('name')!=dmaap.JOB or m.get('annotations',{}).get('meta.helm.sh/release-name')!='onap-dmaap'
            or m.get('deletionTimestamp') or job['spec'].get('suspend') or status.get('active')!=1
            or status.get('failed',0) or status.get('succeeded',0) or len(containers)!=1
            or containers[0].get('command') or containers[0].get('args') or containers[0].get('envFrom')):
        raise dmaap.Blocked('Original DMAAP Job execution/ownership changed')
    env=containers[0].get('env',[])
    if {e['name'] for e in env}!={'DELAY','REQUESTID'} or any('valueFrom' in e for e in env):
        raise dmaap.Blocked('Unreviewed stock DMAAP environment override')
    if not any(e=={'name':'DELAY','value':'0'} for e in env):raise dmaap.Blocked('Stock delay contract changed')
    main=pod.get('status',{}).get('containerStatuses',[])
    if (len(main)!=1 or main[0].get('restartCount')!=0 or main[0].get('lastState')
            or not main[0].get('state',{}).get('running')
            or not main[0].get('imageID','').endswith(dmaap.STOCK_IMAGE.split('@')[1])
            or cmdline!=b'sh\x00./bin/dbc-client\x00'
            or not any(o.get('uid')==m['uid'] and o.get('kind')=='Job' for o in pod['metadata'].get('ownerReferences',[]))):
        raise dmaap.Blocked('Original exact stock process identity/history unavailable')
    lines=logs.decode().splitlines()
    if not lines:raise dmaap.Blocked('Original full startup log unavailable')
    first=timestamp(lines[0].split()[0]);started=timestamp(main[0]['state']['running']['startedAt'])
    responses=re.findall(r'^\S+\s+get dmaap response=(\S+)$',logs.decode(),re.M)
    if (abs((first-started).total_seconds())>2 or len(responses)<2 or any(c!='000' for c in responses)
            or logs.count(b'ENTER config')!=1 or logs.count(b'ENTER init')<1
            or any(s in logs for s in (b'-X POST',b'+ doprov',b'+ dopost',b'http response='))
            or not 0<=(datetime.now(timezone.utc)-timestamp(lines[-1].split()[0])).total_seconds()<=45):
        raise dmaap.Blocked('Cannot prove the original process remained before provisioning writes')
    return {'prewrite':True,'job_uid':m['uid'],'pod_uid':pod['metadata']['uid'],
        'started_at':main[0]['state']['running']['startedAt'],'script_sha256':hashlib.sha256(script).hexdigest(),
        'log_sha256':hashlib.sha256(logs).hexdigest(),'readiness_zero_responses':len(responses)}


def original_proof(job):
    pods=preload.owned_pods(job)
    if len(pods)!=1:raise dmaap.Blocked('Expected one retained original DMAAP Pod')
    pod=pods[0];name=pod['metadata']['name'];container='dmaap-provisioning-job'
    script=backend.execute(name,container,['cat','/opt/app/dbc-client/bin/dbc-client'])
    cmdline=backend.execute(name,container,['cat','/proc/1/cmdline'])
    backend.execute(name,container,['sh','-c','test ! -e /opt/app/config/conf/dbc-client.env'])
    credential=shlex.split(backend.execute(name,container,['cat','/opt/app/osaaf/local/curl.cred']).decode())
    if credential!=['-u',default_credential(script)]:raise dmaap.Blocked('Existing stock credential contract changed')
    logs=backend.command(['kubectl','-n','onap','logs',name,'-c',container,'--timestamps=true'])
    return prewrite_proof(job,pod,script,logs,cmdline),pod,script,logs


def qualification(path,qualification_path=None):
    if qualification_path:
        record=dmaap.strict_json(Path(qualification_path).read_bytes())
    else:
        record=dmaap.strict_json((path.parent/'rehearsal.json').read_bytes()).get('dmaap_rehearsal',{})
    dmaap.require_qualification(record)
    return record


def audit(path,expected_slice,qualification_path):
    if not (path.parent/'onap-deploy-resume-review.json').is_file():
        raise dmaap.Blocked('Original protected continuation review required')
    context,binding=environment(path,expected_slice)
    record=qualification(path,qualification_path)
    job=get('job/'+dmaap.JOB)
    proof,pod,script,logs=original_proof(job)
    plan,inputs=sources();endpoint=server(job['metadata']['uid'])
    transport=dmaap.Transport(Path(context['pki_directory'])/'root.cer',endpoint['address'],default_credential(script))
    dmaap.audit_catalog(transport)
    binding.update({'job_uid':job['metadata']['uid'],'pod_uid':pod['metadata']['uid'],
        'job_spec_sha256':sha(job['spec']),'sources':inputs,'server':endpoint,'qualification_sha256':sha(record)})
    return context,binding,(job,pod,script,logs,proof),plan


def save_original(path,objects):
    directory=Path(tempfile.mkdtemp(prefix='dmaap-original-',dir=str(path.parent.parent)))
    os.chmod(directory,0o700)
    job,pod,script,logs,proof=objects
    for n,b in (('job.json',dmaap.canonical(job)),('pod.json',dmaap.canonical(pod)),
                ('stock-client-script',script),('main.log',logs),('proof.json',dmaap.canonical(proof))):
        fresh.private_write(directory/n,b)
    for c in pod['spec'].get('initContainers',[]):
        fresh.private_write(directory/(c['name']+'.log'),backend.command([
            'kubectl','-n','onap','logs',pod['metadata']['name'],'-c',c['name'],'--timestamps=true']))
    for n in {s for r,s,f in dmaap.INVENTORY}|set(dmaap.EMPTY_MAPS):
        fresh.private_write(directory/(n+'.json'),dmaap.canonical(get('configmap/'+CM_PREFIX+n)))
    hashes={p.name:digest(p) for p in directory.iterdir()}
    durable_write(directory/'SHA256SUMS.json',hashes)
    return str(directory)


def replacement(job):
    new=dmaap.patch_job(job)
    new['apiVersion']='batch/v1'
    new['metadata']={k:copy.deepcopy(job['metadata'][k]) for k in ('name','namespace','annotations','labels') if k in job['metadata']}
    new['metadata'].setdefault('annotations',{})['phase3.onap.org/dmaap-gate']='guarded-v1'
    new.pop('status',None)
    for k in ('selector','manualSelector'):new['spec'].pop(k,None)
    meta=new['spec']['template']['metadata']
    for k in ('creationTimestamp','name'):meta.pop(k,None)
    for k in list(meta.get('labels',{})):
        if k in ('controller-uid','job-name','batch.kubernetes.io/controller-uid','batch.kubernetes.io/job-name'):meta['labels'].pop(k)
    return new


def replace_original(path,binding,objects,archive):
    job=objects[0]
    durable_write(path.parent/'dmaap-recovery-attempt.json',{'binding':binding,'archive':archive})
    patch=[{'op':'test','path':'/metadata/'+k,'value':job['metadata'][k]} for k in ('uid','resourceVersion')]
    patch.append({'op':'add','path':'/spec/suspend','value':True})
    kubectl('patch','job/'+dmaap.JOB,'--type=json','-p',json.dumps(patch),'-o','json')
    deadline=time.monotonic()+120
    while preload.owned_pods(job):
        if time.monotonic()>deadline:raise dmaap.Blocked('Original DMAAP Pod stop not confirmed; no replacement')
        time.sleep(1)
    held=get('job/'+dmaap.JOB)
    if held['metadata']['uid']!=binding['job_uid'] or held['spec'].get('suspend') is not True:
        raise dmaap.Blocked('Original DMAAP hold identity changed')
    before=copy.deepcopy(job['spec']);after=copy.deepcopy(held['spec']);before.pop('suspend',None);after.pop('suspend',None)
    if before!=after:raise dmaap.Blocked('Original Job changed while stopping')
    options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground',
             'preconditions':{k:held['metadata'][k] for k in ('uid','resourceVersion')}}
    # Exact UID/RV, retained full logs/manifests, one target. No Helm replay.
    kubectl('delete','--raw','/apis/batch/v1/namespaces/onap/jobs/'+dmaap.JOB,'-f','-',data=dmaap.canonical(options))
    deadline=time.monotonic()+60
    while True:
        current=kubectl('get','job/'+dmaap.JOB,'--ignore-not-found','-o','json')
        if current is None:break
        if time.monotonic()>deadline:raise dmaap.Blocked('Original Job deletion not confirmed')
        time.sleep(1)
    new=create(replacement(job))
    original_review=path.parent/'onap-deploy-resume-review.json'
    activated_spec=copy.deepcopy(new['spec']);activated_spec['suspend']=False
    transition={'schema':1,'binding_before':binding,'private_archive':archive,
        'original_review_sha256':digest(original_review),
        'replacement':{'uid':new['metadata']['uid'],'spec_sha256':sha(activated_spec)}}
    durable_write(path.parent/'dmaap-transition.json',transition)
    return new


def normalized_pod(spec,admitted=False):
    actual=copy.deepcopy(spec)
    alias=actual.pop('serviceAccount',None)
    if alias is not None and alias!=dmaap.SA:
        raise dmaap.Blocked('DMAAP ServiceAccount alias changed')
    return preload.normalized_pod(actual,admitted=admitted)


def job_contract(job):
    source={'kind':'Job','metadata':{'name':dmaap.JOB},'spec':{'template':{'metadata':{'labels':{}},'spec':{
        'containers':[{'name':'dmaap-provisioning-job','image':dmaap.STOCK_IMAGE}]}}}}
    expected=dmaap.patch_job(source)
    if job['spec']['template']['metadata'].get('labels',{}).get('app')!='phase3-dmaap-provisioner':
        raise dmaap.Blocked('DMAAP client/server role separation changed')
    if job['spec']['template']['metadata'].get('labels',{}).get('app.kubernetes.io/name')!='phase3-dmaap-provisioner':
        raise dmaap.Blocked('DMAAP client still matches the server Service selector')
    if job['metadata'].get('annotations',{}).get('phase3.onap.org/dmaap-gate')!='guarded-v1':
        raise dmaap.Blocked('Guarded DMAAP annotation unavailable')
    for k in ('backoffLimit','completions','parallelism','activeDeadlineSeconds'):
        if job['spec'].get(k)!=expected['spec'][k]:raise dmaap.Blocked('Guarded DMAAP Job policy changed')
    if set(job['spec'])-{'suspend','backoffLimit','parallelism','completions','activeDeadlineSeconds','template',
                        'selector','manualSelector','completionMode','podReplacementPolicy'}:
        raise dmaap.Blocked('Unreviewed guarded Job policy fields')
    if job['spec'].get('completionMode','NonIndexed')!='NonIndexed' or job['spec'].get('manualSelector',False):
        raise dmaap.Blocked('Unreviewed guarded Job selection/completion policy')
    # Reuse only Kubernetes-default normalization, not the SMS Job guard.
    expected_pod=expected['spec']['template']['spec']
    if normalized_pod(job['spec']['template']['spec'])!=expected_pod:raise dmaap.Blocked('Guarded DMAAP Pod template changed')
    return job


def binding_for(path,context,job,plan,inputs,endpoint,key,record):
    return {'contract':1,'slice_urn':context['slice_urn'],'context_sha256':digest(path),
        'job_uid':job['metadata']['uid'],'code_config':dmaap.helper_config()['metadata']['name'],
        'sources':inputs,'server':endpoint,'qualification_sha256':sha(record),
        'input_hmac':hmac.new(key,dmaap.canonical(plan),hashlib.sha256).hexdigest(),
        'root_sha256':context['root_sha256'],
        'sms_receipts':{n:digest(path.parent/n) for n in ('sms-backend-acceptance.json','sms-preload-acceptance.json')}}


def check_attempt(path,armed,key,record):
    context=fresh.verify_context(path)
    backend.verify_acceptance(path);preload.verify_acceptance(path)
    job=job_contract(get('job/'+dmaap.JOB));plan,inputs=sources();endpoint=server()
    if binding_for(path,context,job,plan,inputs,endpoint,key,record)!=armed['binding']:
        raise dmaap.Blocked('DMAAP attempt binding changed')
    helper=dmaap.helper_config();actual=get('configmap/'+helper['metadata']['name'])
    if actual.get('immutable') is not True or actual.get('data')!=helper['data']:raise dmaap.Blocked('DMAAP helper changed')
    for expected in dmaap.resources():
        actual=get(expected['kind'].lower()+'/'+dmaap.SA)
        if any(actual.get(k)!=v for k,v in expected.items() if k!='metadata'):raise dmaap.Blocked('DMAAP scoped identity/RBAC changed')
    journal=get('configmap/'+dmaap.JOURNAL);state=dmaap.strict_json(journal['data']['journal.json'])
    if journal['metadata']['uid']!=armed['journal_uid'] or state.get('binding')!=armed['binding']:
        raise dmaap.Blocked('DMAAP journal identity/binding changed')
    secret=get('secret/'+dmaap.INPUT_SECRET)
    if secret['metadata']['uid']!=armed['input_secret_uid'] or secret.get('immutable') is not True:
        raise dmaap.Blocked('DMAAP private input identity changed')
    credential=default_credential(stock_script())
    config={'contract':1,'plan':plan,'binding':armed['binding'],'journal_uid':armed['journal_uid'],
            'address':endpoint['address'],'credential':credential}
    if (set(secret.get('data',{}))!={'input.json','root.cer'}
            or base64.b64decode(secret['data']['input.json'],validate=True)!=dmaap.canonical(config)
            or base64.b64decode(secret['data']['root.cer'],validate=True)!=(Path(context['pki_directory'])/'root.cer').read_bytes()):
        raise dmaap.Blocked('DMAAP immutable private input changed')
    return context,job,plan,state,credential


def stop(armed):
    stopped={'journal_stopped':False,'job_suspended':False}
    for _ in range(5):
        try:
            obj=get('configmap/'+dmaap.JOURNAL)
            if obj['metadata']['uid']==armed['journal_uid']:
                state=dmaap.strict_json(obj['data']['journal.json'])
                obj['data']={'journal.json':dmaap.canonical(dict(state,state='uncertain',reason='coordinator-stopped-no-replay')).decode()}
                kubectl('replace','-f','-','-o','json',data=dmaap.canonical(obj))
                stopped['journal_stopped']=True
        except Exception:pass
        try:
            patch=[{'op':'test','path':'/metadata/uid','value':armed['binding']['job_uid']},
                   {'op':'add','path':'/spec/suspend','value':True}]
            current=kubectl('patch','job/'+dmaap.JOB,'--type=json','-p',json.dumps(patch),'-o','json')
            stopped['job_suspended']=current['metadata']['uid']==armed['binding']['job_uid'] and current['spec'].get('suspend') is True
        except Exception:pass
        if all(stopped.values()):break
        time.sleep(.2)
    return stopped


def postconditions(path,armed,key,record):
    context,job,plan,state,credential=check_attempt(path,armed,key,record)
    pods=preload.owned_pods(job)
    if (job['spec'].get('suspend') is not False or len(pods)!=1 or pods[0]['metadata']['uid']!=state.get('pod_uid')
            or state.get('state')!='verified' or state.get('posts_observed')!=6
            or not any(c.get('type')=='Complete' and c.get('status')=='True' for c in job.get('status',{}).get('conditions',[]))):
        raise dmaap.Blocked('DMAAP has not completed one verified attempt')
    status=pods[0]['status'].get('containerStatuses',[])
    if (len(status)!=1 or status[0]['restartCount']!=0 or status[0]['state'].get('terminated',{}).get('exitCode')!=0
            or not status[0]['imageID'].endswith(dmaap.IMAGE.split('@')[1])):
        raise dmaap.Blocked('DMAAP runtime identity or successful execution changed')
    if normalized_pod(pods[0]['spec'],admitted=True)!=normalized_pod(job['spec']['template']['spec']):
        raise dmaap.Blocked('Admitted DMAAP Pod differs from reviewed Job')
    dmaap.verify_values(plan,dmaap.Transport(Path(context['pki_directory'])/'root.cer',armed['binding']['server']['address'],credential))
    return state


class ReadOnlyTransport(dmaap.Transport):
    """Closeout cannot reach a provisioning write, even through a future caller."""
    def request(self,method,path,data=None):
        if method!='GET' or data is not None:
            raise dmaap.Blocked('Post-execution closeout permits DMAAP GETs only')
        return super().request(method,path)


def held_job_binding(job,transition):
    status=job.get('status',{})
    if (job['metadata'].get('deletionTimestamp') or job['spec'].get('suspend') is not True
            or status.get('active',0) or status.get('failed',0) or status.get('succeeded')!=1
            or any(c.get('type')=='Failed' and c.get('status')=='True' for c in status.get('conditions',[]))
            or not any(c.get('type')=='Complete' and c.get('status')=='True' for c in status.get('conditions',[]))):
        raise dmaap.Blocked('Post-execution closeout requires one successful completed and held Job')
    activated=copy.deepcopy(job['spec']);activated['suspend']=False
    if transition.get('replacement')!={'uid':job['metadata']['uid'],'spec_sha256':sha(activated)}:
        raise dmaap.Blocked('Held Job is not the original reviewed replacement')
    return {'uid':job['metadata']['uid'],'spec_sha256':sha(job['spec'])}


def archive_ledger(directory):
    directory=Path(directory)
    if directory.is_symlink() or not directory.is_dir():raise dmaap.Blocked('Private archive unavailable')
    ledger_path=directory/'SHA256SUMS.json'
    ledger=dmaap.strict_json(ledger_path.read_bytes())
    if (not ledger or set(ledger)!={p.name for p in directory.iterdir() if p.name!='SHA256SUMS.json'}
            or any(Path(n).name!=n or digest(directory/n)!=h for n,h in ledger.items())):
        raise dmaap.Blocked('Private archive integrity changed')
    return digest(ledger_path)


def completed_history(path,job,pod,journal):
    """Require preserved proof of this exact comparator failure and successful hold."""
    parent=path.parent
    transition=dmaap.strict_json((parent/'dmaap-transition.json').read_bytes())
    before=transition['binding_before']
    if before['code_sha256'].get('bin/phase3-dmaap-recovery.py')!=COMPARATOR_SOURCE_SHA256:
        raise dmaap.Blocked('Failure was not the inspected comparator revision')
    held_job_binding(job,transition)
    original=Path(transition['private_archive']);original_ledger=archive_ledger(original)
    matches=[]
    for directory in sorted(parent.parent.glob('dmaap-closeout-*')):
        if directory.is_symlink():raise dmaap.Blocked('Private archive symlink refused')
        saved=dmaap.strict_json((directory/'job.json').read_bytes())
        if saved['metadata']['uid']!=job['metadata']['uid']:continue
        ledger=archive_ledger(directory)
        saved_pod=dmaap.strict_json((directory/(pod['metadata']['name']+'.json')).read_bytes())
        saved_journal=dmaap.strict_json((directory/'journal.json').read_bytes())
        failures=list(directory.glob('dmaap-blocked-*.json'));stops=list(directory.glob('dmaap-stop-*.json'))
        if len(failures)!=1 or len(stops)!=1:raise dmaap.Blocked('Ambiguous preserved failure history')
        failure=dmaap.strict_json(failures[0].read_bytes());stop_record=dmaap.strict_json(stops[0].read_bytes())
        if (failure!={'schema':1,'failure_type':'Blocked','reason':'Unreviewed Pod default',
                      'application_replay_performed':False,'certificate_fault_cases_started':False}
                or stop_record!={'journal_stopped':True,'job_suspended':True}
                or saved['spec']!=job['spec'] or saved_pod['metadata']['uid']!=pod['metadata']['uid']
                or saved_pod['spec']!=pod['spec'] or saved_journal['metadata']['uid']!=journal['metadata']['uid']
                or saved_journal['data']!=journal['data']):
            raise dmaap.Blocked('Preserved completed attempt or comparator failure changed')
        log_name=pod['metadata']['name']+'-dmaap-provisioning-job.stdout'
        logs=backend.command(['kubectl','-n','onap','logs',pod['metadata']['name'],
                              '-c','dmaap-provisioning-job','--timestamps=true'])
        if (logs!=(directory/log_name).read_bytes() or
                b'DMAAP private postconditions verified; host acceptance remains required' not in logs):
            raise dmaap.Blocked('Original successful guarded-client log unavailable')
        historical=('dmaap-armed.json','dmaap-attempt.json','dmaap-recovery-attempt.json','dmaap-transition.json')
        for name in historical:
            if digest(parent/name)!=digest(directory/name):raise dmaap.Blocked('Original attempt evidence changed')
        if digest(failures[0])!=digest(parent/failures[0].name) or digest(stops[0])!=digest(parent/stops[0].name):
            raise dmaap.Blocked('Original failure/stop evidence changed')
        matches.append({'directory':str(directory),'ledger_sha256':ledger,
                        'history_sha256':{n:digest(parent/n) for n in (*historical,failures[0].name,stops[0].name)}})
    if len(matches)!=1:raise dmaap.Blocked('Exactly one preserved comparator-failure archive required')
    return {**matches[0],'original_directory':str(original),'original_ledger_sha256':original_ledger}


def completed_postconditions(path,armed,key,record):
    context,job,plan,state,credential=check_attempt(path,armed,key,record)
    pods=preload.owned_pods(job)
    if (len(pods)!=1 or state.get('state')!='uncertain' or state.get('reason')!='coordinator-stopped-no-replay'
            or state.get('operation')!='all-private-postconditions'
            or type(state.get('posts_attempted')) is not int or state['posts_attempted']!=6
            or type(state.get('posts_observed')) is not int or state['posts_observed']!=6
            or pods[0]['metadata']['uid']!=state.get('pod_uid')):
        raise dmaap.Blocked('Uncertain attempt is not the completed comparator-failure case')
    pod=pods[0];statuses=pod.get('status',{}).get('containerStatuses',[])
    if (pod['metadata'].get('deletionTimestamp') or pod['status'].get('phase')!='Succeeded'
            or len(statuses)!=1 or statuses[0].get('restartCount')!=0 or statuses[0].get('lastState')
            or statuses[0].get('state',{}).get('terminated',{}).get('exitCode')!=0
            or not statuses[0].get('imageID','').endswith(dmaap.IMAGE.split('@')[1])
            or normalized_pod(pod['spec'],admitted=True)!=normalized_pod(job['spec']['template']['spec'])):
        raise dmaap.Blocked('Completed DMAAP runtime identity/history changed')
    journal=get('configmap/'+dmaap.JOURNAL)
    if journal['metadata']['uid']!=armed['journal_uid'] or dmaap.strict_json(journal['data']['journal.json'])!=state:
        raise dmaap.Blocked('Completed journal changed during observation')
    history=completed_history(path,job,pod,journal)
    dmaap.verify_values(plan,ReadOnlyTransport(Path(context['pki_directory'])/'root.cer',
                       armed['binding']['server']['address'],credential))
    return job,pod,journal,history


def code_transition(before,after):
    old=before['code_sha256'];new=after['code_sha256']
    if set(old)!=set(new):raise dmaap.Blocked('Post-execution code inventory changed')
    changed={n for n in old if old[n]!=new[n]}
    if not changed or not changed<=POSTEXEC_CODE_CHANGES:
        raise dmaap.Blocked('Unreviewed post-execution code change')
    for key in ('context_sha256','slice_urn','sms_receipts','operator','releases'):
        if before[key]!=after[key]:raise dmaap.Blocked('Post-execution protected environment changed')
    return {n:{'before':old[n],'after':new[n]} for n in sorted(changed)}


def completed_audit(path,expected_slice,allow_completed_setup=False):
    path=Path(path);parent=path.parent
    if (parent/'dmaap-acceptance.json').exists():raise dmaap.Blocked('Conflicting ordinary DMAAP acceptance')
    latch=dmaap.strict_json((parent/'dmaap-attempt.json').read_bytes())
    armed=dmaap.strict_json((parent/'dmaap-armed.json').read_bytes())
    if latch['binding']!=armed['binding']:raise dmaap.Blocked('Original attempt binding changed')
    dmaap.require_qualification(latch['qualification'])
    job,pod,journal,history=completed_postconditions(path,armed,bytes.fromhex(latch['hmac_key']),latch['qualification'])
    _,current=environment(path,expected_slice,allow_transition=True,completed_job=job,
                          allow_completed_setup=allow_completed_setup)
    transition=dmaap.strict_json((parent/'dmaap-transition.json').read_bytes())
    changes=code_transition(transition['binding_before'],current)
    original_review=parent/'onap-deploy-resume-review.json'
    reviews=[p for p in parent.glob('dmaap-review-*.json') if digest(p)==digest(Path(history['directory'])/'dmaap-review-df14ef1.json')]
    if len(reviews)!=1:raise dmaap.Blocked('Original DMAAP review unavailable or ambiguous')
    if dmaap.strict_json(reviews[0].read_bytes())['binding']!=transition['binding_before']:
        raise dmaap.Blocked('Original DMAAP review/transition differ')
    return {'schema':1,'kind':'completed-comparator-verification','environment':current,
        'code_changes':changes,'status_script_sha256':digest(ROOT/'bin/phase3-status.sh'),
        'history':history,'original_review_sha256':digest(original_review),
        'dmaap_review_sha256':digest(reviews[0]),'transition_sha256':digest(parent/'dmaap-transition.json'),
        'armed_sha256':digest(parent/'dmaap-armed.json'),'attempt_sha256':digest(parent/'dmaap-attempt.json'),
        'job_uid':job['metadata']['uid'],'job_spec_sha256':sha(job['spec']),
        'pod_uid':pod['metadata']['uid'],'pod_spec_sha256':sha(pod['spec']),
        'journal_uid':journal['metadata']['uid'],'journal_data_sha256':sha(journal['data']),
        'posts_observed':6,'provisioning_replayed':False,'journal_rewritten':False}


def preserve_completed(path,binding):
    directory=Path(tempfile.mkdtemp(prefix='dmaap-postexecution-',dir=str(path.parent.parent)))
    os.chmod(directory,0o700)
    for name,kind in (('job.json','job/'+dmaap.JOB),('journal.json','configmap/'+dmaap.JOURNAL)):
        fresh.private_write(directory/name,dmaap.canonical(get(kind)))
    job=get('job/'+dmaap.JOB)
    for pod in preload.owned_pods(job):
        fresh.private_write(directory/'pod.json',dmaap.canonical(pod))
        fresh.private_write(directory/'main.log',backend.command(['kubectl','-n','onap','logs',pod['metadata']['name'],
                            '-c','dmaap-provisioning-job','--timestamps=true']))
    durable_write(directory/'binding.json',binding)
    durable_write(directory/'SHA256SUMS.json',{p.name:digest(p) for p in directory.iterdir()})
    return {'directory':str(directory),'ledger_sha256':archive_ledger(directory)}


def accept_completed(path,expected_slice,review_path):
    path=Path(path);review_path=Path(review_path);parent=path.parent
    approved=dmaap.strict_json(review_path.read_bytes())
    age=(datetime.now(timezone.utc)-timestamp(approved['created_utc'])).total_seconds()
    if not 0<=age<=1800:raise dmaap.Blocked('Post-execution review expired')
    if any((parent/n).exists() for n in (POSTEXEC_LATCH,POSTEXEC_RECEIPT,'dmaap-acceptance.json')):
        raise dmaap.Blocked('Post-execution latch or acceptance already exists; no overwrite')
    current=completed_audit(path,expected_slice)
    if approved.get('schema')!=1 or approved.get('binding')!=current:
        raise dmaap.Blocked('Reviewed post-execution bindings changed')
    durable_write(parent/POSTEXEC_LATCH,{'schema':1,'review_file':str(review_path.resolve()),
                  'review_sha256':digest(review_path),'binding_sha256':sha(current)})
    archive=preserve_completed(path,current)
    if completed_audit(path,expected_slice)!=current:raise dmaap.Blocked('Completed attempt changed before acceptance')
    receipt={'schema':1,'passed':True,'kind':'completed-comparator-verification',
        'binding':current,'review_file':str(review_path.resolve()),'review_sha256':digest(review_path),
        'latch_sha256':digest(parent/POSTEXEC_LATCH),'private_archive':archive,
        'accepted_utc':datetime.now(timezone.utc).isoformat()}
    durable_write(parent/POSTEXEC_RECEIPT,receipt)
    return receipt


def verify_completed_acceptance(path):
    path=Path(path);parent=path.parent;receipt=dmaap.strict_json((parent/POSTEXEC_RECEIPT).read_bytes())
    review_path=Path(receipt['review_file']);review=dmaap.strict_json(review_path.read_bytes())
    latch=dmaap.strict_json((parent/POSTEXEC_LATCH).read_bytes())
    review_age=(timestamp(receipt['accepted_utc'])-timestamp(review['created_utc'])).total_seconds()
    if (receipt.get('schema')!=1 or receipt.get('passed') is not True or receipt.get('kind')!='completed-comparator-verification'
            or review.get('schema')!=1 or not 0<=review_age<=1800
            or receipt['review_sha256']!=digest(review_path) or receipt['binding']!=review.get('binding')
            or receipt['latch_sha256']!=digest(parent/POSTEXEC_LATCH)
            or latch!={'schema':1,'review_file':str(review_path.resolve()),'review_sha256':digest(review_path),
                       'binding_sha256':sha(receipt['binding'])}
            or archive_ledger(receipt['private_archive']['directory'])!=receipt['private_archive']['ledger_sha256']):
        raise dmaap.Blocked('Post-execution acceptance evidence changed')
    current=completed_audit(path,receipt['binding']['environment']['slice_urn'],allow_completed_setup=True)
    if current!=receipt['binding']:raise dmaap.Blocked('Post-execution current binding changed')
    return {'dmaap_accepted':True,'acceptance_kind':'completed-comparator-verification','posts_observed':6,
            'job_uid':current['job_uid'],'job_spec_sha256':current['job_spec_sha256'],'job_suspended':True,
            'journal_state':'uncertain','receipt_sha256':digest(parent/POSTEXEC_RECEIPT)}


def run_held(path,record):
    parent=path.parent
    if any((parent/n).exists() for n in ('dmaap-attempt.json','dmaap-armed.json','dmaap-acceptance.json')):
        raise dmaap.Blocked('DMAAP latch exists; no replay')
    context=fresh.verify_context(path);backend.verify_acceptance(path);preload.verify_acceptance(path)
    dmaap.require_qualification(record)
    job=job_contract(get('job/'+dmaap.JOB))
    if job['spec'].get('suspend') is not True or preload.owned_pods(job) or any(job.get('status',{}).get(k) for k in ('active','failed','succeeded','startTime')):
        raise dmaap.Blocked('Guarded DMAAP Job has history or is not held')
    plan,inputs=sources();endpoint=server();credential=default_credential(stock_script())
    dmaap.audit_catalog(dmaap.Transport(Path(context['pki_directory'])/'root.cer',endpoint['address'],credential))
    key=secrets.token_bytes(32);binding=binding_for(path,context,job,plan,inputs,endpoint,key,record)
    durable_write(parent/'dmaap-attempt.json',{'binding':binding,'hmac_key':key.hex(),'qualification':record})
    for obj in [dmaap.helper_config(),*dmaap.resources()]:
        actual=kubectl('get',obj['kind'].lower()+'/'+obj['metadata']['name'],'--ignore-not-found','-o','json')
        if actual is None:create(obj)
        elif any(actual.get(k)!=v for k,v in obj.items() if k!='metadata'):raise dmaap.Blocked('Existing DMAAP helper/RBAC differs')
    journal=create({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':dmaap.JOURNAL,'namespace':'onap'},
                    'data':{'journal.json':dmaap.canonical({'state':'unarmed','binding':binding}).decode()}})
    config={'contract':1,'plan':plan,'binding':binding,'journal_uid':journal['metadata']['uid'],
            'address':endpoint['address'],'credential':credential}
    private=create({'apiVersion':'v1','kind':'Secret','metadata':{'name':dmaap.INPUT_SECRET,'namespace':'onap'},
        'immutable':True,'type':'Opaque','data':{'input.json':base64.b64encode(dmaap.canonical(config)).decode(),
            'root.cer':base64.b64encode((Path(context['pki_directory'])/'root.cer').read_bytes()).decode()}})
    armed={'binding':binding,'journal_uid':journal['metadata']['uid'],'input_secret_uid':private['metadata']['uid']}
    durable_write(parent/'dmaap-armed.json',armed)
    journal['data']={'journal.json':dmaap.canonical({'state':'prepared','binding':binding}).decode()}
    kubectl('replace','-f','-','-o','json',data=dmaap.canonical(journal))
    try:
        check_attempt(path,armed,key,record)
        patch=[{'op':'test','path':'/metadata/'+k,'value':job['metadata'][k]} for k in ('uid','resourceVersion')]
        patch += [{'op':'test','path':'/spec/suspend','value':True},{'op':'replace','path':'/spec/suspend','value':False}]
        kubectl('patch','job/'+dmaap.JOB,'--type=json','-p',json.dumps(patch),'-o','json')
        deadline=time.monotonic()+600;seen=None
        while time.monotonic()<deadline:
            _,current,_,state,_=check_attempt(path,armed,key,record)
            pods=preload.owned_pods(current)
            if (current['metadata']['uid']!=binding['job_uid'] or len(pods)>1
                    or (seen and (len(pods)!=1 or pods[0]['metadata']['uid']!=seen))
                    or state.get('state') in ('unarmed','uncertain') or current['spec'].get('suspend')
                    or any(c.get('type')=='Failed' and c.get('status')=='True' for c in current.get('status',{}).get('conditions',[]))):
                raise dmaap.Blocked('Guarded DMAAP execution stopped or identity changed')
            if pods:
                seen=pods[0]['metadata']['uid']
                if pods[0]['status'].get('phase')=='Failed':raise dmaap.Blocked('Guarded DMAAP Pod failed')
            if any(c.get('type')=='Complete' and c.get('status')=='True' for c in current.get('status',{}).get('conditions',[])):
                state=postconditions(path,armed,key,record)
                receipt={'schema':1,'passed':True,'contract':1,**armed,'pod_uid':state['pod_uid'],
                         'posts_observed':6,'accepted_utc':datetime.now(timezone.utc).isoformat()}
                durable_write(parent/'dmaap-acceptance.json',receipt);return receipt
            time.sleep(2)
        raise dmaap.Blocked('DMAAP deadline elapsed; no replay')
    except BaseException:
        stopped=stop(armed);durable_write(parent/('dmaap-stop-%d.json'%time.time_ns()),stopped)
        if not all(stopped.values()):print('URGENT: guarded DMAAP cancellation not fully confirmed')
        raise


def verify_acceptance(path):
    path=Path(path);context=dmaap.strict_json(path.read_bytes())
    if (path.parent/POSTEXEC_RECEIPT).exists():return verify_completed_acceptance(path)
    if context.get('dmaap_contract')!=1 and not (path.parent/'dmaap-transition.json').exists():return None
    latch=dmaap.strict_json((path.parent/'dmaap-attempt.json').read_bytes())
    armed=dmaap.strict_json((path.parent/'dmaap-armed.json').read_bytes())
    receipt=dmaap.strict_json((path.parent/'dmaap-acceptance.json').read_bytes())
    if (receipt.get('schema')!=1 or receipt.get('contract')!=1 or receipt.get('passed') is not True
            or receipt.get('posts_observed')!=6 or any(receipt.get(k)!=v for k,v in armed.items())
            or latch['binding']!=armed['binding']):raise dmaap.Blocked('DMAAP acceptance receipt changed')
    dmaap.require_qualification(latch['qualification'])
    state=postconditions(path,armed,bytes.fromhex(latch['hmac_key']),latch['qualification'])
    if state['pod_uid']!=receipt['pod_uid']:raise dmaap.Blocked('Accepted DMAAP Pod identity changed')
    return {'dmaap_accepted':True,'posts_observed':6}


def apply_review(path,expected_slice,review_path,qualification_path):
    approved=dmaap.strict_json(review_path.read_bytes())
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(approved['created_utc'])).total_seconds()
    if not 0<=age<=1800:raise dmaap.Blocked('DMAAP review expired')
    if any((path.parent/n).exists() for n in ('dmaap-recovery-attempt.json','dmaap-transition.json')):
        raise dmaap.Blocked('DMAAP recovery attempt already exists; no replay')
    context,binding,objects,plan=audit(path,expected_slice,qualification_path)
    if approved.get('binding')!=binding:raise dmaap.Blocked('Reviewed DMAAP allocation/code changed')
    archive=save_original(path,objects)
    replace_original(path,binding,objects,archive)
    run_held(path,qualification(path,qualification_path))


def continue_startup(path,expected_slice,review_path):
    review=dmaap.strict_json(review_path.read_bytes())
    transition=dmaap.strict_json((path.parent/'dmaap-transition.json').read_bytes())
    if review.get('binding')!=transition['binding_before']:raise dmaap.Blocked('DMAAP transition is not the reviewed change')
    acceptance=verify_acceptance(path)
    if acceptance is None:raise dmaap.Blocked('Current DMAAP acceptance unavailable')
    completed=acceptance.get('acceptance_kind')=='completed-comparator-verification'
    _,binding=environment(path,expected_slice,allow_transition=True,
                          completed_job=get('job/'+dmaap.JOB) if completed else None)
    before=(dmaap.strict_json((path.parent/POSTEXEC_RECEIPT).read_bytes())['binding']['environment']
            if completed else transition['binding_before'])
    for k in ('code_sha256','context_sha256','sms_receipts','operator','releases'):
        if binding[k]!=before[k]:raise dmaap.Blocked('Continuation code or protected binding changed')
    if not (path.parent/'onap-acceptance.json').exists():
        if not get('kafkas.kafka.strimzi.io')['items']:raise dmaap.Blocked('Expected Kafka resource unavailable')
        p=subprocess.run(['kubectl','-n','onap','wait','kafkas.kafka.strimzi.io','--all',
                          '--for=condition=Ready','--timeout=20m'],capture_output=True,timeout=1230)
        if p.returncode:raise dmaap.Blocked('Kafka readiness failed; no repair attempted')
        fresh.wait_onap(path,3600)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    for n in ('audit','apply','verify','run-fresh','continue','audit-completed','accept-completed'):
        mode.add_argument('--'+n,action='store_true')
    parser.add_argument('--expected-slice');parser.add_argument('--review-file',type=Path)
    parser.add_argument('--qualification',type=Path);parser.add_argument('--context',type=Path,default=CONTEXT)
    args=parser.parse_args();os.umask(0o077)
    def cancelled(signum,frame):raise KeyboardInterrupt('DMAAP operator cancellation')
    signal.signal(signal.SIGTERM,cancelled)
    try:
        with backend.driver_lock():
            if args.audit_completed or args.accept_completed:
                if not args.expected_slice or not args.review_file or args.qualification:
                    raise dmaap.Blocked('Explicit slice/review required; no new qualification or writer')
                if args.audit_completed:
                    if any((args.context.parent/n).exists() for n in (POSTEXEC_LATCH,POSTEXEC_RECEIPT)):
                        raise dmaap.Blocked('Post-execution closeout already attempted; verify only')
                    binding=completed_audit(args.context,args.expected_slice)
                    durable_write(args.review_file,{'schema':1,'created_utc':datetime.now(timezone.utc).isoformat(),
                                  'binding':binding})
                else:accept_completed(args.context,args.expected_slice,args.review_file)
            elif args.verify:
                if verify_acceptance(args.context) is None:raise dmaap.Blocked('DMAAP contract not active')
            elif args.run_fresh:
                context=fresh.verify_context(args.context)
                if context.get('dmaap_contract')!=1:raise dmaap.Blocked('Retained context cannot run fresh DMAAP')
                run_held(args.context,qualification(args.context))
            elif args.__dict__['continue']:
                if not args.expected_slice or not args.review_file:raise dmaap.Blocked('Explicit slice/review required')
                continue_startup(args.context,args.expected_slice,args.review_file)
            else:
                if not args.expected_slice or not args.review_file or not args.qualification:
                    raise dmaap.Blocked('Explicit slice/review/qualification required')
                if args.audit:
                    _,binding,objects,_=audit(args.context,args.expected_slice,args.qualification)
                    archive=save_original(args.context,objects)
                    durable_write(args.review_file,{'schema':1,'created_utc':datetime.now(timezone.utc).isoformat(),
                        'binding':binding,'private_archive':archive})
                else:apply_review(args.context,args.expected_slice,args.review_file,args.qualification)
        print('DMAAP gate passed; full SMO and certificate acceptance remain separate');return 0
    except Exception as error:
        if args.context.parent.is_dir():
            reason=str(error) if isinstance(error,dmaap.Blocked) else 'private-validation-error'
            prefix='dmaap-postexecution-blocked' if args.audit_completed or args.accept_completed else 'dmaap-blocked'
            durable_write(args.context.parent/('%s-%d.json'%(prefix,time.time_ns())),{
                'schema':1,'failure_type':type(error).__name__,'reason':reason,
                'application_replay_performed':False,'certificate_fault_cases_started':False})
        print('DMAAP gate blocked; private review required; no write retry/reset/replay');return 2


if __name__=='__main__':raise SystemExit(main())
