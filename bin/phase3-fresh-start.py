#!/usr/bin/env python3
"""Prepare a new allocation, or rehearse privately without contacting Kubernetes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
from phase3_fresh import READINESS_IMAGE, helper_config, select_storage_node
from phase3_lab_pki import CONFIG_IMAGE, AGENT_IMAGE, generate, private_write, secret
import phase3_ves
import phase3_sms
import phase3_sms_backend

ROOT = Path(__file__).resolve().parents[1]


def run(argv, data=None, timeout=180, directory=None):
    result = subprocess.run(argv,input=data,capture_output=True,timeout=timeout)
    if directory:
        prefix = Path(directory)/('command-%d-%d'%(time.time_ns(),os.getpid()))
        private_write(prefix.with_suffix('.stdout'),result.stdout)
        private_write(prefix.with_suffix('.stderr'),result.stderr)
    if result.returncode:
        raise RuntimeError('Command failed: '+argv[0]+' (private diagnostics retained)')
    return result.stdout


def kubectl(*args, data=None):
    return run(['kubectl',*args],data)


def cluster_nodes():
    nodes = json.loads(kubectl('get','nodes','-o','json'))['items']
    if {n['metadata']['name'] for n in nodes} != {'node-0','node-1','node-2'}:
        raise ValueError('Not the expected new three-node profile cluster')
    return nodes


def docker_prefix():
    return (['sudo'] if os.geteuid()!=0 and sys.platform!='darwin' else [])+['docker']


def build_truststores(pki, diagnostics):
    pki = Path(pki).resolve()
    for store,kind in [('truststoreONAPall.jks','JKS'),('truststoreONAP.p12','PKCS12')]:
        run(docker_prefix()+['run','--rm','--network','none','--user',str(os.getuid())+':'+str(os.getgid()),
            '--mount','type=bind,src='+str(pki)+',dst=/work', '--entrypoint','keytool',CONFIG_IMAGE,
            '-J-Duser.home=/tmp','-importcert','-noprompt','-alias','onaptestca','-file','/work/root.cer',
            '-keystore','/work/'+store,'-storetype',kind,'-storepass','changeit'],timeout=180,directory=diagnostics)
        os.chmod(pki/store,0o600)


def offline_rehearsal(directory, experiment):
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700,parents=True,exist_ok=False)
    os.chmod(directory,0o700)
    pki = directory/'pki'
    metadata = generate(pki,experiment)
    # An explicit pull may use the registry; the actual bootstrap runs without a network.
    run(docker_prefix()+['pull',CONFIG_IMAGE],timeout=600,directory=directory)
    run(docker_prefix()+['pull',READINESS_IMAGE],timeout=600,directory=directory)
    server_source = run(docker_prefix()+['run','--rm','--network','none','--entrypoint','/bin/cat',
        CONFIG_IMAGE,'/opt/app/aaf_config/bin/agent.sh'],directory=directory)
    source_digest = hashlib.sha256(server_source).hexdigest()
    if source_digest != '5b6b326244d5d8a78fd3157c6c9838ba061f35629dcb291960f5f14446bffe1d':
        raise ValueError('AAF image bootstrap source needs review; actual SHA256='+source_digest)
    source = run(docker_prefix()+['run','--rm','--network','none','--entrypoint','/bin/cat',
        READINESS_IMAGE,'/app/ready.py'],directory=directory)
    spec = importlib.util.spec_from_file_location('readiness_wrapper',ROOT/'bin/phase3-readiness-wrapper.py')
    wrapper = importlib.util.module_from_spec(spec); spec.loader.exec_module(wrapper)
    wrapper.patched_source(source)
    build_truststores(pki,directory)
    spec = importlib.util.spec_from_file_location('ves_rehearsal', ROOT/'bin/phase3-ves-rehearsal.py')
    ves_rehearsal = importlib.util.module_from_spec(spec); spec.loader.exec_module(ves_rehearsal)
    ves_result = ves_rehearsal.check(pki, directory, run, docker_prefix())
    sms_spec = importlib.util.spec_from_file_location('sms_rehearsal', ROOT/'bin/phase3-sms-rehearsal.py')
    sms_rehearsal = importlib.util.module_from_spec(sms_spec); sms_spec.loader.exec_module(sms_rehearsal)
    sms_result = sms_rehearsal.check(directory/'sms-isolated', run, docker_prefix())
    backend_spec = importlib.util.spec_from_file_location('sms_backend_rehearsal', ROOT/'bin/phase3-sms-backend-rehearsal.py')
    backend_rehearsal = importlib.util.module_from_spec(backend_spec); backend_spec.loader.exec_module(backend_rehearsal)
    backend_result = backend_rehearsal.check(directory/'sms-backend-isolated', docker_prefix())
    preload_spec = importlib.util.spec_from_file_location('sms_preload_rehearsal', ROOT/'bin/phase3-sms-preload-rehearsal.py')
    preload_rehearsal = importlib.util.module_from_spec(preload_spec); preload_spec.loader.exec_module(preload_rehearsal)
    preload_result = preload_rehearsal.check(directory/'sms-preload-isolated', docker_prefix())
    dmaap_spec = importlib.util.spec_from_file_location('dmaap_rehearsal',ROOT/'bin/phase3-dmaap-rehearsal.py')
    dmaap_rehearsal = importlib.util.module_from_spec(dmaap_spec);dmaap_spec.loader.exec_module(dmaap_rehearsal)
    dmaap_result = dmaap_rehearsal.check(directory/'dmaap-isolated',docker_prefix())
    run(docker_prefix()+['run','--rm','--network','none',
        '--mount','type=bind,src='+str(pki)+',dst=/phase3-pki,readonly',
        '--mount','type=bind,src='+str(ROOT/'tools/Phase3PkiTlsProbe.java')+',dst=/checks/Phase3PkiTlsProbe.java,readonly',
        '--entrypoint','java',CONFIG_IMAGE,'/checks/Phase3PkiTlsProbe.java','/phase3-pki'],timeout=90,directory=directory)
    output = directory/'offline-server-config'
    output.mkdir(mode=0o700)
    wrapper_path = ROOT/'bin/phase3-aaf-bootstrap.sh'
    # Preserve diagnostics privately, restore only this owned directory's host ownership.
    script = ('/bin/bash /phase3-aaf-bootstrap.sh; result=$?; '
              'chown -R '+str(os.getuid())+':'+str(os.getgid())+' /opt/app/osaaf; exit "$result"')
    run(docker_prefix()+['run','--rm','--network','none','--hostname','phase3-aaf-rehearsal',
        '--mount','type=bind,src='+str(pki)+',dst=/phase3-pki,readonly',
        '--mount','type=bind,src='+str(output)+',dst=/opt/app/osaaf',
        '--mount','type=bind,src='+str(wrapper_path)+',dst=/phase3-aaf-bootstrap.sh,readonly',
        '-e','aaf_locator_container=oom','-e','aaf_locator_container_ns=onap',
        '-e','aaf_locator_public_fqdn=aaf.osaaf.org','-e','cadi_latitude=0','-e','cadi_longitude=0',
        '--entrypoint','/bin/bash',CONFIG_IMAGE,'-c',script],timeout=180,directory=directory)
    # Never adopt a result in which the stock certificate or signer survived.
    for source_name,target in [('server.p12','local/org.osaaf.aaf.p12'),
                               ('signer.p12','local/org.osaaf.aaf.signer.p12'),
                               ('truststoreONAPall.jks','public/truststoreONAPall.jks')]:
        if (pki/source_name).read_bytes() != (output/target).read_bytes():
            raise ValueError('Offline AAF store replacement did not persist')
    record = {'schema':1,'passed':True,'experiment':experiment,'config_image':CONFIG_IMAGE,
              'readiness_image':READINESS_IMAGE,'readiness_source_sha256':hashlib.sha256(source).hexdigest(),
              'aaf_bootstrap_source_sha256':source_digest,
              'root_sha256':metadata['certificates']['root']['sha256'],
              'pkcs12_packaging':metadata['pkcs12_packaging'],'runtime':metadata['runtime'],
              'offline_server_bootstrap':True,'live_agent_retrieval_tested':False,
              'isolated_java_tls_controls':True,
              'ves_rehearsal':ves_result,
              'sms_rehearsal':sms_result,
              'sms_backend_rehearsal':backend_result,
              'sms_preload_rehearsal':preload_result,
              'dmaap_rehearsal':dmaap_result,
              'full_smo_tested':False,'network_during_bootstrap':'none'}
    private_write(directory/'rehearsal.json',(json.dumps(record,indent=2)+'\n').encode())
    return record


def assert_empty_onap():
    resources = json.loads(kubectl('get','deployments,statefulsets,jobs,pvc','-n','onap','-o','json'))['items']
    if resources:
        raise ValueError('Fresh installation refused: ONAP workloads/claims already exist; use a separate reviewed recovery')


STORAGE_INSPECTION = '''import json, pathlib, subprocess, sys
actual=subprocess.check_output(['geni-get','slice_urn'],text=True).strip()
if actual!=sys.argv[1]:raise SystemExit('Storage peer allocation mismatch')
paths=['/storage/nfs/deployment-1/onap/mariadb-galera/data-0',
       '/storage/nfs/deployment-1/onap/policy/maria/data-0',
       '/storage/nfs/deployment-1/onap/elastic-master-0']
if len(sys.argv)>2 and sys.argv[2]=='sms-backend-v1':
    paths+=['/storage/nfs/deployment-1/onap/sms/'+p for p in
            ('auth','consul/data-0','quorum/data-0','quorum/data-1','quorum/data-2')]
records=[]
for value in paths:
    path=pathlib.Path(value)
    if str(path.resolve())!=value:raise SystemExit('Noncanonical backing path')
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise SystemExit('Backing path is not an empty directory')
    records.append({'path':value,'exists':path.exists(),'empty':True})
print(json.dumps({'slice_urn':actual,'paths':records}))
'''


def storage_inspection(slice_urn, include_sms=False):
    # Resolve the new logical peer; its own geni-get must match before filesystem
    # inspection. This command is read-only and never uses an old physical host.
    command='sudo -n python3 - '+shlex.quote(slice_urn)
    if include_sms: command+=' sms-backend-v1'
    return json.loads(run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=20','node-2',command],
                          data=STORAGE_INSPECTION.encode(),timeout=60))


def prepare(directory, slice_urn):
    if not re.fullmatch(r'urn:publicid:IDN\+emulab.net:[A-Za-z0-9_-]+\+slice\+[A-Za-z0-9_-]+',slice_urn):
        raise ValueError('Expected the current allocation slice URN')
    nodes = cluster_nodes()
    storage = select_storage_node(nodes)
    current = {n['metadata']['name']:n['metadata']['uid'] for n in nodes}
    identity = hashlib.sha256(json.dumps([slice_urn,current],sort_keys=True).encode()).hexdigest()
    storage_check = storage_inspection(slice_urn, include_sms=True)
    # No output from runtime credentials is printed; ownership and image IDs are recorded instead.
    record = offline_rehearsal(directory,identity[:24])
    import phase3_dmaap
    phase3_dmaap.require_qualification(record['dmaap_rehearsal'])
    directory = Path(directory).resolve()
    pki = directory/'pki'
    context = {'schema':1,'baseline':'fresh-isolated-lab-pki','slice_urn':slice_urn,'node_uids':current,
               'storage_node':storage,'pki_directory':str(pki),'root_sha256':record['root_sha256'],
               'secret_name':'phase3-lab-pki-'+record['root_sha256'][:16],
               'storage_preflight':storage_check,'sms_backend_contract':1,'sms_preload_contract':1,'dmaap_contract':1,
               'rehearsal_sha256':hashlib.sha256((directory/'rehearsal.json').read_bytes()).hexdigest()}
    for namespace in ('onap','nonrtric','network'):
        existing = kubectl('get','namespace',namespace,'--ignore-not-found','-o','name').strip()
        if not existing:
            kubectl('create','namespace',namespace)
    assert_empty_onap()
    for namespace in ('onap','nonrtric','network'):
        kubectl('create','-f','-',data=json.dumps(helper_config(namespace)).encode())
    kubectl('create','-f','-',data=json.dumps(secret(pki,'onap',context['secret_name'])).encode())
    kubectl('create','-f','-',data=json.dumps(phase3_ves.config(context)).encode())
    kubectl('create','-f','-',data=json.dumps(phase3_sms.config(context)).encode())
    kubectl('create','-f','-',data=json.dumps(phase3_sms_backend.config(context)).encode())
    import phase3_preload
    if phase3_preload.CONTRACT != 1:
        raise ValueError('Unreviewed SMS preload contract')
    for resource in [phase3_preload.helper_config(), *phase3_preload.resources(context)]:
        kubectl('create','-f','-',data=json.dumps(resource).encode())
    for resource in [phase3_dmaap.helper_config(),*phase3_dmaap.resources()]:
        kubectl('create','-f','-',data=json.dumps(resource).encode())
    context['files_sha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in pki.iterdir() if p.is_file()}
    private_write(directory/'context.json',(json.dumps(context,indent=2)+'\n').encode())
    return context


def verify_context(path, require_empty=False):
    context = json.loads(Path(path).read_text())
    if context.get('schema')!=1 or context.get('baseline')!='fresh-isolated-lab-pki':
        raise ValueError('Unreviewed fresh-install context')
    if 'sms_preload_contract' in context and (
            type(context['sms_preload_contract']) is not int or context['sms_preload_contract'] != 1):
        raise ValueError('Unreviewed SMS preload contract')
    if 'dmaap_contract' in context and (type(context['dmaap_contract']) is not int or context['dmaap_contract']!=1):
        raise ValueError('Unreviewed DMAAP contract')
    actual_slice = run(['geni-get','slice_urn']).decode().strip()
    if actual_slice != context['slice_urn']:
        raise ValueError('Allocation slice changed')
    nodes = cluster_nodes()
    if {n['metadata']['name']:n['metadata']['uid'] for n in nodes} != context['node_uids'] or select_storage_node(nodes) != context['storage_node']:
        raise ValueError('Allocation or storage Node identity changed')
    directory = Path(path).parent
    if hashlib.sha256((directory/'rehearsal.json').read_bytes()).hexdigest()!=context['rehearsal_sha256']:
        raise ValueError('Offline rehearsal receipt changed')
    for filename,digest in context['files_sha256'].items():
        if Path(filename).name!=filename or hashlib.sha256((Path(context['pki_directory'])/filename).read_bytes()).hexdigest()!=digest:
            raise ValueError('Private PKI artifact changed')
    for namespace in ('onap','nonrtric','network'):
        expected = helper_config(namespace)
        actual = json.loads(kubectl('get','configmap',expected['metadata']['name'],'-n',namespace,'-o','json'))
        if actual.get('data')!=expected['data'] or actual.get('immutable') is not True:
            raise ValueError('Runtime compatibility helper changed')
    actual = json.loads(kubectl('get','secret',context['secret_name'],'-n','onap','-o','json'))
    if actual.get('data')!=secret(context['pki_directory'],'onap',context['secret_name'])['data'] or actual.get('immutable') is not True:
        raise ValueError('Runtime PKI Secret changed')
    if require_empty:
        assert_empty_onap()
        if storage_inspection(context['slice_urn'], include_sms=context.get('sms_backend_contract')==1)!=context['storage_preflight']:
            raise ValueError('Backing-directory state changed before first install')
    if context.get('sms_backend_contract') == 1:
        rehearsal=json.loads((directory/'rehearsal.json').read_text()).get('sms_backend_rehearsal',{})
        phase3_sms_backend.require_qualification(rehearsal)
        expected=phase3_sms_backend.config(context)
        actual=json.loads(kubectl('get','configmap',expected['metadata']['name'],'-n','onap','-o','json'))
        if actual.get('immutable') is not True or actual.get('data')!=expected['data']:
            raise ValueError('Immutable quorum trust helper changed')
    if context.get('sms_preload_contract') == 1:
        import phase3_preload
        if phase3_preload.CONTRACT != 1 or context.get('sms_backend_contract') != 1:
            raise ValueError('Unreviewed SMS preload/backend contract')
        receipt=json.loads((directory/'rehearsal.json').read_text()).get('sms_preload_rehearsal',{})
        phase3_preload.require_qualification(receipt)
        expected=phase3_preload.helper_config()
        actual=json.loads(kubectl('get','configmap',expected['metadata']['name'],'-n','onap','-o','json'))
        if actual.get('immutable') is not True or actual.get('data')!=expected['data']:
            raise ValueError('Immutable SMS preload helper changed')
    if context.get('dmaap_contract')==1:
        import phase3_dmaap
        phase3_dmaap.require_qualification(json.loads((directory/'rehearsal.json').read_text()).get('dmaap_rehearsal',{}))
        expected=phase3_dmaap.helper_config()
        actual=json.loads(kubectl('get','configmap',expected['metadata']['name'],'-n','onap','-o','json'))
        if actual.get('immutable') is not True or actual.get('data')!=expected['data']:
            raise ValueError('Immutable DMAAP helper changed')
    return context


def onap_errors(resources, preload_verified=False, dmaap_verified=False, dmaap_acceptance=None):
    errors=[]
    kinds={r['kind'] for r in resources}
    if not {'Deployment','StatefulSet','Job'}.issubset(kinds):
        errors.append('Missing ONAP controller or Job inventory')
    for r in resources:
        spec=r.get('spec',{}); status=r.get('status',{}); kind=r['kind']; name=r['metadata']['name']
        if kind=='Job':
            held_verified=False
            if name=='onap-dmaap-bc-dmaap-provisioning' and r['metadata'].get('annotations',{}).get('phase3.onap.org/dmaap-gate')=='guarded-v1':
                import phase3_dmaap
                pod=spec.get('template',{}).get('spec',{})
                if isinstance(dmaap_acceptance,dict) and dmaap_acceptance.get('acceptance_kind')=='completed-comparator-verification':
                    held_verified=(dmaap_acceptance.get('dmaap_accepted') is True
                        and dmaap_acceptance.get('job_suspended') is True
                        and spec.get('suspend') is True
                        and r['metadata'].get('uid')==dmaap_acceptance.get('job_uid')
                        and hashlib.sha256(phase3_dmaap.canonical(spec)).hexdigest()==dmaap_acceptance.get('job_spec_sha256')
                        and status.get('succeeded')==1 and not status.get('active',0) and not status.get('failed',0))
                normal_verified=(dmaap_verified is True or isinstance(dmaap_acceptance,dict)
                                 and dmaap_acceptance.get('dmaap_accepted') is True
                                 and dmaap_acceptance.get('acceptance_kind')!='completed-comparator-verification')
                if (not (held_verified or normal_verified and spec.get('suspend') is False) or spec.get('backoffLimit')!=0
                        or pod.get('restartPolicy')!='Never' or len(pod.get('containers',[]))!=1
                        or not phase3_dmaap.is_client(pod['containers'][0])):
                    raise ValueError('DMAAP guarded acceptance unavailable; Job Complete alone is not acceptance')
            if name == phase3_sms.JOB:
                if spec.get('suspend') is True:
                    raise ValueError('SMS preload is safely held: explicit write-safety review is required; do not unsuspend stock preload')
                if (not preload_verified or r['metadata'].get('annotations', {}).get('phase3.onap.org/preload-gate')
                        == 'explicit-write-safety-review-required'):
                    raise ValueError('SMS preload write-safety acceptance is unavailable; manual unsuspension is not acceptance')
                import phase3_preload
                pod=spec.get('template',{}).get('spec',{})
                clients=pod.get('containers',[])
                if (spec.get('backoffLimit') != 0 or pod.get('restartPolicy') != 'Never'
                        or len(clients) != 1 or not phase3_preload.is_client(clients[0])):
                    raise ValueError('SMS preload Job is not the exact reviewed guarded client')
            if spec.get('suspend') is True and not held_verified:
                raise ValueError('ONAP Job is held without exact post-execution acceptance: '+name)
            conditions=status.get('conditions',[])
            if any(c['type']=='Failed' and c['status']=='True' for c in conditions):
                raise ValueError('ONAP Job failed; no automatic retry: '+name)
            if not any(c['type']=='Complete' and c['status']=='True' for c in conditions):
                errors.append('Job incomplete: '+name)
        elif kind in ('Deployment','StatefulSet'):
            if (status.get('observedGeneration')!=r['metadata']['generation'] or
                    status.get('readyReplicas',0)!=spec.get('replicas',1) or
                    (kind=='Deployment' and status.get('updatedReplicas',0)!=spec.get('replicas',1))):
                errors.append('Controller unready: '+name)
    return errors


def wait_onap(path, timeout):
    context=verify_context(path)
    backend_spec=importlib.util.spec_from_file_location('backend_acceptance',ROOT/'bin/phase3-sms-backend.py')
    backend_gate=importlib.util.module_from_spec(backend_spec); backend_spec.loader.exec_module(backend_gate)
    backend_gate.verify_acceptance(path)
    preload_spec=importlib.util.spec_from_file_location('preload_acceptance',ROOT/'bin/phase3-sms-preload.py')
    preload_gate=importlib.util.module_from_spec(preload_spec); preload_spec.loader.exec_module(preload_gate)
    preload_verified=preload_gate.verify_acceptance(path) is not None
    dmaap_spec=importlib.util.spec_from_file_location('dmaap_acceptance',ROOT/'bin/phase3-dmaap-recovery.py')
    dmaap_gate=importlib.util.module_from_spec(dmaap_spec);dmaap_spec.loader.exec_module(dmaap_gate)
    dmaap_acceptance=dmaap_gate.verify_acceptance(path)
    if context.get('dmaap_contract')==1 and dmaap_acceptance is None:raise ValueError('Fresh DMAAP acceptance required')
    deadline=time.monotonic()+timeout
    while True:
        resources=json.loads(kubectl('get','deployments,statefulsets,jobs','-n','onap','-o','json'))['items']
        errors=onap_errors(resources, preload_verified=preload_verified, dmaap_acceptance=dmaap_acceptance)
        if not errors:
            break
        if time.monotonic()>=deadline:
            raise ValueError('ONAP acceptance timeout; first unmet gate: '+errors[0])
        print('ONAP prerequisite gate: %d pending'%len(errors),flush=True)
        time.sleep(20)
        preload_verified=preload_gate.verify_acceptance(path) is not None
        dmaap_acceptance=dmaap_gate.verify_acceptance(path)
    service=json.loads(kubectl('get','service','aaf-locate','-n','onap','-o','json'))
    tls=ssl.create_default_context(cafile=str(Path(context['pki_directory'])/'root.cer'))
    with socket.create_connection((service['spec']['clusterIP'],8095),timeout=20) as sock:
        with tls.wrap_socket(sock,server_hostname='aaf-locate.onap') as session:
            leaf_sha=hashlib.sha256(session.getpeercert(binary_form=True)).hexdigest()
    metadata=json.loads((Path(context['pki_directory'])/'public-metadata.json').read_text())
    if leaf_sha!=metadata['certificates']['server']['sha256']:
        raise ValueError('AAF endpoint is not presenting the prepared experiment certificate')
    pods=json.loads(kubectl('get','pods','-n','onap','-o','json'))['items']
    agents=[]
    ves=[]
    for pod in pods:
        statuses={s['name']:s for s in pod.get('status',{}).get('initContainerStatuses',[])}
        for container in pod['spec'].get('initContainers',[]):
            if container.get('image')==AGENT_IMAGE:
                state=statuses.get(container['name'],{}).get('state',{}).get('terminated',{})
                if state.get('exitCode')!=0:
                    raise ValueError('AAF retrieval initializer did not succeed: '+pod['metadata']['name'])
                agents.append({'pod_uid':pod['metadata']['uid'],'container':container['name']})
            if 'org.onap.dcaegen2.deployments.tls-init-container' in container.get('image', ''):
                expected = phase3_ves.verify(pod, context)
                actual = json.loads(kubectl('get', 'configmap', expected['metadata']['name'], '-n', 'onap', '-o', 'json'))
                if any(actual.get(k) != expected.get(k) for k in ('data', 'binaryData', 'immutable')):
                    raise ValueError('VES runtime trust/configuration changed')
                if statuses.get(container['name'], {}).get('state', {}).get('terminated', {}).get('exitCode') != 0:
                    raise ValueError('VES TLS initializer did not succeed')
                ves.append({'pod_uid':pod['metadata']['uid'], 'image':phase3_ves.IMAGE})
    if not agents:
        raise ValueError('No actual successful AAF retrieval initializer was observed')
    verify_context(path)
    preload_gate.verify_acceptance(path)
    dmaap_gate.verify_acceptance(path)
    result={'schema':1,'passed':True,'slice_urn':context['slice_urn'],'root_sha256':context['root_sha256'],
            'server_leaf_sha256':leaf_sha,'hostname_verified':'aaf-locate.onap','successful_agent_initializers':agents,
            'successful_ves_initializers':ves,
            'certificate_fault_cases_started':False,'full_smo_tested':False}
    private_write(Path(path).parent/'onap-acceptance.json',(json.dumps(result,indent=2)+'\n').encode())
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True)
    rehearsal=sub.add_parser('rehearse'); rehearsal.add_argument('--directory',required=True)
    prep=sub.add_parser('prepare'); prep.add_argument('--directory',required=True); prep.add_argument('--slice-urn',required=True)
    check=sub.add_parser('verify'); check.add_argument('--context',required=True); check.add_argument('--require-empty-onap',action='store_true')
    wait=sub.add_parser('wait-onap'); wait.add_argument('--context',required=True); wait.add_argument('--timeout',type=int,default=3600)
    args=parser.parse_args()
    try:
        if args.action=='rehearse': result=offline_rehearsal(args.directory,'isolated-rehearsal')
        elif args.action=='prepare': result=prepare(args.directory,args.slice_urn)
        elif args.action=='verify': result=verify_context(args.context,args.require_empty_onap)
        else: result=wait_onap(args.context,args.timeout)
        print('Fresh-start gate passed: '+args.action)
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.TimeoutExpired) as error:
        parser.exit(1,'Fresh-start gate failed: '+str(error)+'\n')


if __name__=='__main__':
    main()
