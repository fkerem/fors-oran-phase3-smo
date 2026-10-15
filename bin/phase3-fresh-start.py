#!/usr/bin/env python3
"""Prepare a new allocation, or rehearse privately without contacting Kubernetes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from phase3_fresh import READINESS_IMAGE, helper_config, select_storage_node
from phase3_lab_pki import CONFIG_IMAGE, AGENT_IMAGE, generate, private_write, secret

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
    import importlib.util
    spec = importlib.util.spec_from_file_location('readiness_wrapper',ROOT/'bin/phase3-readiness-wrapper.py')
    wrapper = importlib.util.module_from_spec(spec); spec.loader.exec_module(wrapper)
    wrapper.patched_source(source)
    build_truststores(pki,directory)
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
              'offline_server_bootstrap':True,'live_agent_retrieval_tested':False,
              'isolated_java_tls_controls':True,
              'full_smo_tested':False,'network_during_bootstrap':'none'}
    private_write(directory/'rehearsal.json',(json.dumps(record,indent=2)+'\n').encode())
    return record


def assert_empty_onap():
    resources = json.loads(kubectl('get','deployments,statefulsets,jobs,pvc','-n','onap','-o','json'))['items']
    if resources:
        raise ValueError('Fresh installation refused: ONAP workloads/claims already exist; use a separate reviewed recovery')


def prepare(directory, slice_urn):
    if not re.fullmatch(r'urn:publicid:IDN\+emulab.net:[A-Za-z0-9_-]+\+slice\+[A-Za-z0-9_-]+',slice_urn):
        raise ValueError('Expected the current allocation slice URN')
    nodes = cluster_nodes()
    storage = select_storage_node(nodes)
    current = {n['metadata']['name']:n['metadata']['uid'] for n in nodes}
    identity = hashlib.sha256(json.dumps([slice_urn,current],sort_keys=True).encode()).hexdigest()
    # No output from runtime credentials is printed; ownership and image IDs are recorded instead.
    record = offline_rehearsal(directory,identity[:24])
    directory = Path(directory).resolve()
    pki = directory/'pki'
    context = {'schema':1,'baseline':'fresh-isolated-lab-pki','slice_urn':slice_urn,'node_uids':current,
               'storage_node':storage,'pki_directory':str(pki),'root_sha256':record['root_sha256'],
               'secret_name':'phase3-lab-pki-'+record['root_sha256'][:16],
               'rehearsal_sha256':hashlib.sha256((directory/'rehearsal.json').read_bytes()).hexdigest()}
    for namespace in ('onap','nonrtric','network'):
        existing = kubectl('get','namespace',namespace,'--ignore-not-found','-o','name').strip()
        if not existing:
            kubectl('create','namespace',namespace)
    assert_empty_onap()
    for namespace in ('onap','nonrtric','network'):
        kubectl('create','-f','-',data=json.dumps(helper_config(namespace)).encode())
    kubectl('create','-f','-',data=json.dumps(secret(pki,'onap',context['secret_name'])).encode())
    context['files_sha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in pki.iterdir() if p.is_file()}
    private_write(directory/'context.json',(json.dumps(context,indent=2)+'\n').encode())
    return context


def verify_context(path, require_empty=False):
    context = json.loads(Path(path).read_text())
    if context.get('schema')!=1 or context.get('baseline')!='fresh-isolated-lab-pki':
        raise ValueError('Unreviewed fresh-install context')
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
    return context


def onap_errors(resources):
    errors=[]
    kinds={r['kind'] for r in resources}
    if not {'Deployment','StatefulSet','Job'}.issubset(kinds):
        errors.append('Missing ONAP controller or Job inventory')
    for r in resources:
        spec=r.get('spec',{}); status=r.get('status',{}); kind=r['kind']; name=r['metadata']['name']
        if kind=='Job':
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
    deadline=time.monotonic()+timeout
    while True:
        resources=json.loads(kubectl('get','deployments,statefulsets,jobs','-n','onap','-o','json'))['items']
        errors=onap_errors(resources)
        if not errors:
            break
        if time.monotonic()>=deadline:
            raise ValueError('ONAP acceptance timeout; first unmet gate: '+errors[0])
        print('ONAP prerequisite gate: %d pending'%len(errors),flush=True)
        time.sleep(20)
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
    for pod in pods:
        statuses={s['name']:s for s in pod.get('status',{}).get('initContainerStatuses',[])}
        for container in pod['spec'].get('initContainers',[]):
            if container.get('image')==AGENT_IMAGE:
                state=statuses.get(container['name'],{}).get('state',{}).get('terminated',{})
                if state.get('exitCode')!=0:
                    raise ValueError('AAF retrieval initializer did not succeed: '+pod['metadata']['name'])
                agents.append({'pod_uid':pod['metadata']['uid'],'container':container['name']})
    if not agents:
        raise ValueError('No actual successful AAF retrieval initializer was observed')
    verify_context(path)
    result={'schema':1,'passed':True,'slice_urn':context['slice_urn'],'root_sha256':context['root_sha256'],
            'server_leaf_sha256':leaf_sha,'hostname_verified':'aaf-locate.onap','successful_agent_initializers':agents,
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
