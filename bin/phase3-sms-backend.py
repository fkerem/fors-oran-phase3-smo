#!/usr/bin/env python3
"""Audit without repair; accept fresh bootstrap only after durable backend handoff."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time

import phase3_sms as sms
import phase3_sms_backend as backend
from phase3_lab_pki import private_write

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = '/local/setup/phase3-smo/fresh-start/context.json'


class Blocked(ValueError):
    pass


class Pending(Blocked):
    def __init__(self, message, pod_uids=None):
        super().__init__(message)
        self.pod_uids = pod_uids or {}


@contextmanager
def driver_lock():
    import fcntl
    path=Path('/local/setup/phase3-driver.lock')
    inherited=os.environ.get('PHASE3_RECOVERY_LOCK_FD')
    if inherited is not None:
        held=os.fstat(int(inherited));expected=path.stat()
        if (held.st_dev,held.st_ino)!=(expected.st_dev,expected.st_ino):
            raise Blocked('Inherited setup-driver lock differs')
        fcntl.flock(int(inherited),fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    else:
        with path.open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield


def command(args, allowed=(0,)):
    result = subprocess.run(args, capture_output=True, timeout=45)
    if result.returncode not in allowed:
        raise Blocked('Required metadata/private validation command unavailable')
    return result.stdout


def get(kind):
    return json.loads(command(['kubectl', '-n', 'onap', 'get', kind, '-o', 'json']))


def execute(pod, container, args):
    return command(['kubectl', '-n', 'onap', 'exec', pod, '-c', container, '--']+args)


def vault_observation(pod):
    result = subprocess.run(['kubectl','-n','onap','exec',pod,'-c','aaf-sms-vault','--',
        'vault','status','-address=http://127.0.0.1:8200','-format=json'],capture_output=True,timeout=45)
    if result.returncode not in (0,2):
        if result.returncode == 1 and b'connection refused' in result.stderr.lower():
            raise Pending('Vault listener is not available yet')
        raise Blocked('Vault status observation failed')
    return backend.vault_status(json.loads(result.stdout))


def file_metadata(pod, container, paths):
    result = {}
    for key, path in paths.items():
        blob = execute(pod, container, ['sh', '-c',
            'if test -f "$1" && test ! -L "$1"; then stat -c "%a %u %g %s" "$1"; else printf missing; fi', 'sh', path])
        if blob == b'missing': result[key] = {'present': False}; continue
        mode, uid, gid, size = blob.decode().split()
        result[key] = {'present': int(size) > 0, 'mode': mode, 'uid': int(uid), 'gid': int(gid), 'size': int(size)}
    return result


def ready(pod):
    statuses = pod.get('status', {}).get('containerStatuses', [])
    return (bool(statuses) and all(s.get('ready') for s in statuses)
            and all(s.get('restartCount') == 0 for s in statuses+pod.get('status', {}).get('initContainerStatuses', [])))


def snapshot():
    all_pods = get('pods')['items']
    server = [p for p in all_pods if p['metadata'].get('labels', {}).get(sms.ROLE) == 'server']
    vault = [p for p in all_pods if p['metadata']['name'] == backend.VAULT+'-0']
    quorum = sorted([p for p in all_pods if re.fullmatch(backend.QUORUM+r'-[012]', p['metadata']['name'])],
                    key=lambda p:p['metadata']['name'])
    pod_uids = {p['metadata']['name']:p['metadata']['uid'] for p in [*server,*vault,*quorum]}
    if len(server) > 1:
        raise Blocked('Multiple SMS servers observed during bootstrap')
    if len(server) != 1 or len(vault) != 1 or len(quorum) != 3:
        raise Pending('SMS/Vault/three-quorum Pod inventory is incomplete',pod_uids)
    server, vault = server[0], vault[0]
    objects = [server,vault,*quorum]
    if any(s.get('restartCount',0) for p in objects for s in
           p.get('status',{}).get('containerStatuses',[])+p.get('status',{}).get('initContainerStatuses',[])):
        raise Blocked('Backend process restarted before acceptance')
    if not all(ready(p) for p in objects):
        raise Pending('Backend Pods are not ready yet',pod_uids)
    try:
        state = vault_observation(vault['metadata']['name'])
    except Pending as pending:
        pending.pod_uids = pod_uids
        raise
    auth_paths = {'role': '/sms/auth/role', 'secret': '/sms/auth/secret'}
    entries = []
    for pod in quorum:
        name = pod['metadata']['name']
        paths = {n:'/quorumclient/auth/'+name+'/'+n for n in ('id','pbkey','prkey','shard')}
        entries.append({'name': name, 'uid': pod['metadata']['uid'], 'paths': paths,
            'files': file_metadata(name, 'aaf-sms-quorumclient', paths)})
    auth = file_metadata(server['metadata']['name'], 'aaf-sms', auth_paths)
    pvcs = get('pvc')['items']
    relevant = [r for r in pvcs if 'sms' in r['metadata']['name']]
    if len(relevant) != 5 or any(r.get('status', {}).get('phase') != 'Bound' for r in relevant):
        raise Pending('SMS backing claims are missing or not Bound',pod_uids)
    identity = {'pods': {p['metadata']['name']:p['metadata']['uid'] for p in objects},
                'claims': {p['metadata']['name']:p['metadata']['uid'] for p in relevant},
                'volumes': {p['metadata']['name']:p['spec']['volumeName'] for p in relevant}}
    volumes = {v['metadata']['name']:v for v in get('pv')['items']}
    used = [volumes[p['spec']['volumeName']] for p in relevant]
    if {v['spec'].get('hostPath',{}).get('path') for v in used} != set(backend.STORAGE_PATHS):
        raise Blocked('SMS backing paths differ from fresh-storage proof')
    identity['pv_uids'] = {v['metadata']['name']:v['metadata']['uid'] for v in used}
    record = {'vault': state, 'quorum': [{k:v for k,v in e.items() if k != 'paths'} for e in entries],
        'sms_backend_auth': auth, 'identity': identity, 'pods_ready_without_restarts': all(ready(p) for p in objects),
        'backend_accepted': False, 'preload_authorized': False, 'live_repair_performed': False}
    return record, (server, vault, quorum, entries, relevant)


def operator_binding():
    spec = importlib.util.spec_from_file_location('backend_operator_gate',ROOT/'bin/phase3-onap-resume-gate.py')
    gate_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate_module)
    reviewed, gate = gate_module.acceptance_record('/local/setup/phase3-smo/compatibility')
    deployment = json.loads(command(['kubectl','-n','strimzi-system','get',
                                    'deployment/strimzi-cluster-operator','-o','json']))
    pods = json.loads(command(['kubectl','-n','strimzi-system','get','pods','-o','json']))['items']
    sample = gate_module.compat.operator_sample(deployment,pods,reviewed)
    if sample is None or any(sample[k] != gate['observations'][-1][k] for k in sample):
        raise Blocked('Operator changed after its one-hour gate')
    return sample


def tls(context, server):
    service = get('service/'+sms.SERVICE)
    endpoints = [e for r in get('endpointslices')['items']
        if r['metadata'].get('labels', {}).get('kubernetes.io/service-name') == sms.SERVICE
        for e in r.get('endpoints', [])]
    if (service['spec']['selector'] != dict(sms.LABELS, **{sms.ROLE:'server'}) or len(endpoints) != 1
            or endpoints[0].get('targetRef', {}).get('uid') != server['metadata']['uid']
            or endpoints[0].get('conditions', {}).get('ready') is not True):
        raise Blocked('SMS Service is not exclusively bound to the verified server')
    trust = ssl.create_default_context(cafile=str(Path(context['pki_directory'])/'root.cer'))
    address = service['spec']['clusterIP']
    with socket.create_connection((address,10443),timeout=10) as sock:
        with trust.wrap_socket(sock,server_hostname='aaf-sms.onap') as session:
            fingerprint = hashlib.sha256(session.getpeercert(binary_form=True)).hexdigest()
    return fingerprint, service, trust


def verify_pins(context, objects):
    server, vault, quorum, _, _ = objects
    sms.verify(server, context)
    expected = backend.config(context)
    actual = get('configmap/'+expected['metadata']['name'])
    if actual.get('immutable') is not True or actual.get('data') != expected['data']:
        raise Blocked('Immutable quorum public trust helper differs')
    expected_images = {'aaf-sms': sms.IMAGE, 'aaf-sms-vault': backend.VAULT_IMAGE,
        'aaf-sms-vault-backend': backend.CONSUL_IMAGE, 'aaf-sms-quorumclient': backend.QUORUM_IMAGE}
    for pod in [server,vault,*quorum]:
        for c in pod['spec']['containers']:
            image = expected_images.get(c['name'])
            statuses = pod['status'].get('containerStatuses', [])
            found = [s for s in statuses if s['name'] == c['name']]
            if image is None or c['image'] != image or len(found) != 1 or not found[0].get('imageID','').endswith(image[image.index('@'):]):
                raise Blocked('SMS backend requested/observed image digest changed')
    for pod in quorum:
        c = pod['spec']['containers'][0]
        volumes = {v['name']:v for v in pod['spec']['volumes']}
        if (c.get('command') != ['/quorumclient/bin/quorumclient'] or c.get('args')
                or volumes.get('aaf-sms-quorumclient', {}).get('configMap', {}).get('name') != expected['metadata']['name']
                or volumes.get('phase3-sms-backend', {}).get('configMap', {}).get('name') != expected['metadata']['name']
                or {'name':'phase3-sms-backend','mountPath':'/phase3-sms-backend','readOnly':True} not in c.get('volumeMounts', [])):
            raise Blocked('Quorum does not use the reviewed verified-TLS contract')


def read_private_files(record, objects):
    server, _, _, entries, _ = objects
    for values in [record['sms_backend_auth'], *[e['files'] for e in record['quorum']]]:
        if any(not m.get('present') or int(m.get('mode','0'),8) != 0o600 for m in values.values()):
            raise Blocked('Recovery material missing, empty, or not owner-private')
    material = [{'files':{n:execute(e['name'],'aaf-sms-quorumclient',['cat',path])
                            for n,path in e['paths'].items()}} for e in entries]
    custody = backend.recovery_checks(material)
    auth = {n:execute(server['metadata']['name'],'aaf-sms',['cat','/sms/auth/'+n]).strip() for n in ('role','secret')}
    return custody, auth


def backend_address(vault_uid):
    service = get('service/aaf-sms-db')
    ports = [p for p in service['spec'].get('ports',[]) if p.get('port')==8200]
    endpoints = [e for r in get('endpointslices')['items']
        if r['metadata'].get('labels',{}).get('kubernetes.io/service-name')=='aaf-sms-db'
        for e in r.get('endpoints',[])]
    if (len(ports)!=1 or ports[0].get('targetPort')!=8200 or ports[0].get('protocol','TCP')!='TCP'
            or len(endpoints)!=1 or endpoints[0].get('targetRef',{}).get('uid')!=vault_uid
            or endpoints[0].get('conditions',{}).get('ready') is not True):
        raise Blocked('Vault Service is not exclusively bound to the observed backend')
    return service['spec']['clusterIP']


def role_probe(auth, vault_uid):
    # Fresh-only normal AppRole login; no root token/policy creation, no SMS
    # domain writes. Token and credentials remain in memory, never argv/logs.
    address = backend_address(vault_uid)
    token = None
    def request(method, path, data=None, use_token=False):
        connection = http.client.HTTPConnection(address,8200,timeout=10)
        headers = {'Content-Type':'application/json'}
        if use_token: headers['X-Vault-Token'] = token
        try:
            connection.request(method,path,json.dumps(data).encode() if data is not None else None,headers)
            response = connection.getresponse(); blob = response.read(1024*1024)
            if response.status not in (200,204): raise Blocked('Scoped Vault metadata probe failed')
            return json.loads(blob) if blob else {}
        finally: connection.close()
    try:
        login = request('POST','/v1/auth/approle/login',{'role_id':auth['role'].decode(),'secret_id':auth['secret'].decode()})
        token = login['auth']['client_token']
        if 'smsvaultpolicy' not in login['auth']['policies'] or 'root' in login['auth']['policies']:
            raise Blocked('Unexpected backend AppRole policies')
        capabilities = request('POST','/v1/sys/capabilities-self',{'path':'sms/phase3-metadata-probe'},True)['capabilities']
        if not {'read','list'}.issubset(capabilities) or 'sudo' in capabilities:
            raise Blocked('Backend metadata capability unavailable')
        catalog = request('GET','/v1/sys/internal/ui/mounts',use_token=True)
        if not isinstance(catalog.get('data', {}).get('secret'),dict):
            raise Blocked('Version-qualified backend mount metadata unavailable')
        return {'scoped_approle_login': True, 'mount_catalog_read': True, 'application_writes': False}
    finally:
        if token: request('POST','/v1/auth/token/revoke-self',{},True)


def preserve(directory, record, objects):
    directory = Path(directory); directory.mkdir(mode=0o700,parents=True,exist_ok=False)
    server,vault,quorum,_,claims = objects
    for pod in [server,vault,*quorum]:
        private_write(directory/(pod['metadata']['name']+'.json'),json.dumps(pod,indent=2).encode())
        for c in pod['spec'].get('initContainers',[])+pod['spec']['containers']:
            private_write(directory/(pod['metadata']['name']+'-'+c['name']+'.log'),
                command(['kubectl','-n','onap','logs',pod['metadata']['name'],'-c',c['name'],'--timestamps']))
    for name in ('job/'+sms.JOB,'deployment/'+sms.NAME,'statefulset/'+backend.QUORUM,
                 'statefulset/'+backend.VAULT,'service/'+sms.SERVICE,'service/aaf-sms-db'):
        private_write(directory/(name.replace('/','-')+'.json'),json.dumps(get(name),indent=2).encode())
    private_write(directory/'claims.json',json.dumps(claims,indent=2).encode())
    private_write(directory/'metadata.json',json.dumps(record,indent=2).encode())
    hashes = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()}
    private_write(directory/'preservation.json',json.dumps({'files_sha256':hashes},indent=2).encode())
    return {'directory':str(directory),'files_sha256':hashes}


def wait_fresh(context_path, timeout):
    spec = importlib.util.spec_from_file_location('fresh_backend',ROOT/'bin/phase3-fresh-start.py')
    fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
    context = fresh.verify_context(context_path)
    if context.get('sms_backend_contract') != 1 or not all(p in {
            r['path'] for r in context.get('storage_preflight',{}).get('paths',[]) if r.get('empty') is True}
            for p in backend.STORAGE_PATHS):
        raise Blocked('Retained/pre-existing allocation cannot enter fresh backend bootstrap')
    receipt_path = Path(context_path).parent/'sms-backend-acceptance.json'
    if receipt_path.exists(): raise Blocked('Backend acceptance already exists; no bootstrap replay')
    attempt_path = receipt_path.parent/'sms-backend-first-use-attempt.json'
    if attempt_path.exists(): raise Blocked('First-use bootstrap was attempted; review its outcome before continuation')
    operator = operator_binding()
    deadline = time.monotonic()+timeout
    identity = None; stable_start = None; accepted = None; observed_pods = {}
    while time.monotonic() < deadline:
        try:
            record, objects = snapshot()
        except Pending as pending:
            if stable_start is not None:
                raise Blocked('Backend lost readiness during acceptance observation')
            if any(name not in pending.pod_uids or pending.pod_uids[name]!=uid for name,uid in observed_pods.items()):
                raise Blocked('Backend Pod changed before durable handoff')
            observed_pods.update(pending.pod_uids)
            stable_start = None; time.sleep(2); continue
        if any(record['identity']['pods'].get(name)!=uid for name,uid in observed_pods.items()):
            raise Blocked('Backend Pod changed before durable handoff')
        observed_pods.update(record['identity']['pods'])
        if identity is not None and identity != record['identity']:
            raise Blocked('Backend Pod/storage identity changed during credential handoff')
        identity = record['identity']
        if not record['pods_ready_without_restarts']:
            # Restarted processes cannot safely regenerate the original in-memory
            # initialization authority. Pending/Ready status is never acceptance.
            pods = [objects[0],objects[1],*objects[2]]
            if any(s.get('restartCount',0) for p in pods for s in p['status'].get('containerStatuses',[])):
                raise Blocked('Backend process restarted before acceptance; no automatic recovery')
            time.sleep(2); continue
        verify_pins(context, objects)
        job = get('job/'+sms.JOB)
        if (job['spec'].get('suspend') is not True or job.get('status',{}).get('active',0)
                or any(any(o.get('uid')==job['metadata']['uid'] for o in p['metadata'].get('ownerReferences',[]))
                       for p in get('pods')['items'])):
            raise Blocked('Stock SMS preload is not safely held')
        try:
            leaf, service, trust = tls(context, objects[0])
        except (ConnectionRefusedError,TimeoutError):
            if stable_start is not None:
                raise Blocked('SMS TLS listener lost during acceptance observation')
            time.sleep(2); continue
        if not record['vault']['initialized'] or record['vault']['sealed']:
            stable_start = None; time.sleep(2); continue
        # A normal first-use read lets the stock server persist its AppRole.
        # HTTP 500/empty data is never interpreted as target-state absence.
        if any(not m.get('present') for m in record['sms_backend_auth'].values()):
            private_write(attempt_path,json.dumps({'schema':1,'slice_urn':context['slice_urn'],
                'identity':identity,'operation':'one-normal-first-use-GET','preload_authorized':False}).encode())
            connection = http.client.HTTPSConnection('aaf-sms.onap',10443,context=trust,timeout=10)
            connection._create_connection = lambda *a,**kw:socket.create_connection((service['spec']['clusterIP'],10443),timeout=10)
            try:
                connection.request('GET','/v1/sms/domain/phase3-backend-readiness/secret')
                response = connection.getresponse(); response.read(1024*1024)
            finally: connection.close()
            record, objects = snapshot()
            if record['identity'] != identity:
                raise Blocked('Backend identity changed during first-use bootstrap')
        custody, auth = read_private_files(record, objects)
        auth_binding = hmac.new((Path(context['pki_directory'])/'store-password').read_bytes(),
            auth['role']+b'\0'+auth['secret'],hashlib.sha256).hexdigest()
        if stable_start is None:
            auth_receipt = role_probe(auth,identity['pods'][backend.VAULT+'-0'])
            stable_start = time.monotonic()
            accepted = {'custody':custody,'auth_probe':auth_receipt,'server_leaf_sha256':leaf,
                        'backend_auth_binding_hmac':auth_binding}
        elif (leaf != accepted['server_leaf_sha256'] or custody != accepted['custody']
              or auth_binding != accepted['backend_auth_binding_hmac']):
            raise Blocked('SMS TLS/recovery material changed during backend observation')
        if time.monotonic()-stable_start >= 120:
            if operator_binding() != operator:
                raise Blocked('Operator identity changed during backend observation')
            role_probe(auth,identity['pods'][backend.VAULT+'-0'])
            record.update({'schema':1,'backend_accepted':True,'passed':True,'slice_urn':context['slice_urn'],
                'root_sha256':context['root_sha256'],'images':backend.IMAGES,'restart_free_seconds':120,
                'accepted_utc':datetime.now(timezone.utc).isoformat(),'operator':operator,**accepted})
            private_write(receipt_path,(json.dumps(record,indent=2)+'\n').encode())
            return record
        time.sleep(5)
    raise Blocked('Fresh backend handoff timed out; no reset or recovery attempted')


def verify_acceptance(context_path):
    context = json.loads(Path(context_path).read_text())
    if context.get('sms_backend_contract') != 1:
        return None  # Retained contexts keep their original, separate gates.
    if command(['geni-get','slice_urn']).decode().strip() != context['slice_urn']:
        raise Blocked('Backend acceptance allocation changed')
    receipt = json.loads((Path(context_path).parent/'sms-backend-acceptance.json').read_text())
    if (receipt.get('passed') is not True or receipt.get('backend_accepted') is not True
            or receipt.get('slice_urn') != context['slice_urn'] or receipt.get('root_sha256') != context['root_sha256']
            or receipt.get('images') != backend.IMAGES or receipt.get('restart_free_seconds',0) < 120):
        raise Blocked('Fresh SMS backend acceptance missing or unreviewed')
    record, objects = snapshot()
    if record['identity'] != receipt['identity'] or record['vault']['sealed'] or not record['vault']['initialized']:
        raise Blocked('Accepted backend identity/seal status changed')
    verify_pins(context, objects)
    custody, auth = read_private_files(record, objects)
    binding = hmac.new((Path(context['pki_directory'])/'store-password').read_bytes(),
                      auth['role']+b'\0'+auth['secret'],hashlib.sha256).hexdigest()
    leaf, _, _ = tls(context,objects[0])
    if (custody != receipt['custody'] or binding != receipt['backend_auth_binding_hmac']
            or leaf != receipt['server_leaf_sha256'] or operator_binding() != receipt['operator']):
        raise Blocked('Accepted backend trust/material/operator binding changed')
    return {'backend_accepted':True,'preload_authorized':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation',required=True)
    audit = sub.add_parser('audit'); audit.add_argument('--expected-slice',required=True)
    audit.add_argument('--output',required=True); audit.add_argument('--preserve-directory')
    rehearsal = sub.add_parser('rehearse'); rehearsal.add_argument('--directory',required=True)
    wait = sub.add_parser('wait-fresh'); wait.add_argument('--context',default=CONTEXT)
    wait.add_argument('--timeout',type=int,default=600)
    args = parser.parse_args(); os.umask(0o077)
    try:
        if args.operation == 'rehearse':
            spec = importlib.util.spec_from_file_location('backend_rehearsal',ROOT/'bin/phase3-sms-backend-rehearsal.py')
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            module.check(args.directory,(['sudo'] if os.geteuid()!=0 and os.sys.platform!='darwin' else [])+['docker'])
        elif args.operation == 'audit':
            actual = command(['geni-get','slice_urn']).decode().strip()
            if actual != args.expected_slice: raise Blocked('Allocation mismatch')
            record, objects = snapshot()
            record.update({'schema':1,'slice_urn':actual,'collected_utc':datetime.now(timezone.utc).isoformat()})
            record['blockers'] = (["vault-sealed"] if record['vault']['sealed'] else [])
            if any(not m.get('present') for m in record['sms_backend_auth'].values()):
                record['blockers'].append('sms-backend-credentials-missing')
            if any(not e['files']['shard'].get('present') for e in record['quorum']):
                record['blockers'].append('quorum-shard-custody-incomplete')
            record['quorum_tls_error_counts'] = {}
            for p in objects[2]:
                log = command(['kubectl','-n','onap','logs',p['metadata']['name'],'-c','aaf-sms-quorumclient','--tail=5000'])
                record['quorum_tls_error_counts'][p['metadata']['name']] = {
                    'unknown_authority':log.count(b'certificate signed by unknown authority'),
                    'expired_certificate':log.count(b'certificate has expired or is not yet valid')}
            if args.preserve_directory: record['preservation'] = preserve(args.preserve_directory,record,objects)
            private_write(args.output,(json.dumps(record,indent=2)+'\n').encode())
            print('SMS backend audit preserved; acceptance/recovery/preload are not authorized')
            return 2
        else:
            with driver_lock():
                wait_fresh(args.context,args.timeout)
        print('SMS backend isolated/fresh gate passed; preload and full SMO acceptance remain separate')
        return 0
    except (ValueError,OSError,RuntimeError,KeyError,subprocess.SubprocessError) as error:
        # Do not interpolate API bodies, private material or subprocess stderr.
        if args.operation == 'wait-fresh':
            parent=Path(args.context).parent
            if parent.is_dir():
                failure={'schema':1,'backend_accepted':False,'preload_authorized':False,
                    'failure_type':type(error).__name__,
                    'reason':str(error) if isinstance(error,Blocked) else 'private-validation-error',
                    'live_repair_performed':False}
                private_write(parent/('sms-backend-blocked-%d.json'%time.time_ns()),json.dumps(failure,indent=2).encode())
        print('SMS backend gate blocked; inspect private metadata; no reset/recovery/preload performed')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
