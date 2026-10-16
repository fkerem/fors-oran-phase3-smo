#!/usr/bin/env python3
"""Fresh-only SMS preload coordinator. No repair, reset, overwrite or replay."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

import phase3_preload as preload

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = '/local/setup/phase3-smo/fresh-start/context.json'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'bin'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backend = load('preload_backend_gate', 'phase3-sms-backend.py')


def durable_write(path, value):
    """Exclusive private latch, synced with its directory before any effects."""
    path = Path(path)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(preload.canonical(value))
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def kubectl(*args, data=None):
    result = subprocess.run(['kubectl', '-n', 'onap', *args], input=data,
                            capture_output=True, timeout=45)
    if result.returncode:
        raise preload.Blocked('Required Kubernetes operation failed; no retry')
    return preload.strict_json(result.stdout) if result.stdout.strip() else None


def get(name):
    return kubectl('get', name, '-o', 'json')


def create(obj):
    return kubectl('create', '-f', '-', '-o', 'json', data=preload.canonical(obj))


def identity(obj):
    return {k: obj['metadata'][k] for k in ('uid', 'resourceVersion')}


@contextmanager
def vault_session(auth, vault_uid):
    address = backend.backend_address(vault_uid)
    token = None
    def request(method, path, data=None):
        conn = http.client.HTTPConnection(address, 8200, timeout=10)
        try:
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['X-Vault-Token'] = token
            conn.request(method, path, preload.canonical(data) if data is not None else None, headers)
            response = conn.getresponse()
            blob = response.read(1024*1024+1)
            if response.status not in (200, 204) or len(blob) > 1024*1024:
                raise preload.Blocked('Scoped Vault request failed; no absence inference')
            return preload.strict_json(blob) if blob else {}
        finally:
            conn.close()
    try:
        login = request('POST', '/v1/auth/approle/login',
                        {'role_id': auth['role'].decode(), 'secret_id': auth['secret'].decode()})
        token = login['auth']['client_token']
        if not token or set(login['auth']['policies']) != {'default', 'smsvaultpolicy'}:
            raise preload.Blocked('Unexpected scoped backend policies')
        yield request
    finally:
        if token:
            request('POST', '/v1/auth/token/revoke-self', {})


def context_and_backend(path):
    fresh = load('preload_fresh_context', 'phase3-fresh-start.py')
    context = fresh.verify_context(path)
    if context.get('sms_preload_contract') != preload.CONTRACT or context.get('sms_backend_contract') != 1:
        raise preload.Blocked('Retained contexts cannot activate guarded preload')
    if backend.verify_acceptance(path) is None:
        raise preload.Blocked('Qualified fresh backend acceptance unavailable')
    return context


def source_inputs():
    cm = get('configmap/'+preload.JOB)
    if {n: hashlib.sha256(s.encode()).hexdigest() for n, s in cm.get('data', {}).items()} != preload.TEMPLATE_HASHES:
        raise preload.Blocked('Pinned public input templates changed')
    substitutions, sources = {}, {'templates': identity(cm), 'secrets': {}}
    for variable, (name, key) in preload.REFERENCES.items():
        if name not in sources['secrets']:
            obj = get('secret/'+name)
            sources['secrets'][name] = dict(identity(obj), _data=obj.get('data', {}))
        entry = sources['secrets'][name]
        try:
            substitutions[variable] = base64.b64decode(entry['_data'][key], validate=True).decode()
        except (KeyError, ValueError, UnicodeError):
            raise preload.Blocked('Required private source value unavailable') from None
        if not substitutions[variable]:
            raise preload.Blocked('Required referenced credential is empty')
    for entry in sources['secrets'].values():
        entry.pop('_data')
    return preload.validate_inputs(cm.get('data', {}), substitutions), sources


def normalized_pod(pod, admitted=False):
    actual = json.loads(json.dumps(pod))
    defaults = {'dnsPolicy': 'ClusterFirst', 'schedulerName': 'default-scheduler',
                'terminationGracePeriodSeconds': 30, 'enableServiceLinks': True,
                'serviceAccount': preload.SA}
    if admitted:
        defaults.update(priority=0, preemptionPolicy='PreemptLowerPriority')
        actual.pop('nodeName', None)  # Separately checked against this allocation.
        tolerations = actual.pop('tolerations', [])
        expected = [{'key': 'node.kubernetes.io/'+name, 'operator': 'Exists',
                     'effect': 'NoExecute', 'tolerationSeconds': 300}
                    for name in ('not-ready', 'unreachable')]
        if tolerations and sorted(tolerations, key=lambda t: t.get('key', '')) != expected:
            raise preload.Blocked('Unreviewed admitted Pod tolerations')
    for key, value in defaults.items():
        if key in actual and actual.pop(key) != value:
            raise preload.Blocked('Unreviewed Pod default')
    for container in actual.get('containers', []):
        for key, value in {'terminationMessagePath': '/dev/termination-log',
                           'terminationMessagePolicy': 'File', 'imagePullPolicy': 'IfNotPresent'}.items():
            if key in container and container.pop(key) != value:
                raise preload.Blocked('Unreviewed container default')
    return actual


def job_contract(job):
    """Check exact reviewed template while allowing only Kubernetes defaults."""
    context = {'sms_preload_contract': 1, 'sms_backend_contract': 1}
    stock = {'kind': 'Job', 'metadata': {'name': preload.JOB}, 'spec': {'template': {
        'metadata': {'labels': {'app': 'aaf-sms', 'release': 'onap'}}, 'spec': {'containers': [{
            'name': 'aaf-sms-preload', 'image': 'nexus3.onap.org:10001/onap/aaf/sms:4.0.2',
            'command': preload.STOCK_COMMAND.copy()}]}}}}
    expected = preload.patch_job(stock, context)
    if job['metadata'].get('annotations', {}).get('phase3.onap.org/preload-gate') != 'guarded-fresh-v1':
        raise preload.Blocked('Guarded preload Job annotation missing')
    for key in ('backoffLimit', 'parallelism', 'completions', 'activeDeadlineSeconds'):
        if job['spec'].get(key) != expected['spec'][key]:
            raise preload.Blocked('Guarded Job execution policy changed')
    template = job['spec']['template']
    if template['metadata'].get('labels', {}).get('phase3.onap.org/sms-role') != 'preload':
        raise preload.Blocked('Preload/server role separation changed')
    actual = normalized_pod(template['spec'])
    if actual != expected['spec']['template']['spec']:
        raise preload.Blocked('Guarded preload Pod template changed')
    return job


def owned_pods(job):
    return [p for p in get('pods')['items'] if any(o.get('uid') == job['metadata']['uid']
            for o in p['metadata'].get('ownerReferences', []))]


def audit(path):
    context = context_and_backend(path)
    record, objects = backend.snapshot()
    _, auth = backend.read_private_files(record, objects)
    with vault_session(auth, record['identity']['pods'][backend.backend.VAULT+'-0']) as request:
        result = preload.audit_catalog(request('GET', '/v1/sys/internal/ui/resultant-acl'),
                                       request('GET', '/v1/sys/internal/ui/mounts'))
    job = job_contract(get('job/'+preload.JOB))
    if (job['spec'].get('suspend') is not True or job.get('status', {}).get('startTime')
            or job.get('status', {}).get('active', 0) or owned_pods(job)):
        raise preload.Blocked('Fresh preload Job has execution history or is not held')
    plan, sources = source_inputs()
    helper = preload.helper_config()
    actual = get('configmap/'+helper['metadata']['name'])
    if actual.get('immutable') is not True or actual.get('data') != helper['data']:
        raise preload.Blocked('Immutable guarded helper changed')
    for expected in preload.resources(context):
        obj = get(expected['kind'].lower()+'/'+expected['metadata']['name'])
        if any(obj.get(k) != v for k, v in expected.items() if k not in ('metadata',)):
            raise preload.Blocked('Guarded ServiceAccount/RBAC changed')
    _, service, _ = backend.tls(context, objects[0])
    result.update({'fresh_only': True, 'domains': 2, 'secret_records': 20, 'sms_posts': 0})
    return context, job, plan, sources, service, result


def binding_for(path, context, job, plan, sources, service, key):
    return {'schema': 1, 'contract': preload.CONTRACT, 'slice_urn': context['slice_urn'],
        'root_sha256': context['root_sha256'], 'job_uid': job['metadata']['uid'],
        'code_config': preload.helper_config()['metadata']['name'],
        'backend_receipt_sha256': hashlib.sha256((Path(path).parent/'sms-backend-acceptance.json').read_bytes()).hexdigest(),
        'sources': sources, 'input_hmac': hmac.new(key, preload.canonical(plan), hashlib.sha256).hexdigest(),
        'service_uid': service['metadata']['uid'], 'sms_address': service['spec']['clusterIP']}


def journal_record(obj):
    return preload.strict_json(obj['data']['journal.json'])


def replace_journal(obj, record):
    obj['data'] = {'journal.json': json.dumps(record, sort_keys=True)}
    return kubectl('replace', '-f', '-', '-o', 'json', data=preload.canonical(obj))


def check_bindings(path, armed, key):
    context = context_and_backend(path)
    job = job_contract(get('job/'+preload.JOB))
    plan, sources = source_inputs()
    record, objects = backend.snapshot()
    _, service, _ = backend.tls(context, objects[0])
    if binding_for(path, context, job, plan, sources, service, key) != armed['binding']:
        raise preload.Blocked('Allocation/backend/Job/code/input binding changed')
    helper = preload.helper_config()
    actual = get('configmap/'+helper['metadata']['name'])
    if actual.get('immutable') is not True or actual.get('data') != helper['data']:
        raise preload.Blocked('Guarded helper content changed')
    secret = get('secret/'+preload.INPUT_SECRET)
    if (secret['metadata']['uid'] != armed['input_secret_uid'] or secret.get('immutable') is not True
            or set(secret.get('data', {})) != {'input.json', 'root.cer'}):
        raise preload.Blocked('Immutable preload input identity changed')
    expected_config = {'contract': 1, 'plan': plan, 'binding': armed['binding'],
                       'journal_uid': armed['journal_uid'], 'sms_address': service['spec']['clusterIP']}
    if (base64.b64decode(secret['data']['input.json'], validate=True) != preload.canonical(expected_config)
            or base64.b64decode(secret['data']['root.cer'], validate=True) != (Path(context['pki_directory'])/'root.cer').read_bytes()):
        raise preload.Blocked('Immutable private preload input changed')
    obj = get('configmap/'+preload.JOURNAL)
    state = journal_record(obj)
    if (obj['metadata']['uid'] != armed['journal_uid'] or state.get('binding') != armed['binding']
            or state.get('input_secret_uid') != armed['input_secret_uid']):
        raise preload.Blocked('Attempt journal binding changed')
    return context, job, plan, state


def postconditions(path, armed, key, require_complete=True):
    context, job, plan, state = check_bindings(path, armed, key)
    pods = owned_pods(job)
    if len(pods) != 1 or pods[0]['metadata']['uid'] != state.get('pod_uid'):
        raise preload.Blocked('Preload Pod replaced, missing or duplicated')
    if (pods[0]['spec'].get('nodeName') not in context['node_uids']
            or normalized_pod(pods[0]['spec'], admitted=True) != normalized_pod(job['spec']['template']['spec'])
            or pods[0]['metadata'].get('labels', {}).get('phase3.onap.org/sms-role') != 'preload'):
        raise preload.Blocked('Admitted preload Pod contract differs')
    statuses = pods[0].get('status', {}).get('containerStatuses', [])
    if (len(statuses) != 1 or statuses[0].get('restartCount') != 0
            or not statuses[0].get('imageID', '').endswith(preload.IMAGE[preload.IMAGE.index('@'):])):
        raise preload.Blocked('Preload observed runtime identity changed')
    if require_complete and (state.get('state') != 'verified' or state.get('posts_observed') != 22
            or statuses[0].get('state', {}).get('terminated', {}).get('exitCode') != 0
            or not any(c.get('type') == 'Complete' and c.get('status') == 'True' for c in job.get('status', {}).get('conditions', []))):
        raise preload.Blocked('Guarded preload has not completed verified postconditions')
    transport = preload.Transport(Path(context['pki_directory'])/'root.cer', armed['binding']['sms_address'])
    preload.verify_values(plan, transport)
    # Independently check UUID-to-domain metadata and reject any extra SMS mounts.
    record, objects = backend.snapshot()
    _, auth = backend.read_private_files(record, objects)
    with vault_session(auth, record['identity']['pods'][backend.backend.VAULT+'-0']) as request:
        preload.validate_acl(request('GET', '/v1/sys/internal/ui/resultant-acl'))
        catalog = request('GET', '/v1/sys/internal/ui/mounts')['data']['secret']
        sms_mounts = {p for p in catalog if p.startswith('sms')}
        if sms_mounts != {'sms/has/', 'sms/osdf/', 'sms/smsinternaldomain/'}:
            raise preload.Blocked('SMS backend mount postconditions differ')
        if any(catalog[p].get('type') != 'kv' or (catalog[p].get('options') or {}).get('version', '1') != '1'
               for p in sms_mounts):
            raise preload.Blocked('SMS data mount type/version changed')
        for domain in preload.INVENTORY:
            data = request('GET', '/v1/sms/smsinternaldomain/'+domain).get('data')
            if data != {'uuid': state['domain_uuids'].get(domain)}:
                raise preload.Blocked('Domain UUID backend readback mismatch')
    return state


def stop_attempt(armed):
    stopped = {'journal_stopped': False, 'job_suspended': False}
    # Only safety-control requests may retry. SMS application requests never do.
    for _ in range(5):
        if not stopped['journal_stopped']:
            try:
                obj = get('configmap/'+preload.JOURNAL)
                if obj['metadata']['uid'] == armed['journal_uid']:
                    state = journal_record(obj)
                    replace_journal(obj, dict(state, state='uncertain', reason='coordinator-stopped-no-replay'))
                    current = get('configmap/'+preload.JOURNAL)
                    stopped['journal_stopped'] = (current['metadata']['uid'] == armed['journal_uid']
                                                  and journal_record(current).get('state') == 'uncertain')
            except Exception:
                pass
        if not stopped['job_suspended']:
            try:
                job = get('job/'+preload.JOB)
                if job['metadata']['uid'] == armed['binding']['job_uid']:
                    # UID prevents replacement adoption; omit resourceVersion here so
                    # unrelated controller status updates cannot defeat cancellation.
                    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': job['metadata']['uid']},
                             {'op': 'replace', 'path': '/spec/suspend', 'value': True}]
                    kubectl('patch', 'job/'+preload.JOB, '--type=json', '-p', json.dumps(patch), '-o', 'json')
                    current = get('job/'+preload.JOB)
                    stopped['job_suspended'] = (current['metadata']['uid'] == armed['binding']['job_uid']
                                                and current['spec'].get('suspend') is True)
            except Exception:
                pass
        if all(stopped.values()):
            return stopped
        time.sleep(.2)
    return stopped


def run_fresh(path, timeout):
    parent = Path(path).parent
    if any((parent/n).exists() for n in ('sms-preload-attempt.json', 'sms-preload-armed.json', 'sms-preload-acceptance.json')):
        raise preload.Blocked('Preload latch/receipt exists; no replay')
    context, job, plan, sources, service, empty = audit(path)
    key = secrets.token_bytes(32)
    binding = binding_for(path, context, job, plan, sources, service, key)
    durable_write(parent/'sms-preload-attempt.json', {'binding': binding, 'hmac_key': key.hex(), 'empty_audit': empty})
    obj = create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': preload.JOURNAL, 'namespace': 'onap'},
                  'data': {'journal.json': json.dumps({'state': 'unarmed', 'binding': binding})}})
    journal_uid = obj['metadata']['uid']
    config = {'contract': 1, 'plan': plan, 'binding': binding, 'journal_uid': journal_uid,
              'sms_address': service['spec']['clusterIP']}
    private_input = create({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': preload.INPUT_SECRET, 'namespace': 'onap'},
        'type': 'Opaque', 'immutable': True, 'data': {
            'input.json': base64.b64encode(preload.canonical(config)).decode(),
            'root.cer': base64.b64encode((Path(context['pki_directory'])/'root.cer').read_bytes()).decode()}})
    armed = {'binding': binding, 'journal_uid': journal_uid, 'input_secret_uid': private_input['metadata']['uid']}
    durable_write(parent/'sms-preload-armed.json', armed)
    replace_journal(obj, dict(state='prepared', binding=binding, input_secret_uid=armed['input_secret_uid']))
    try:
        # Recheck authoritative emptiness at the last controlled activation boundary.
        audit(path)
        _, current, _, _ = check_bindings(path, armed, key)
        if identity(current) != identity(job):
            raise preload.Blocked('Held Job changed before activation')
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': job['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': job['metadata']['resourceVersion']},
                 {'op': 'test', 'path': '/spec/suspend', 'value': True},
                 {'op': 'replace', 'path': '/spec/suspend', 'value': False}]
        kubectl('patch', 'job/'+preload.JOB, '--type=json', '-p', json.dumps(patch), '-o', 'json')
        deadline = time.monotonic()+timeout
        seen_pod = None
        while time.monotonic() < deadline:
            _, current, _, state = check_bindings(path, armed, key)
            if state.get('state') in ('uncertain', 'unarmed') or current['spec'].get('suspend'):
                raise preload.Blocked('Guarded execution stopped')
            pods = owned_pods(current)
            if len(pods) > 1 or (seen_pod and (len(pods) != 1 or pods[0]['metadata']['uid'] != seen_pod)):
                raise preload.Blocked('Preload Pod replaced or duplicated')
            if pods:
                seen_pod = pods[0]['metadata']['uid']
                if pods[0].get('status', {}).get('phase') == 'Failed':
                    raise preload.Blocked('Guarded preload Pod failed')
            conditions = current.get('status', {}).get('conditions', [])
            if any(c.get('type') == 'Failed' and c.get('status') == 'True' for c in conditions):
                raise preload.Blocked('Guarded preload Job failed')
            if any(c.get('type') == 'Complete' and c.get('status') == 'True' for c in conditions):
                state = postconditions(path, armed, key)
                receipt = {'schema': 1, 'passed': True, 'contract': 1, **armed,
                    'pod_uid': state['pod_uid'], 'domain_uuids': state['domain_uuids'],
                    'posts_observed': 22, 'private_values_verified': 20,
                    'accepted_utc': datetime.now(timezone.utc).isoformat()}
                durable_write(parent/'sms-preload-acceptance.json', receipt)
                return receipt
            time.sleep(2)
        raise preload.Blocked('Guarded preload deadline elapsed; no replay')
    except Exception:
        stopped = stop_attempt(armed)
        durable_write(parent/('sms-preload-stop-%d.json' % time.time_ns()), stopped)
        if not all(stopped.values()):
            print('URGENT: preload cancellation not fully confirmed; inspect the allocated guarded Job immediately')
        raise


def verify_acceptance(path):
    context = preload.strict_json(Path(path).read_bytes())
    if 'sms_preload_contract' not in context:
        return None
    if context['sms_preload_contract'] != preload.CONTRACT:
        raise preload.Blocked('Unreviewed preload context contract')
    parent = Path(path).parent
    latch = preload.strict_json((parent/'sms-preload-attempt.json').read_bytes())
    armed = preload.strict_json((parent/'sms-preload-armed.json').read_bytes())
    receipt = preload.strict_json((parent/'sms-preload-acceptance.json').read_bytes())
    if (receipt.get('schema') != 1 or receipt.get('contract') != 1 or receipt.get('passed') is not True
            or receipt.get('posts_observed') != 22 or receipt.get('private_values_verified') != 20
            or any(receipt.get(k) != v for k, v in armed.items()) or latch['binding'] != armed['binding']):
        raise preload.Blocked('Guarded preload acceptance receipt unavailable or changed')
    state = postconditions(path, armed, bytes.fromhex(latch['hmac_key']))
    if state['pod_uid'] != receipt['pod_uid'] or state['domain_uuids'] != receipt['domain_uuids']:
        raise preload.Blocked('Accepted preload journal changed')
    return {'preload_accepted': True, 'private_values_verified': 20}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for operation in ('audit', 'run-fresh', 'verify'):
        p = sub.add_parser(operation)
        p.add_argument('--context', default=CONTEXT)
        if operation == 'run-fresh':
            p.add_argument('--timeout', type=int, default=600, choices=range(1, 601))
    p = sub.add_parser('rehearse'); p.add_argument('--directory', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.operation == 'rehearse':
            rehearsal = load('preload_rehearsal_cli', 'phase3-sms-preload-rehearsal.py')
            result = rehearsal.check(args.directory, (['sudo'] if os.geteuid() != 0 and os.sys.platform != 'darwin' else [])+['docker'])
            preload.require_qualification(result)
        elif args.operation == 'audit':
            audit(args.context)
        elif args.operation == 'verify':
            if verify_acceptance(args.context) is None:
                raise preload.Blocked('Retained context is not guarded preload acceptance')
        else:
            with backend.driver_lock():
                run_fresh(args.context, args.timeout)
        print('Guarded SMS preload '+args.operation+' passed; full SMO/certificate acceptance remains separate')
        return 0
    except Exception:
        print('Guarded SMS preload blocked; private review required; no automatic retry/reset/reconciliation')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
