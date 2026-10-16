"""Fresh SMS preload contract and no-retry writer. Python 3.8 stdlib only."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import ssl

CONTRACT = 1
JOB = 'onap-aaf-sms-preload'
JOURNAL = 'phase3-sms-preload-journal'
INPUT_SECRET = 'phase3-sms-preload-input'
SA = 'phase3-sms-preload'
IMAGE = 'nexus3.onap.org:10001/onap/oom/readiness@sha256:317c8a361ae73750f4d4a1b682c42b73de39083f73228dede31fd68b16c089db'
COMMAND = ['python3', '/phase3-preload/phase3-sms-preload-client.py']
STOCK_COMMAND = ['/sms/bin/preload', '-cacert', '/opt/app/osaaf/local/aaf_root_ca.cer',
                 '-jsondir', '/preload/config', '-serviceport', '10443', '-serviceurl', 'https://aaf-sms.onap']
ROOT = Path(__file__).resolve().parents[1]
INVENTORY = {
    'has': {'aai': ['password', 'username'], 'conductor_api': ['password', 'username'],
        'sdnc': ['password', 'username'], 'music_api': ['aafns', 'aafpass', 'aafuser'],
        'aaf_api': ['aaf_conductor_user', 'password', 'username'], 'sdc': ['password', 'username']},
    'osdf': {n: ['Password', 'UserName'] for n in ('so', 'conductor', 'policyPlatform',
        'policyClient', 'dmaap', 'sdc', 'osdfPlacement', 'osdfPlacementSO', 'osdfPlacementVFC',
        'osdfCMScheduler', 'configDb', 'pciHMS', 'osdfPCIOpt', 'osdfOptEngine')}}
PREFIXES = dict(zip(('AAI', 'CONDUCTOR', 'SDNC', 'MUSIC', 'AAF', 'POLICY_PLAT', 'POLICY_CLI',
    'OSDF_PLACEMENT', 'OSDF_PLACEMENT_SO', 'OSDF_PLACEMENT_VFC', 'OSDF_CM_SCHEDULER',
    'CONFIG_DB', 'OSDF_PCI_OPT', 'OSDF_OPT_ENGINE', 'SO', 'SDC'),
    ('aai', 'conductor', 'sdnc', 'music', 'aaf', 'policy-plat', 'policy-cli', 'osdf-placement',
     'osdf-placement-so', 'osdf-placement-vfc', 'osdf-cm-scheduler', 'config-db', 'osdf-pci-opt',
     'osdf-opt-engine', 'so', 'sdc')))
REFERENCES = {p+'_'+suffix: ('onap-aaf-sms-'+name+'-creds', key)
    for p, name in PREFIXES.items() for suffix, key in (('USER', 'login'), ('PASS', 'password'))}
# Hashes of the public, unexpanded pinned-chart templates, NOT credential hashes.
TEMPLATE_HASHES = {'has.json': 'bc7f802cb896caa1de28e7061ba42fba883a62fbf2355ad996bf2176c0f3b03b',
                   'osdf.json': '770c1f9df6bb8ca96e521400d80188301f6be6cd58e77f1e6a5383a237c24e39'}


class Blocked(ValueError):
    """Sanitized failure; never include response bodies or credential values."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def strict_json(blob):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Blocked('Duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(blob, object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(Blocked('Invalid JSON constant')))
    except (TypeError, UnicodeError, json.JSONDecodeError):
        raise Blocked('Invalid JSON input or response') from None


def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != {'domains'} or not isinstance(plan['domains'], list):
        raise Blocked('Unreviewed preload plan')
    domains = plan['domains']
    if any(not isinstance(d, dict) for d in domains) or [d.get('name') for d in domains] != sorted(INVENTORY):
        raise Blocked('Unreviewed domain inventory/order')
    for domain in domains:
        if set(domain) != {'name', 'secrets'} or not isinstance(domain['secrets'], list):
            raise Blocked('Unreviewed domain fields')
        expected = INVENTORY[domain['name']]
        if (any(not isinstance(s, dict) for s in domain['secrets'])
                or [s.get('name') for s in domain['secrets']] != sorted(expected)):
            raise Blocked('Unreviewed secret inventory/order')
        for secret in domain['secrets']:
            if (set(secret) != {'name', 'values'} or not isinstance(secret['values'], dict)
                    or set(secret['values']) != set(expected[secret['name']])
                    or any(not isinstance(v, str) for v in secret['values'].values())):
                raise Blocked('Unreviewed secret value keys/types')
    return plan


def validate_inputs(files, substitutions=None):
    if set(files) != {'has.json', 'osdf.json'}:
        raise Blocked('Unreviewed preload template inventory')
    result = {'domains': []}
    for domain in sorted(INVENTORY):
        value = strict_json(files[domain+'.json'])
        if not isinstance(value, dict) or set(value) != {'domain'} or not isinstance(value['domain'], dict):
            raise Blocked('Unreviewed template envelope')
        value = copy.deepcopy(value['domain'])
        if value.get('name') != domain:
            raise Blocked('Template filename/domain mismatch')
        if not isinstance(value.get('secrets'), list):
            raise Blocked('Missing secret inventory')
        for record in value['secrets']:
            if not isinstance(record, dict) or not isinstance(record.get('values'), dict):
                raise Blocked('Invalid secret template')
            for key, text in record['values'].items():
                if not isinstance(text, str):
                    raise Blocked('Non-string template leaf')
                matches = re.findall(r'\$\{([^}]+)\}', text)
                if substitutions is not None:
                    for variable in matches:
                        if variable not in REFERENCES or not substitutions.get(variable):
                            raise Blocked('Missing or unreviewed template reference')
                    record['values'][key] = re.sub(r'\$\{([^}]+)\}', lambda m: substitutions[m[1]], text)
                elif matches:
                    raise Blocked('Unresolved template reference')
        value['secrets'].sort(key=lambda s: s['name'])
        result['domains'].append(value)
    return validate_plan(result)


def synthetic_inputs():
    """Only synthetic data for isolated checks, never read from a live Secret."""
    return {'domains': [{'name': d, 'secrets': [{'name': n, 'values': {
        k: 'fixture-only-"\\\n\u03bb-$value-'+k for k in INVENTORY[d][n]}}
        for n in sorted(INVENTORY[d])]} for d in sorted(INVENTORY)]}


def validate_acl(acl):
    """Vault 1.3.3 visibility is authoritative only with the exact SMS ACL."""
    data = acl.get('data', {})
    if (data.get('root') is not False or not isinstance(data.get('exact_paths'), dict)
            or not isinstance(data.get('glob_paths'), dict)):
        raise Blocked('Effective scoped ACL metadata unavailable')
    intersecting = {}
    for section in ('exact_paths', 'glob_paths'):
        for path, entry in data[section].items():
            if path.startswith('sms') or 'sms/'.startswith(path) or path.startswith('sys/mounts/sms'):
                if section != 'glob_paths':
                    raise Blocked('Unreviewed exact SMS ACL rule')
                intersecting[path] = entry
    expected = {'sms/': {'create', 'read', 'update', 'delete', 'list'},
                'sys/mounts/sms': {'create', 'update', 'delete'}}
    if set(intersecting) != set(expected):
        raise Blocked('SMS mount catalog visibility is not complete')
    for path, entry in intersecting.items():
        if (not isinstance(entry, dict) or set(entry.get('capabilities', [])) != expected[path]
                or any(v for k, v in entry.items() if k != 'capabilities')):
            raise Blocked('Restricted or unreviewed SMS ACL')
    return True


def audit_catalog(acl, catalog):
    validate_acl(acl)
    mounts = catalog.get('data', {}).get('secret')
    if not isinstance(mounts, dict):
        raise Blocked('Authenticated mount catalog unavailable')
    for path, entry in mounts.items():
        if not isinstance(path, str) or not path.endswith('/') or not isinstance(entry, dict):
            raise Blocked('Malformed mount catalog')
        if path.startswith('sms') or 'sms/'.startswith(path):
            raise Blocked('Existing SMS mount; no overwrite or reconciliation')
    return {'sms_mounts_absent': True, 'acl_complete': True}


class Transport:
    def __init__(self, ca, address, hostname='aaf-sms.onap', port=10443):
        self.context = ssl.create_default_context(cafile=str(ca))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.address, self.hostname, self.port = address, hostname, port

    def request(self, method, path, data=None):
        conn = http.client.HTTPSConnection(self.hostname, self.port, timeout=10, context=self.context)
        conn._create_connection = lambda *a, **k: socket.create_connection((self.address, self.port), timeout=10)
        try:
            conn.request(method, path, canonical(data) if data is not None else None,
                         {'Content-Type': 'application/json'})
            response = conn.getresponse()
            body = response.read(1024*1024+1)
            if len(body) > 1024*1024:
                raise Blocked('Oversized SMS response')
            return response.status, body
        finally:
            conn.close()


def get_json(transport, path):
    code, blob = transport.request('GET', path)
    if code != 200:
        raise Blocked('SMS private readback failed')
    return strict_json(blob)


def verify_values(plan, transport):
    validate_plan(plan)
    for domain in plan['domains']:
        path = '/v1/sms/domain/'+domain['name']+'/secret'
        names = get_json(transport, path)
        if (not isinstance(names, dict) or set(names) != {'secretnames'} or not isinstance(names['secretnames'], list)
                or sorted(names['secretnames']) != [s['name'] for s in domain['secrets']]):
            raise Blocked('SMS secret-name inventory mismatch')
        for secret in domain['secrets']:
            if get_json(transport, path+'/'+secret['name']) != secret:
                raise Blocked('SMS private value readback mismatch')


def execute(plan, transport, journal, binding, pod_uid):
    validate_plan(plan)
    old = journal.read()
    if not pod_uid or old.get('state') != 'prepared' or old.get('binding') != binding:
        raise Blocked('Preload attempt already claimed or binding changed')
    def transition(**changes):
        nonlocal old
        current = journal.read()
        if current != old:
            raise Blocked('Concurrent journal modification; attempt stopped')
        new = dict(old, **changes)
        journal.cas(old, new)
        old = journal.read()
        if any(old.get(k) != v for k, v in new.items() if not k.startswith('_')):
            raise Blocked('Journal update outcome is uncertain')
    transition(state='claimed', pod_uid=pod_uid, posts_observed=0, domain_uuids={})
    count = 0
    try:
        for domain in plan['domains']:
            transition(state='intent', operation='domain:'+domain['name'])
            code, blob = transport.request('POST', '/v1/sms/domain', {'name': domain['name']})
            response = strict_json(blob)
            if (code != 201 or not isinstance(response, dict) or set(response) != {'name', 'uuid'}
                    or response['name'] != domain['name'] or not isinstance(response['uuid'], str)
                    or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', response['uuid'])):
                raise Blocked('Domain create response was not accepted')
            count += 1
            uuids = dict(old['domain_uuids'], **{domain['name']: response['uuid']})
            if len(set(uuids.values())) != len(uuids):
                raise Blocked('Duplicate domain identity')
            transition(state='observed', posts_observed=count, domain_uuids=uuids)
        for domain in plan['domains']:
            path = '/v1/sms/domain/'+domain['name']+'/secret'
            for secret in domain['secrets']:
                transition(state='intent', operation=domain['name']+':'+secret['name'])
                code, body = transport.request('POST', path, secret)
                if code != 201 or body:
                    raise Blocked('Secret create response was not accepted')
                if get_json(transport, path+'/'+secret['name']) != secret:
                    raise Blocked('SMS private value readback mismatch')
                count += 1
                transition(state='observed', posts_observed=count)
        verify_values(plan, transport)
        transition(state='verified', operation='all-private-postconditions', posts_observed=22)
        return old
    except Exception:
        try:
            transition(state='uncertain', reason='execution-stopped-no-replay')
        except Exception:
            pass
        raise


def helper_config():
    data = {n: (ROOT/'bin'/n).read_text() for n in ('phase3_preload.py', 'phase3-sms-preload-client.py')}
    digest = hashlib.sha256(canonical(data)).hexdigest()
    return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
        'name': 'phase3-preload-'+digest[:16], 'namespace': 'onap'}, 'immutable': True, 'data': data}


def resources(context):
    if context.get('sms_preload_contract') != CONTRACT:
        raise Blocked('Fresh preload contract unavailable')
    meta = {'name': SA, 'namespace': 'onap'}
    return [{'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': meta.copy(), 'automountServiceAccountToken': False},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': meta.copy(), 'rules': [
            {'apiGroups': [''], 'resources': ['configmaps'], 'resourceNames': [JOURNAL], 'verbs': ['get', 'update']}]},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': meta.copy(),
         'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': SA},
         'subjects': [{'kind': 'ServiceAccount', 'name': SA, 'namespace': 'onap'}]}]


def is_client(container):
    return (container.get('name') == 'aaf-sms-preload' and container.get('image') == IMAGE
            and container.get('command') == COMMAND and not container.get('args'))


def patch_job(resource, context):
    if context.get('sms_preload_contract') != CONTRACT or context.get('sms_backend_contract') != 1:
        raise Blocked('Fresh backend/preload contract unavailable')
    if (resource.get('kind') != 'Job' or resource['metadata']['name'] != JOB
            or resource['metadata'].get('namespace', 'onap') != 'onap'):
        raise Blocked('Unreviewed preload Job target')
    r = copy.deepcopy(resource)
    pod = r['spec']['template']['spec']
    containers = pod.get('containers', [])
    if (len(containers) != 1 or containers[0].get('name') != 'aaf-sms-preload'
            or containers[0].get('image') not in (
                'nexus3.onap.org:10001/onap/aaf/sms:4.0.2',
                'nexus3.onap.org:10001/onap/aaf/sms@sha256:8bbed20427d11342eb96ebcf6c592f54cf9ee647aa8d3989e317f634f222e293')
            or containers[0].get('command') != STOCK_COMMAND or containers[0].get('args')):
        raise Blocked('Unreviewed stock preload entry point')
    labels = r['spec']['template']['metadata']['labels']
    if labels.get('app') != 'aaf-sms' or labels.get('release') != 'onap' or 'phase3.onap.org/sms-role' in labels:
        raise Blocked('Unreviewed preload role labels')
    labels['phase3.onap.org/sms-role'] = 'preload'
    r['metadata'].setdefault('annotations', {})['phase3.onap.org/preload-gate'] = 'guarded-fresh-v1'
    r['spec'].update(suspend=True, backoffLimit=0, parallelism=1, completions=1, activeDeadlineSeconds=600)
    r['spec']['template']['spec'] = {
        'restartPolicy': 'Never', 'serviceAccountName': SA, 'automountServiceAccountToken': False,
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000, 'fsGroup': 1000},
        'containers': [{'name': 'aaf-sms-preload', 'image': IMAGE, 'command': COMMAND.copy(),
            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '10m', 'memory': '64Mi'}, 'limits': {'memory': '128Mi'}},
            'env': [{'name': 'PYTHONDONTWRITEBYTECODE', 'value': '1'},
                    {'name': 'PHASE3_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}],
            'volumeMounts': [{'name': 'code', 'mountPath': '/phase3-preload', 'readOnly': True},
                {'name': 'input', 'mountPath': '/phase3-input', 'readOnly': True},
                {'name': 'api', 'mountPath': '/phase3-api', 'readOnly': True}]}],
        'volumes': [{'name': 'code', 'configMap': {'name': helper_config()['metadata']['name'], 'defaultMode': 292}},
            {'name': 'input', 'secret': {'secretName': INPUT_SECRET, 'defaultMode': 288}},
            {'name': 'api', 'projected': {'defaultMode': 288, 'sources': [
                {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 600}},
                {'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}}]}}]}
    return r


def require_qualification(record):
    import importlib.util
    import phase3_sms_backend
    sources = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (
        ROOT/'bin/phase3_preload.py', ROOT/'bin/phase3-sms-preload-client.py',
        ROOT/'bin/phase3-sms-preload-rehearsal.py', ROOT/'tools/Phase3PreloadFixture.py')}
    if (record.get('schema') != 1 or record.get('passed') is not True
            or record.get('contract') != CONTRACT or record.get('client_image') != IMAGE
            or record.get('synthetic_material_only') is not True or record.get('live_api_contacted') is not False
            or record.get('real_sms_posts') != 22 or record.get('private_values_verified') != 20
            or record.get('acl_catalog_qualified') is not True or record.get('existing_mount_blocked') is not True
            or record.get('client_adapter_https_qualified') is not True
            or record.get('internal_uuid_metadata_qualified') is not True
            or record.get('tested_sources_sha256') != sources
            or record.get('images') != dict(phase3_sms_backend.IMAGES, readiness=IMAGE)
            or record.get('client_source_sha256') != hashlib.sha256((ROOT/'bin/phase3-sms-preload-client.py').read_bytes()).hexdigest()
            or record.get('contract_source_sha256') != hashlib.sha256((ROOT/'bin/phase3_preload.py').read_bytes()).hexdigest()):
        raise Blocked('Exact-image preload qualification missing or stale')
    spec = importlib.util.spec_from_file_location('preload_receipt_validation', ROOT/'bin/phase3-sms-preload-rehearsal.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.validate_observations({'real': record.get('runtime', {}), 'faults': record.get('cases', {}),
                                  'journal': record.get('client_adapter', {})})
    return True
