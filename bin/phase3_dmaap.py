"""Reviewed DMAAP 2.0.8 provisioning contract; Python 3.8 stdlib only.

Six client POST attempts maximum, not exactly-once server execution. The
server can provision downstream AAF/MR objects. No retry or reconciliation.
"""
import base64
import copy
import hashlib
import http.client
from pathlib import Path
import socket
import ssl

from phase3_preload import Blocked, canonical, strict_json

CONTRACT = 1
ROOT = Path(__file__).resolve().parents[1]
JOB = 'onap-dmaap-bc-dmaap-provisioning'
JOURNAL = 'phase3-dmaap-journal'
SA = 'phase3-dmaap'
INPUT_SECRET = 'phase3-dmaap-input'
IMAGE = 'nexus3.onap.org:10001/onap/oom/readiness@sha256:317c8a361ae73750f4d4a1b682c42b73de39083f73228dede31fd68b16c089db'
STOCK_IMAGE = 'nexus3.onap.org:10001/onap/dmaap/dbc-client@sha256:c5d0505287e1465214cf4ded947feca992a439e1d2294ca3a8954e20533de3ba'
SERVER_IMAGE = 'nexus3.onap.org:10001/onap/dmaap/dmaap-bc@sha256:2cdaf313ce70c749a0f3bd083eaf7415a4b1758d3f4f9695826e3006117be425'
STOCK_SCRIPT_SHA256 = '4ff8e62f5f7325b5bde110d2180cb170e2b13b2c1448f811600198cd8b0ed58c'
COMMAND = ['python3', '/phase3-dmaap/phase3-dmaap-client.py']
INVENTORY = (
    ('dmaap', 'dbc-dmaap', 'onap.json'),
    ('dcaeLocations', 'dbc-dcaelocations', 'san-francisco.json'),
    ('mr_clusters', 'mr-clusters', 'san-francisco.json'),
    ('topics', 'topics', 'PNF_READY.json'),
    ('topics', 'topics', 'PNF_REGISTRATION.json'),
    ('topics', 'topics', 'mirrormakeragent.json'))
EMPTY_MAPS = ('dr-nodes', 'feeds')
COLLECTIONS = ('dcaeLocations', 'mr_clusters', 'topics', 'mr_clients', 'dr_nodes', 'feeds', 'dr_pubs', 'dr_subs')
FIELDS = ({'bridgeAdminTopic', 'dmaapName', 'drProvUrl', 'topicNsRoot', 'version'},
          {'dcaeLayer', 'dcaeLocationName'},
          {'dcaeLocationName', 'fqdn', 'topicPort', 'topicProtocol'},
          {'clients', 'owner', 'tnxEnabled', 'topicDescription', 'topicName'})


def validate_plan(plan):
    if not isinstance(plan, list) or len(plan) != 6:
        raise Blocked('Unreviewed DMAAP input inventory')
    for i, (record, inventory) in enumerate(zip(plan, INVENTORY)):
        route, _, filename = inventory
        if (not isinstance(record, dict) or set(record) != {'route', 'file', 'body'}
                or (record['route'], record['file']) != (route, filename)
                or not isinstance(record['body'], dict)):
            raise Blocked('Unreviewed DMAAP input order or envelope')
        fields = FIELDS[min(i, 3)] | ({'partitionCount', 'replicationCase'} if i == 5 else set())
        body = record['body']
        if set(body) != fields:
            raise Blocked('Unreviewed DMAAP input fields')
        for key, value in body.items():
            if key == 'clients':
                if not isinstance(value, list) or len(value) != (3 if i == 5 else 1):
                    raise Blocked('Malformed DMAAP topic clients')
                for client in value:
                    principal = 'clientIdentity' if i == 5 else 'clientRole'
                    if (not isinstance(client, dict) or set(client) != {'dcaeLocationName', principal, 'action'}
                            or not isinstance(client['action'], list) or not client['action']
                            or any(a not in ('pub', 'sub', 'view') for a in client['action'])
                            or len(set(client['action'])) != len(client['action'])
                            or any(not isinstance(client[k], str) or not client[k] for k in ('dcaeLocationName', principal))):
                        raise Blocked('Unreviewed DMAAP topic-client relationship')
            elif key == 'tnxEnabled':
                if type(value) is not bool:
                    raise Blocked('Malformed DMAAP transaction flag')
            elif not isinstance(value, str) or not value:
                raise Blocked('Malformed DMAAP input leaf')
    location = plan[1]['body']['dcaeLocationName']
    if (plan[2]['body']['dcaeLocationName'] != location
            or any(c['dcaeLocationName'] != location for r in plan[3:] for c in r['body']['clients'])
            or len({r['body']['topicName'] for r in plan[3:]}) != 3):
        raise Blocked('DMAAP input relationships differ')
    return plan


class Transport:
    def __init__(self, ca, address, credential, hostname='dmaap-bc.onap', port=8443):
        if (not isinstance(credential, str) or ':' not in credential
                or any(c in credential for c in ('\r', '\n', '\0'))):
            raise Blocked('Existing basic credential contract unavailable')
        self.context = ssl.create_default_context(cafile=str(ca))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.address, self.hostname, self.port = address, hostname, port
        self.authorization = 'Basic '+base64.b64encode(credential.encode()).decode()

    def request(self, method, path, data=None):
        if method not in ('GET', 'POST') or path not in {'/webapi/dmaap', *('/webapi/'+p for p in COLLECTIONS)}:
            raise Blocked('Unreviewed DMAAP method or path')
        conn = http.client.HTTPSConnection(self.hostname, self.port, timeout=15, context=self.context)
        conn._create_connection = lambda *a, **k: socket.create_connection((self.address, self.port), timeout=15)
        try:
            conn.request(method, path, canonical(data) if data is not None else None,
                         {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': self.authorization})
            response = conn.getresponse()
            body = response.read(1024*1024+1)
            if len(body) > 1024*1024:
                raise Blocked('Oversized DMAAP response')
            return response.status, body
        finally:
            conn.close()


def read(transport, route):
    code, blob = transport.request('GET', '/webapi/'+route)
    if code != 200:
        raise Blocked('DMAAP authenticated catalog unavailable; no absence inference')
    result = strict_json(blob)
    if (route == 'dmaap' and not isinstance(result, dict)) or (route != 'dmaap' and not isinstance(result, list)):
        raise Blocked('Malformed DMAAP catalog')
    return result


def audit_catalog(transport):
    singleton = read(transport, 'dmaap')
    expected = {'version': '0', 'dmaapName': '', 'topicNsRoot': '', 'drProvUrl': '',
                'bridgeAdminTopic': '', 'loggingUrl': '', 'nodeKey': '', 'accessKeyOwner': ''}
    if (any(singleton.get(k) != v for k, v in expected.items())
            or set(singleton) != set(expected) | {'lastMod', 'status', 'statusValid'}
            or singleton.get('status') != 'NEW' or singleton.get('statusValid') is not False):
        raise Blocked('DMAAP singleton is not the qualified fresh default')
    for route in COLLECTIONS:
        if read(transport, route) != []:
            raise Blocked('Existing DMAAP collection; no partial reconciliation')
    return {'default_singleton': True, 'empty_collections': len(COLLECTIONS)}


def matches(supplied, actual):
    """Every supplied field must survive; server-managed fields may be added."""
    if isinstance(supplied, dict):
        return isinstance(actual, dict) and all(k in actual and matches(v, actual[k]) for k, v in supplied.items())
    if isinstance(supplied, list):
        if not isinstance(actual, list) or len(actual) != len(supplied):
            return False
        remaining = list(actual)
        for value in supplied:
            found = [i for i, item in enumerate(remaining) if matches(value, item)]
            if len(found) != 1:
                return False
            remaining.pop(found[0])
        return not remaining
    return type(supplied) is type(actual) and supplied == actual


def check_record(body, actual):
    expected = copy.deepcopy(body)
    # The 2.0.8 Topic Java model uses String get/setTnxEnabled. Jackson accepts
    # the stock chart's JSON boolean but emits its lowercase string. Do not
    # generalize this to arbitrary type coercion or change the submitted input.
    if 'tnxEnabled' in expected:
        expected['tnxEnabled'] = 'true' if expected['tnxEnabled'] else 'false'
    if not matches(expected, actual) or actual.get('status') != 'VALID' or actual.get('statusValid') is not True:
        raise Blocked('DMAAP supplied-field/status postcondition failed')


def verify_values(plan, transport, through=6):
    validate_plan(plan)
    check_record(plan[0]['body'], read(transport, 'dmaap'))
    expected_clients = []
    for route, indices in (('dcaeLocations', [1]), ('mr_clusters', [2]), ('topics', [3, 4, 5])):
        records = read(transport, route)
        expected = [plan[i]['body'] for i in indices if i < through]
        if len(records) != len(expected):
            raise Blocked('DMAAP postcondition inventory mismatch')
        identity = 'topicName' if route == 'topics' else 'dcaeLocationName'
        for body in expected:
            found = [r for r in records if isinstance(r, dict) and r.get(identity) == body[identity]]
            if len(found) != 1:
                raise Blocked('DMAAP missing or duplicate record')
            check_record(body, found[0])
            if route == 'topics':
                topic = found[0]
                fqtn = topic.get('fqtn')
                if not isinstance(fqtn, str) or not fqtn:
                    raise Blocked('DMAAP topic identity unavailable')
                for client in topic['clients']:
                    if (client.get('fqtn') != fqtn or client.get('status') != 'VALID'
                            or client.get('statusValid') is not True or not client.get('mrClientId')
                            or not client.get('topicURL')):
                        raise Blocked('DMAAP topic/client relationship postcondition failed')
                    expected_clients.append(client)
    actual_clients = read(transport, 'mr_clients')
    if (not matches(expected_clients, actual_clients)
            or len({c['mrClientId'] for c in expected_clients}) != len(expected_clients)):
        raise Blocked('DMAAP global client inventory differs')
    for route in ('dr_nodes', 'feeds', 'dr_pubs', 'dr_subs'):
        if read(transport, route) != []:
            raise Blocked('Unexpected DMAAP data-router state')


def execute(plan, transport, journal, binding, pod_uid):
    validate_plan(plan)
    old = journal.read()
    if not pod_uid or old.get('state') != 'prepared' or old.get('binding') != binding:
        raise Blocked('DMAAP attempt already claimed or binding changed')
    def transition(**changes):
        nonlocal old
        if journal.read() != old:
            raise Blocked('Concurrent DMAAP journal change')
        new = dict(old, **changes)
        journal.cas(old, new)
        old = journal.read()
        if any(old.get(k) != v for k, v in new.items() if not k.startswith('_')):
            raise Blocked('DMAAP journal outcome uncertain')
    transition(state='claimed', pod_uid=pod_uid, posts_observed=0)
    try:
        audit_catalog(transport)  # Repeat immediately in the sole guarded client.
        for index, record in enumerate(plan):
            transition(state='intent', operation=index, posts_attempted=index+1)
            code, blob = transport.request('POST', '/webapi/'+record['route'], record['body'])
            actual = strict_json(blob)
            if code != (200 if index == 0 else 201):
                raise Blocked('DMAAP write response rejected; no retry')
            check_record(record['body'], actual)
            verify_values(plan, transport, through=index+1)
            transition(state='observed', posts_observed=index+1)
        verify_values(plan, transport)
        transition(state='verified', operation='all-private-postconditions', posts_observed=6)
        return old
    except Exception:
        try:
            transition(state='uncertain', reason='execution-stopped-no-replay')
        except Exception:
            pass
        raise


def helper_config():
    data = {n: (ROOT/'bin'/n).read_text() for n in ('phase3_preload.py', 'phase3_dmaap.py', 'phase3-dmaap-client.py')}
    digest = hashlib.sha256(canonical(data)).hexdigest()
    return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
        'name': 'phase3-dmaap-'+digest[:16], 'namespace': 'onap'}, 'immutable': True, 'data': data}


def is_client(container):
    return (container.get('name')=='dmaap-provisioning-job' and container.get('image')==IMAGE
            and container.get('command')==COMMAND and not container.get('args'))


def resources():
    meta = {'name': SA, 'namespace': 'onap'}
    return [{'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': meta.copy(), 'automountServiceAccountToken': False},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': meta.copy(), 'rules': [
            {'apiGroups': [''], 'resources': ['configmaps'], 'resourceNames': [JOURNAL], 'verbs': ['get', 'update']}]},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': meta.copy(),
         'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': SA},
         'subjects': [{'kind': 'ServiceAccount', 'name': SA, 'namespace': 'onap'}]}]


def patch_job(resource):
    if (resource.get('kind') != 'Job' or resource['metadata']['name'] != JOB
            or resource['metadata'].get('namespace', 'onap') != 'onap'):
        raise Blocked('Unreviewed DMAAP Job target')
    r = copy.deepcopy(resource)
    containers = r['spec']['template']['spec'].get('containers', [])
    if (len(containers) != 1 or containers[0].get('name') != 'dmaap-provisioning-job'
            or containers[0].get('image') not in (STOCK_IMAGE, 'nexus3.onap.org:10001/onap/dmaap/dbc-client:1.0.9')
            or containers[0].get('command') or containers[0].get('args')):
        raise Blocked('Unreviewed stock DMAAP entry point')
    r['metadata'].setdefault('annotations', {})['phase3.onap.org/dmaap-gate'] = 'guarded-v1'
    labels=r['spec']['template'].setdefault('metadata', {}).setdefault('labels', {})
    labels['app'] = labels['app.kubernetes.io/name'] = 'phase3-dmaap-provisioner'
    r['spec'].update(suspend=True, backoffLimit=0, parallelism=1, completions=1, activeDeadlineSeconds=600)
    r['spec']['template']['spec'] = {
        'restartPolicy': 'Never', 'serviceAccountName': SA, 'automountServiceAccountToken': False,
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000, 'fsGroup': 1000},
        'containers': [{'name': 'dmaap-provisioning-job', 'image': IMAGE, 'command': COMMAND.copy(),
            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '10m', 'memory': '64Mi'}, 'limits': {'memory': '128Mi'}},
            'env': [{'name': 'PYTHONDONTWRITEBYTECODE', 'value': '1'},
                    {'name': 'PHASE3_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}],
            'volumeMounts': [{'name': 'code', 'mountPath': '/phase3-dmaap', 'readOnly': True},
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
    spec=importlib.util.spec_from_file_location('dmaap_qualification',ROOT/'bin/phase3-dmaap-rehearsal.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    runtime=record.get('runtime',{})
    if (record.get('schema')!=1 or record.get('passed') is not True or record.get('contract')!=CONTRACT
            or record.get('synthetic_material_only') is not True or record.get('live_api_contacted') is not False
            or record.get('images')!={'server':SERVER_IMAGE,'stock_client':STOCK_IMAGE,'client':IMAGE,'postgres':module.PG_IMAGE}
            or record.get('tested_sources_sha256')!={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in module.SOURCES}
            or runtime.get('passed') is not True or runtime.get('posts')!=6
            or runtime.get('private_fields_and_relationships_verified') is not True
            or runtime.get('clients_verified')!=5 or runtime.get('aaf_requests',0)<1 or runtime.get('mr_requests',0)<1
            or record.get('client_adapter_https_qualified') is not True):
        raise Blocked('Exact-image DMAAP qualification missing or stale')
    return True
