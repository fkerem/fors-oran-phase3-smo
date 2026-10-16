"""Unit contracts for the guarded writer; no sockets, kubectl or real credentials."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import ssl
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import phase3_preload as preload

spec = importlib.util.spec_from_file_location('preload_client_unit', ROOT / 'bin/phase3-sms-preload-client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)

# Independent expectations: deriving these from INVENTORY would hide inventory drift.
REVIEWED = {
    'has': {'aai': ['password', 'username'], 'conductor_api': ['password', 'username'],
            'sdnc': ['password', 'username'], 'music_api': ['aafns', 'aafpass', 'aafuser'],
            'aaf_api': ['aaf_conductor_user', 'password', 'username'], 'sdc': ['password', 'username']},
    'osdf': {name: ['Password', 'UserName'] for name in (
        'so', 'conductor', 'policyPlatform', 'policyClient', 'dmaap', 'sdc',
        'osdfPlacement', 'osdfPlacementSO', 'osdfPlacementVFC', 'osdfCMScheduler',
        'configDb', 'pciHMS', 'osdfPCIOpt', 'osdfOptEngine')},
}
PREFIXES = {
    'AAI': 'aai', 'CONDUCTOR': 'conductor', 'SDNC': 'sdnc', 'MUSIC': 'music',
    'AAF': 'aaf', 'POLICY_PLAT': 'policy-plat', 'POLICY_CLI': 'policy-cli',
    'OSDF_PLACEMENT': 'osdf-placement', 'OSDF_PLACEMENT_SO': 'osdf-placement-so',
    'OSDF_PLACEMENT_VFC': 'osdf-placement-vfc', 'OSDF_CM_SCHEDULER': 'osdf-cm-scheduler',
    'CONFIG_DB': 'config-db', 'OSDF_PCI_OPT': 'osdf-pci-opt',
    'OSDF_OPT_ENGINE': 'osdf-opt-engine', 'SO': 'so', 'SDC': 'sdc',
}
PRIVATE = 'fixture-only: $\'quoted\' ${UNKNOWN} $(no-command) `no-command` " \\ \n\t λ雪🙂'
UUIDS = {'has': '11111111-1111-4111-8111-111111111111',
         'osdf': '22222222-2222-4222-8222-222222222222'}


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode('utf-8')


def plan_fixture():
    return {'domains': [{'name': domain, 'secrets': [
        {'name': name, 'values': {key: '' if name == 'pciHMS' else PRIVATE + ':' + key
                                 for key in REVIEWED[domain][name]}}
        for name in sorted(REVIEWED[domain])]} for domain in sorted(REVIEWED)]}


def template_fixture():
    plan = plan_fixture()
    has = {'aai': 'AAI', 'conductor_api': 'CONDUCTOR', 'sdnc': 'SDNC',
           'music_api': 'MUSIC', 'aaf_api': 'AAF', 'sdc': 'SDC'}
    osdf = dict(zip(REVIEWED['osdf'], (
        'SO', 'CONDUCTOR', 'POLICY_PLAT', 'POLICY_CLI', 'AAF', 'SDC',
        'OSDF_PLACEMENT', 'OSDF_PLACEMENT_SO', 'OSDF_PLACEMENT_VFC',
        'OSDF_CM_SCHEDULER', 'CONFIG_DB', None, 'OSDF_PCI_OPT', 'OSDF_OPT_ENGINE')))
    for domain in plan['domains']:
        for secret in domain['secrets']:
            prefix = (has if domain['name'] == 'has' else osdf)[secret['name']]
            for key in secret['values']:
                if prefix is None:
                    secret['values'][key] = ''
                elif key == 'aafns':
                    secret['values'][key] = 'org.onap.synthetic'
                else:
                    suffix = 'PASS' if key.lower() in ('password', 'aafpass') else 'USER'
                    secret['values'][key] = '${' + prefix + '_' + suffix + '}'
    return {domain['name'] + '.json': encoded({'domain': domain}) for domain in plan['domains']}


class ProcessCrash(BaseException):
    """Simulate SIGKILL without allowing the writer's Exception handler to run."""


class StatefulSMS:
    """Wire-level model, independent of production validation and response helpers."""
    def __init__(self, fault=None):
        self.domains = {}
        self.requests = []
        self.fault = fault

    @property
    def posts(self):
        return [(method, path) for method, path in self.requests if method == 'POST']

    def request(self, method, path, data=None):
        self.requests.append((method, path))
        parts = path.strip('/').split('/')
        if method == 'POST' and parts == ['v1', 'sms', 'domain']:
            assert set(data) == {'name'}
            name = data['name']
            if name in self.domains:
                response = (409, b'{}')
            else:
                self.domains[name] = {}
                response = (201, encoded({'name': name, 'uuid': UUIDS[name]}))
        elif len(parts) in (5, 6) and parts[:3] == ['v1', 'sms', 'domain'] and parts[4] == 'secret':
            records = self.domains[parts[3]]
            if method == 'POST' and len(parts) == 5:
                assert set(data) == {'name', 'values'}
                if data['name'] in records:
                    response = (409, b'')
                else:
                    records[data['name']] = copy.deepcopy(data)
                    response = (201, b'')
            elif method == 'GET' and len(parts) == 5:
                response = (200, encoded({'secretnames': sorted(records)}))
            elif method == 'GET' and len(parts) == 6:
                response = (200, encoded(records[parts[5]]))
            else:
                raise AssertionError('Unexpected SMS method')
        else:
            raise AssertionError('Unexpected SMS path: ' + path)
        return self.fault(method, path, response, self) if self.fault else response


class CASJournal:
    def __init__(self, binding):
        self.record = {'state': 'prepared', 'binding': copy.deepcopy(binding)}
        self.version = 1
        self.history = []
        self.before_cas = None

    def read(self):
        return dict(copy.deepcopy(self.record), _resourceVersion=str(self.version))

    def cas(self, old, new):
        if self.before_cas:
            self.before_cas(old, new)
        if old != self.read():
            raise preload.Blocked('Synthetic CAS conflict')
        self.record = {k: copy.deepcopy(v) for k, v in new.items() if not k.startswith('_')}
        self.version += 1
        self.history.append(copy.deepcopy(self.record))


class InputTests(unittest.TestCase):
    def test_exact_inventory_and_32_reference_allowlist(self):
        self.assertEqual(REVIEWED, preload.INVENTORY)
        references = {prefix + '_' + suffix: ('onap-aaf-sms-' + name + '-creds', key)
                      for prefix, name in PREFIXES.items()
                      for suffix, key in (('USER', 'login'), ('PASS', 'password'))}
        self.assertEqual(32, len(references))
        self.assertEqual(references, preload.REFERENCES)
        self.assertEqual(('onap-aaf-sms-osdf-placement-vfc-creds', 'password'),
                         preload.REFERENCES['OSDF_PLACEMENT_VFC_PASS'])

    def test_substitution_preserves_dollar_quotes_unicode_and_two_empty_literals(self):
        substitutions = {name: PRIVATE + ':' + name for name in preload.REFERENCES}
        files = template_fixture()
        before = copy.deepcopy(files)
        with patch('subprocess.run', side_effect=AssertionError('No shell expansion')):
            plan = preload.validate_inputs(files, substitutions)
        self.assertEqual(before, files)
        secrets = {d['name']: {s['name']: s['values'] for s in d['secrets']} for d in plan['domains']}
        self.assertEqual({'Password': '', 'UserName': ''}, secrets['osdf']['pciHMS'])
        self.assertEqual(substitutions['OSDF_PLACEMENT_VFC_USER'], secrets['osdf']['osdfPlacementVFC']['UserName'])
        self.assertEqual(substitutions['OSDF_PLACEMENT_VFC_PASS'], secrets['osdf']['osdfPlacementVFC']['Password'])
        self.assertIn('${UNKNOWN}', secrets['has']['aai']['password'])
        self.assertEqual(plan, preload.strict_json(preload.canonical(plan)))

    def test_input_envelope_and_inventory_fail_closed(self):
        files = template_fixture()
        mutations = [
            lambda x: x.pop('osdf.json'),
            lambda x: x.update(extra=encoded({})),
            lambda x: x.update({'has.json': b'[]'}),
            lambda x: x.update({'has.json': b'{"domain":null}'}),
            lambda x: x.update({'has.json': b'{"domain":{},"extra":1}'}),
            lambda x: x.update({'has.json': files['osdf.json']}),
            lambda x: x.update({'has.json': b'{"domain":{"name":"has","secrets":[]}}'}),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(files)
                mutate(changed)
                with self.assertRaises(preload.Blocked):
                    preload.validate_inputs(changed, {k: PRIVATE for k in preload.REFERENCES})

    def test_missing_empty_unknown_and_misspelled_references_rejected(self):
        for variable, substitutions in (
            ('AAI_USER', {}), ('AAI_USER', {'AAI_USER': ''}),
            ('OSDF_PLACEMENT_VCF_PASS', {'OSDF_PLACEMENT_VCF_PASS': PRIVATE}),
            ('HOME', {'HOME': PRIVATE}), ('UNKNOWN', {'UNKNOWN': PRIVATE}),
        ):
            with self.subTest(variable=variable, empty=not bool(substitutions)):
                files = template_fixture()
                obj = json.loads(files['has.json'])
                obj['domain']['secrets'][0]['values']['password'] = '${' + variable + '}'
                files['has.json'] = encoded(obj)
                with self.assertRaises(preload.Blocked):
                    preload.validate_inputs(files, substitutions)
        with self.assertRaisesRegex(preload.Blocked, 'Unresolved'):
            preload.validate_inputs(template_fixture())

    def test_plan_rejects_case_unknown_missing_duplicate_inventory_and_nonstring_values(self):
        mutations = {
            'domain case': lambda p: p['domains'][0].update(name='HAS'),
            'domain order': lambda p: p['domains'].reverse(),
            'extra domain': lambda p: p['domains'].append(copy.deepcopy(p['domains'][0])),
            'missing domain': lambda p: p['domains'].pop(),
            'unknown secret': lambda p: p['domains'][0]['secrets'][0].update(name='other'),
            'secret case': lambda p: p['domains'][1]['secrets'][0].update(name='Conductor'),
            'missing secret': lambda p: p['domains'][0]['secrets'].pop(),
            'duplicate secret': lambda p: p['domains'][0]['secrets'].append(copy.deepcopy(p['domains'][0]['secrets'][0])),
            'secret order': lambda p: p['domains'][0]['secrets'].reverse(),
            'field case': lambda p: p['domains'][1]['secrets'][0]['values'].update(username='x'),
            'missing value': lambda p: p['domains'][0]['secrets'][0]['values'].pop('username'),
            'extra value': lambda p: p['domains'][0]['secrets'][0]['values'].update(extra='x'),
            'nonstring': lambda p: p['domains'][0]['secrets'][0]['values'].update(password=42),
            'extra envelope': lambda p: p.update(extra=True),
            'extra domain field': lambda p: p['domains'][0].update(extra=True),
            'extra secret field': lambda p: p['domains'][0]['secrets'][0].update(extra=True),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                plan = plan_fixture()
                mutate(plan)
                with self.assertRaises(preload.Blocked):
                    preload.validate_plan(plan)
        for value in (None, [], {}, {'domains': None}, {'domains': [None, None]}):
            with self.subTest(value=value), self.assertRaises(preload.Blocked):
                preload.validate_plan(value)

    def test_strict_json_rejects_duplicate_nested_keys_nonfinite_and_malformed_data(self):
        blobs = [b'{', b'\xff', b'{"x":1,"x":2}', b'{"x":{"y":1,"y":2}}',
                 b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{} trailing', None]
        for blob in blobs:
            with self.subTest(blob=blob), self.assertRaises(preload.Blocked) as error:
                preload.strict_json(blob)
            self.assertNotIn(PRIVATE, str(error.exception))


def acl_fixture():
    return {'data': {'root': False, 'exact_paths': {}, 'glob_paths': {
        'sms/': {'capabilities': ['create', 'read', 'update', 'delete', 'list']},
        'sys/mounts/sms': {'capabilities': ['create', 'update', 'delete']},
        'auth/token/': {'capabilities': ['read']},
    }}}


class CatalogTests(unittest.TestCase):
    def test_authoritative_zero_sms_mounts_is_positive(self):
        for mounts in ({}, {'secret/': {'type': 'kv'}, 'cubbyhole/': {'type': 'cubbyhole'}}):
            self.assertEqual({'sms_mounts_absent': True, 'acl_complete': True},
                             preload.audit_catalog(acl_fixture(), {'data': {'secret': mounts}}))

    def test_any_existing_sms_internal_or_orphan_mount_blocks(self):
        for path in ('sms/', 'sms/has/', 'sms/osdf/', 'sms/smsinternaldomain/',
                     'sms/orphan/', 'sms/unreviewed/nested/', 'sms-old/'):
            with self.subTest(path=path), self.assertRaises(preload.Blocked):
                preload.audit_catalog(acl_fixture(), {'data': {'secret': {path: {'type': 'kv'}}}})

    def test_missing_restricted_denied_root_and_extra_sms_acls_block(self):
        mutations = [
            lambda a: a['data'].pop('root'), lambda a: a['data'].update(root=True),
            lambda a: a['data'].pop('exact_paths'), lambda a: a['data'].pop('glob_paths'),
            lambda a: a['data']['glob_paths'].pop('sms/'),
            lambda a: a['data']['glob_paths'].pop('sys/mounts/sms'),
            lambda a: a['data']['glob_paths']['sms/'].update(capabilities=['read', 'list']),
            lambda a: a['data']['glob_paths']['sms/'].update(capabilities=['deny']),
            lambda a: a['data']['glob_paths']['sms/'].update(denied_parameters={'*': []}),
            lambda a: a['data']['glob_paths'].update({'sms/has/': {'capabilities': ['deny']}}),
            lambda a: a['data']['exact_paths'].update({'sms/has': {'capabilities': ['read']}}),
        ]
        for number, mutate in enumerate(mutations):
            with self.subTest(number=number):
                acl = acl_fixture()
                mutate(acl)
                with self.assertRaises(preload.Blocked):
                    preload.audit_catalog(acl, {'data': {'secret': {}}})

    def test_missing_204_style_and_malformed_catalogs_never_prove_absence(self):
        for catalog in ({}, {'data': {}}, {'data': {'secret': None}}, {'data': {'secret': []}},
                        {'data': {'secret': {'sms/has': {}}}}, {'data': {'secret': {'other/': None}}}):
            with self.subTest(catalog=catalog), self.assertRaises(preload.Blocked):
                preload.audit_catalog(acl_fixture(), catalog)


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_fixture()
        self.binding = {'allocation': 'synthetic-fresh-only', 'input_hmac': 'private-fixture'}
        self.journal = CASJournal(self.binding)
        self.sms = StatefulSMS()

    def execute(self):
        return preload.execute(self.plan, self.sms, self.journal, self.binding, 'pod-first')

    def assert_no_replay(self):
        before = list(self.sms.requests)
        for uid in ('pod-first', 'pod-second'):
            with self.assertRaises(preload.Blocked):
                preload.execute(self.plan, self.sms, self.journal, self.binding, uid)
        self.assertEqual(before, self.sms.requests)

    def test_independent_stateful_success_exactly_two_domains_twenty_records_22_posts(self):
        before = copy.deepcopy(self.plan)
        result = self.execute()
        self.assertEqual(before, self.plan)
        self.assertEqual('verified', result['state'])
        self.assertEqual(22, result['posts_observed'])
        self.assertEqual(UUIDS, result['domain_uuids'])
        self.assertEqual('pod-first', result['pod_uid'])
        self.assertEqual(22, len(self.sms.posts))
        self.assertEqual(2, sum(path == '/v1/sms/domain' for _, path in self.sms.posts))
        self.assertEqual(20, sum(len(records) for records in self.sms.domains.values()))
        for domain in self.plan['domains']:
            self.assertEqual({s['name']: s for s in domain['secrets']}, self.sms.domains[domain['name']])
        self.assertEqual(22, sum(s['state'] == 'intent' for s in self.journal.history))
        self.assertEqual(list(range(1, 23)), [s['posts_observed'] for s in self.journal.history if s['state'] == 'observed'])
        self.assertNotIn(PRIVATE, json.dumps(self.journal.history))
        self.assertNotIn(PRIVATE, json.dumps(self.sms.requests))
        reads_before = len(self.sms.requests)
        preload.verify_values(self.plan, self.sms)
        self.assertEqual(22, len(self.sms.requests) - reads_before)
        self.assertTrue(all(method == 'GET' for method, _ in self.sms.requests[reads_before:]))
        self.assert_no_replay()

    def test_wrong_status_redirect_throttle_and_server_error_stop_without_retry(self):
        for post_number in (1, 3, 22):
            for status in (200, 202, 204, 301, 302, 307, 308, 400, 401, 403, 404, 409, 429, 500, 503):
                with self.subTest(post_number=post_number, status=status):
                    self.setUp()
                    self.sms.fault = lambda m, p, response, sms: (status, response[1]) if m == 'POST' and len(sms.posts) == post_number else response
                    with self.assertRaises(preload.Blocked):
                        self.execute()
                    self.assertEqual(post_number, len(self.sms.posts))
                    self.assertEqual('uncertain', self.journal.record['state'])
                    self.assert_no_replay()

    def test_domain_response_malformed_duplicate_json_uuid_name_and_extra_fields(self):
        bodies = [b'{', b'{}', b'[]', b'null', b'{"name":"has","name":"has","uuid":"x"}',
                  encoded({'name': 'HAS', 'uuid': UUIDS['has']}), encoded({'name': 'has', 'uuid': 1}),
                  encoded({'name': 'has', 'uuid': 'not-a-uuid'}),
                  encoded({'name': 'has', 'uuid': UUIDS['has'], 'extra': PRIVATE})]
        for body in bodies:
            with self.subTest(body=body):
                self.setUp()
                self.sms.fault = lambda m, p, r, s: (201, body) if m == 'POST' else r
                with self.assertRaises(preload.Blocked) as error:
                    self.execute()
                self.assertNotIn(PRIVATE, str(error.exception))
                self.assertEqual(1, len(self.sms.posts))
                self.assert_no_replay()

    def test_duplicate_domain_uuid_stops_before_secrets(self):
        self.sms.fault = lambda m, p, r, s: (201, encoded({'name': 'osdf', 'uuid': UUIDS['has']})) if m == 'POST' and len(s.posts) == 2 else r
        with self.assertRaisesRegex(preload.Blocked, 'Duplicate domain'):
            self.execute()
        self.assertEqual(2, len(self.sms.posts))
        self.assert_no_replay()

    def test_secret_201_requires_empty_body(self):
        for body in (b'{}', b'\n', b'null', b'{"accepted":true}', encoded({'private': PRIVATE})):
            with self.subTest(body=body):
                self.setUp()
                self.sms.fault = lambda m, p, r, s: (201, body) if m == 'POST' and len(s.posts) == 3 else r
                with self.assertRaises(preload.Blocked):
                    self.execute()
                self.assertEqual(3, len(self.sms.posts))
                self.assert_no_replay()

    def test_connection_dropped_after_each_possible_commit_never_reposts(self):
        for number in range(1, 23):
            with self.subTest(number=number):
                self.setUp()
                def fault(method, path, response, sms):
                    if method == 'POST' and len(sms.posts) == number:
                        raise ConnectionError('synthetic response lost after commit')
                    return response
                self.sms.fault = fault
                with self.assertRaises(ConnectionError):
                    self.execute()
                self.assertEqual(number, len(self.sms.posts))
                self.assertEqual(number, len(self.sms.domains) + sum(map(len, self.sms.domains.values())))
                self.assertEqual('uncertain', self.journal.record['state'])
                self.assert_no_replay()

    def test_process_crash_after_each_commit_leaves_intent_and_refuses_second_pod(self):
        for number in range(1, 23):
            with self.subTest(number=number):
                self.setUp()
                def crash(method, path, response, sms):
                    if method == 'POST' and len(sms.posts) == number:
                        raise ProcessCrash()
                    return response
                self.sms.fault = crash
                with self.assertRaises(ProcessCrash):
                    self.execute()
                self.assertEqual('intent', self.journal.record['state'])
                self.assertEqual(number, len(self.sms.posts))
                self.assert_no_replay()

    def test_bad_private_readback_never_advances_to_next_secret(self):
        responses = [(status, b'{}') for status in (204, 301, 307, 401, 403, 404, 429, 500)]
        responses += [(200, body) for body in (b'{', b'{"name":"x","name":"x"}', b'null',
                     encoded({'name': 'aaf_api', 'values': {'password': PRIVATE + 'changed'}}))]
        for response in responses:
            with self.subTest(response=response):
                self.setUp()
                self.sms.fault = lambda m, p, r, s: response if m == 'GET' else r
                with self.assertRaises(preload.Blocked) as error:
                    self.execute()
                self.assertNotIn(PRIVATE, str(error.exception))
                self.assertEqual(3, len(self.sms.posts))
                self.assert_no_replay()

    def test_final_inventory_extra_missing_duplicate_or_wrong_case_is_not_acceptance(self):
        for mode in ('extra', 'missing', 'duplicate', 'case', 'wrong-envelope'):
            with self.subTest(mode=mode):
                self.setUp()
                def fault(method, path, response, sms):
                    if method == 'GET' and path.endswith('/secret'):
                        names = json.loads(response[1])['secretnames']
                        if mode == 'extra': names.append('orphan')
                        elif mode == 'missing': names.pop()
                        elif mode == 'duplicate': names.append(names[0])
                        elif mode == 'case': names[0] = names[0].upper()
                        else: return 200, encoded({'names': names})
                        return 200, encoded({'secretnames': names})
                    return response
                self.sms.fault = fault
                with self.assertRaises(preload.Blocked):
                    self.execute()
                self.assertEqual(22, len(self.sms.posts))
                self.assertEqual('uncertain', self.journal.record['state'])
                self.assert_no_replay()

    def test_prepared_binding_uid_and_nonprepared_states_block_before_any_post(self):
        for state in ('unarmed', 'claimed', 'intent', 'observed', 'uncertain', 'verified'):
            self.journal.record['state'] = state
            with self.subTest(state=state), self.assertRaises(preload.Blocked):
                self.execute()
        self.journal.record['state'] = 'prepared'
        self.journal.record['binding'] = {'changed': True}
        with self.assertRaises(preload.Blocked): self.execute()
        self.journal.record['binding'] = self.binding
        with self.assertRaises(preload.Blocked):
            preload.execute(self.plan, self.sms, self.journal, self.binding, '')
        self.assertEqual([], self.sms.requests)

    def test_concurrent_second_pod_wins_claim_and_stale_cas_adds_no_posts(self):
        def competing_claim(old, new):
            self.journal.before_cas = None
            preload.execute(self.plan, self.sms, self.journal, self.binding, 'pod-second')
        self.journal.before_cas = competing_claim
        with self.assertRaisesRegex(preload.Blocked, 'CAS conflict'):
            self.execute()
        self.assertEqual(22, len(self.sms.posts))
        self.assertEqual('pod-second', self.journal.record['pod_uid'])
        self.assertEqual('verified', self.journal.record['state'])
        self.assert_no_replay()

    def test_journal_cas_failure_at_intent_or_observation_never_adds_a_post(self):
        for target, operation, expected in (('intent', 'domain:has', 0), ('observed', None, 1),
                                            ('intent', 'has:aaf_api', 2), ('verified', None, 22)):
            with self.subTest(target=target, operation=operation):
                self.setUp()
                def conflict(old, new):
                    if new['state'] == target and (operation is None or new.get('operation') == operation):
                        self.journal.before_cas = None
                        self.journal.version += 1
                self.journal.before_cas = conflict
                with self.assertRaises(preload.Blocked):
                    self.execute()
                self.assertEqual(expected, len(self.sms.posts))
                self.assert_no_replay()

    def test_unacknowledged_journal_commit_stops_before_first_post(self):
        original = self.journal.cas
        def lost_ack(old, new):
            original(old, new)
            raise ConnectionError('synthetic journal response lost')
        self.journal.cas = lost_ack
        with self.assertRaises(ConnectionError):
            self.execute()
        self.assertEqual('claimed', self.journal.record['state'])
        self.assertEqual([], self.sms.requests)
        self.assert_no_replay()


class KubeJournalTests(unittest.TestCase):
    def setUp(self):
        self.journal = client.KubeJournal('journal-uid')
        self.object = {'metadata': {'uid': 'journal-uid', 'resourceVersion': '17'},
                       'data': {'journal.json': json.dumps({'state': 'prepared', 'binding': {'fixture': 1}})}}
        self.response = Mock(status=200)
        self.response.read.return_value = encoded(self.object)
        self.connection = Mock()
        self.connection.getresponse.return_value = self.response
        self.tls = Mock()
        self.connect = self.enterContext(patch.object(client.http.client, 'HTTPSConnection', return_value=self.connection))
        self.ca = self.enterContext(patch.object(client.ssl, 'create_default_context', return_value=self.tls))
        self.token = self.enterContext(patch.object(client.Path, 'read_text', return_value='  synthetic-token\n'))
        self.enterContext(patch.dict(client.os.environ, {'KUBERNETES_SERVICE_HOST': 'kube.invalid',
                              'KUBERNETES_SERVICE_PORT_HTTPS': '6443'}, clear=True))

    # Keep compatibility with the repository's Python 3.8 test runtime.
    def enterContext(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def test_request_uses_scoped_ca_tls12_bearer_header_and_exact_path(self):
        self.assertEqual(self.object, self.journal.request('GET'))
        self.ca.assert_called_once_with(cafile='/phase3-api/ca.crt')
        self.assertEqual(ssl.TLSVersion.TLSv1_2, self.tls.minimum_version)
        self.connect.assert_called_once_with('kube.invalid', 6443, context=self.tls, timeout=10)
        self.connection.request.assert_called_once_with('GET', '/api/v1/namespaces/onap/configmaps/phase3-sms-preload-journal',
            None, {'Authorization': 'Bearer synthetic-token', 'Content-Type': 'application/json'})
        self.response.read.assert_called_once_with(1024 * 1024 + 1)
        self.connection.close.assert_called_once_with()

    def test_default_api_port_and_read_resource_version(self):
        client.os.environ.pop('KUBERNETES_SERVICE_PORT_HTTPS')
        result = self.journal.read()
        self.assertEqual({'state': 'prepared', 'binding': {'fixture': 1}, '_resourceVersion': '17'}, result)
        self.assertEqual(443, self.connect.call_args.args[1])

    def test_cas_sends_old_uid_rv_and_strips_only_internal_fields(self):
        old = {'state': 'prepared', '_resourceVersion': '17'}
        new = {'state': 'claimed', 'pod_uid': 'pod-uid', '_resourceVersion': '18', '_private': 'local'}
        before = copy.deepcopy(new)
        self.journal.cas(old, new)
        method, path, blob, headers = self.connection.request.call_args.args
        self.assertEqual('PUT', method)
        obj = json.loads(blob)
        self.assertEqual({'name': preload.JOURNAL, 'namespace': 'onap', 'uid': 'journal-uid', 'resourceVersion': '17'}, obj['metadata'])
        self.assertEqual({'state': 'claimed', 'pod_uid': 'pod-uid'}, json.loads(obj['data']['journal.json']))
        self.assertEqual(before, new)
        self.connect.assert_called_once()

    def test_exact_200_required_no_redirect_retry_or_conflict_retry(self):
        for status in (201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 404, 409, 429, 500, 503):
            with self.subTest(status=status):
                self.connect.reset_mock()
                self.connection.reset_mock()
                self.response.status = status
                with self.assertRaises(preload.Blocked):
                    self.journal.cas({'_resourceVersion': '17'}, {'state': 'claimed'})
                self.connect.assert_called_once()
                self.connection.request.assert_called_once()
                self.connection.close.assert_called_once()

    def test_dropped_update_response_closes_without_retry(self):
        self.connection.getresponse.side_effect = ConnectionError('synthetic commit acknowledgement lost')
        with self.assertRaises(ConnectionError):
            self.journal.cas({'_resourceVersion': '17'}, {'state': 'claimed'})
        self.connect.assert_called_once()
        self.connection.request.assert_called_once()
        self.connection.close.assert_called_once()

    def test_uid_replacement_oversize_malformed_and_duplicate_json_block(self):
        blobs = [encoded(dict(self.object, metadata={'uid': 'replacement', 'resourceVersion': '17'})),
                 b' ' * (1024 * 1024 + 1), b'{',
                 b'{"metadata":{"uid":"journal-uid","uid":"replacement"}}']
        for blob in blobs:
            with self.subTest(size=len(blob)):
                self.connection.reset_mock()
                self.response.read.return_value = blob
                with self.assertRaises(preload.Blocked):
                    self.journal.read()
                self.connection.request.assert_called_once()
                self.connection.close.assert_called_once()

    def test_exact_one_megabyte_body_is_accepted(self):
        blob = encoded(self.object)
        self.response.read.return_value = blob + b' ' * (1024 * 1024 - len(blob))
        self.assertEqual('17', self.journal.read()['_resourceVersion'])

    def test_missing_api_host_or_token_never_sends_a_request(self):
        client.os.environ.pop('KUBERNETES_SERVICE_HOST')
        with self.assertRaises(KeyError): self.journal.read()
        self.connection.request.assert_not_called()
        client.os.environ['KUBERNETES_SERVICE_HOST'] = 'kube.invalid'
        self.token.side_effect = FileNotFoundError('synthetic projected token missing')
        with self.assertRaises(FileNotFoundError): self.journal.read()
        self.connection.request.assert_not_called()
        self.connection.close.assert_called_once()

    def test_read_rejects_duplicate_embedded_journal(self):
        self.object['data']['journal.json'] = '{"state":"prepared","state":"verified"}'
        self.response.read.return_value = encoded(self.object)
        with self.assertRaises(preload.Blocked): self.journal.read()


class TransportTests(unittest.TestCase):
    def test_transport_enforces_ca_hostname_size_bound_and_closes(self):
        context, connection = Mock(), Mock()
        response = Mock(status=201)
        response.read.return_value = b''
        connection.getresponse.return_value = response
        with patch.object(preload.ssl, 'create_default_context', return_value=context) as ca, \
                patch.object(preload.http.client, 'HTTPSConnection', return_value=connection) as connect, \
                patch.object(preload.socket, 'create_connection') as socket_connect:
            transport = preload.Transport('/synthetic/root.cer', '10.0.0.99')
            self.assertEqual((201, b''), transport.request('POST', '/v1/sms/domain', {'name': 'has'}))
            ca.assert_called_once_with(cafile='/synthetic/root.cer')
            self.assertEqual(ssl.TLSVersion.TLSv1_2, context.minimum_version)
            connect.assert_called_once_with('aaf-sms.onap', 10443, timeout=10, context=context)
            connection._create_connection(None)
            socket_connect.assert_called_once_with(('10.0.0.99', 10443), timeout=10)
            self.assertEqual({'name': 'has'}, json.loads(connection.request.call_args.args[2]))
            response.read.assert_called_once_with(1024 * 1024 + 1)
            connection.close.assert_called_once()
            response.read.return_value = b'x' * (1024 * 1024 + 1)
            with self.assertRaisesRegex(preload.Blocked, 'Oversized'):
                transport.request('GET', '/v1/sms/domain/has/secret')
            self.assertEqual(2, connection.close.call_count)


class ClientMainTests(unittest.TestCase):
    def test_client_reads_only_mounted_input_and_invokes_guarded_execute(self):
        config = {'contract': 1, 'plan': plan_fixture(), 'binding': {'fixture': 'bound'},
                  'journal_uid': 'journal-uid', 'sms_address': '10.0.0.99'}
        output = io.StringIO()
        with patch.object(client.Path, 'read_bytes', return_value=encoded(config)), \
                patch.object(client, 'KubeJournal') as journal, patch.object(client.preload, 'Transport') as transport, \
                patch.object(client.preload, 'execute') as execute, \
                patch.dict(client.os.environ, {'PHASE3_POD_UID': 'pod-uid'}), patch('sys.stdout', output):
            self.assertEqual(0, client.main())
        journal.assert_called_once_with('journal-uid')
        transport.assert_called_once_with(Path('/phase3-input/root.cer'), '10.0.0.99')
        execute.assert_called_once_with(config['plan'], transport.return_value, journal.return_value, config['binding'], 'pod-uid')
        self.assertNotIn(PRIVATE, output.getvalue())

    def test_missing_malformed_and_unreviewed_input_return_sanitized_failure(self):
        blobs = [b'{', b'{}', encoded({'contract': 2}), encoded({'contract': 1, 'plan': {}})]
        for blob in blobs:
            with self.subTest(blob=blob), patch.object(client.Path, 'read_bytes', return_value=blob), \
                    patch.object(client.preload, 'Transport') as transport, patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(2, client.main())
                transport.assert_not_called()
                self.assertNotIn(PRIVATE, output.getvalue())
        with patch.object(client.Path, 'read_bytes', side_effect=FileNotFoundError(PRIVATE)), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(2, client.main())
            self.assertNotIn(PRIVATE, output.getvalue())


if __name__ == '__main__':
    unittest.main()
