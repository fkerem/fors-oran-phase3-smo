"""Local synthetic controls; these tests never claim exact-image qualification."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
sys.path.insert(0, str(ROOT/'tools'))
import phase3_preload as preload
import Phase3PreloadFixture as fixture

spec = importlib.util.spec_from_file_location('preload_rehearsal_tests', ROOT/'bin/phase3-sms-preload-rehearsal.py')
rehearsal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rehearsal)


def tls_material(directory):
    """Build ephemeral certs using local OpenSSL, including a truly expired leaf."""
    directory.mkdir(mode=0o700)
    executable = shutil.which('openssl')
    if not executable:
        raise unittest.SkipTest('OpenSSL is required for synthetic TLS tests')

    def openssl(*args):
        result = subprocess.run([executable, *map(str, args)], capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Synthetic certificate generation failed: ' + result.stderr.decode())

    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
            '-subj', '/CN=isolated-test-root', '-keyout', directory/'ca.key', '-out', directory/'root.cer')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
            '-keyout', directory/'server.key', '-out', directory/'leaf.csr')
    (directory/'good.ext').write_text('subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n')
    (directory/'bad.ext').write_text('subjectAltName=DNS:wrong.invalid\nbasicConstraints=CA:FALSE\n')

    def sign(output, extensions, ca='root.cer', key='ca.key'):
        openssl('x509', '-req', '-in', directory/'leaf.csr', '-CA', directory/ca,
                '-CAkey', directory/key, '-set_serial', '10', '-days', '1',
                '-extfile', directory/extensions, '-out', output)

    sign(directory/'server.cer', 'good.ext')
    (directory/'tls').mkdir(mode=0o700)
    for mode in rehearsal.TLS_CASES:
        target = directory/'tls'/mode
        target.mkdir(mode=0o700)
        shutil.copyfile(directory/'server.key', target/'server.key')
        if mode == 'wrong-ca':
            openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                    '-subj', '/CN=untrusted-test-root', '-keyout', directory/'wrong.key', '-out', directory/'wrong.cer')
            sign(target/'server.cer', 'good.ext', 'wrong.cer', 'wrong.key')
        elif mode == 'wrong-hostname':
            sign(target/'server.cer', 'bad.ext')
        elif mode == 'expired-server':
            (directory/'index').touch()
            (directory/'serial').write_text('10\n')
            config = ('[ca]\ndefault_ca=fixture\n[fixture]\n'
                      'database={0}/index\nserial={0}/serial\nnew_certs_dir={0}\n'
                      'private_key={0}/ca.key\ncertificate={0}/root.cer\n'
                      'default_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n').format(directory)
            (directory/'ca.conf').write_text(config)
            openssl('ca', '-batch', '-notext', '-config', directory/'ca.conf',
                    '-in', directory/'leaf.csr', '-startdate', '20000101000000Z',
                    '-enddate', '20010101000000Z', '-extfile', directory/'good.ext', '-out', target/'server.cer')
        else:
            shutil.copyfile(directory/'server.cer', target/'server.cer')


class IndependentFixtureTests(unittest.TestCase):
    def test_real_success_shapes_and_stateful_readback(self):
        state = fixture.State()
        status, blob = state.request('POST', '/v1/sms/domain', {'name': 'fixture'})
        self.assertEqual(201, status)
        self.assertEqual({'name', 'uuid'}, set(json.loads(blob)))
        secret = {'name': 'record', 'values': {'password': 'synthetic-"\\\n\u03bb'}}
        self.assertEqual((201, b''), state.request('POST', '/v1/sms/domain/fixture/secret', secret))
        secret['values']['password'] = 'changed-outside-server'
        self.assertEqual({'secretnames': ['record']}, json.loads(state.request('GET', '/v1/sms/domain/fixture/secret')[1]))
        returned = json.loads(state.request('GET', '/v1/sms/domain/fixture/secret/record')[1])
        self.assertEqual('synthetic-"\\\n\u03bb', returned['values']['password'])
        self.assertEqual({'domain_posts': 1, 'secret_posts': 1}, state.counts())
        self.assertNotIn('synthetic-', json.dumps(state.requests))

    def test_conflict_does_not_overwrite_existing_values(self):
        state = fixture.State()
        state.request('POST', '/v1/sms/domain', {'name': 'fixture'})
        secret = {'name': 'record', 'values': {'k': 'first'}}
        state.request('POST', '/v1/sms/domain/fixture/secret', secret)
        self.assertEqual(409, state.request('POST', '/v1/sms/domain', {'name': 'fixture'})[0])
        secret['values']['k'] = 'second'
        self.assertEqual(409, state.request('POST', '/v1/sms/domain/fixture/secret', secret)[0])
        self.assertEqual('first', state.domains['fixture']['record']['k'])

    def test_uncertain_write_changes_server_state_before_connection_loss(self):
        state = fixture.State('ambiguous-domain')
        with self.assertRaises(ConnectionError):
            state.request('POST', '/v1/sms/domain', {'name': 'fixture'})
        self.assertIn('fixture', state.domains)
        self.assertEqual({'domain_posts': 1, 'secret_posts': 0}, state.counts())

    def test_journal_cas_checks_resource_version_and_returns_private_copy(self):
        journal = fixture.Journal({'fixture': 'synthetic'})
        first = journal.read()
        first['binding']['fixture'] = 'changed'
        self.assertEqual('synthetic', journal.read()['binding']['fixture'])
        first = journal.read()
        journal.cas(first, dict(first, state='claimed'))
        with self.assertRaisesRegex(ValueError, 'CAS conflict'):
            journal.cas(first, dict(first, state='verified'))
        current = journal.read()
        journal.cas(current, dict(current, state='prepared'))
        # Even an ABA return to prepared cannot reuse the original RV.
        with self.assertRaises(ValueError):
            journal.cas(first, dict(first, state='claimed'))

    def test_shared_client_full_inventory_and_no_replay(self):
        plan = rehearsal.synthetic_plan(preload)
        state = fixture.State()
        binding = {'fixture': 'synthetic'}
        journal = fixture.Journal(binding)
        verified = preload.execute(plan, state, journal, binding, 'fixture-pod')
        self.assertEqual('verified', verified['state'])
        self.assertEqual({'domain_posts': 2, 'secret_posts': 20}, state.counts())
        preload.verify_values(plan, state)
        before = list(state.requests)
        with self.assertRaises(ValueError):
            preload.execute(plan, state, journal, binding, 'fixture-pod')
        self.assertEqual(before, state.requests)

    def test_backend_callback_follows_scoped_probe_and_precedes_restart(self):
        tree = ast.parse((ROOT/'bin/phase3-sms-backend-rehearsal.py').read_text())
        check = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'check')
        self.assertEqual(['directory', 'docker', 'callback'], [a.arg for a in check.args.args])
        self.assertIsNone(check.args.defaults[0].value)
        source = ast.get_source_segment((ROOT/'bin/phase3-sms-backend-rehearsal.py').read_text(), check)
        probe = source.index("if probe('seal')")
        callback = source.index('callback(case, dict(names), command)')
        restart = source.index("for role in ('sms','quorum-0','quorum-1','quorum-2','vault')")
        self.assertLess(probe, callback)
        self.assertLess(callback, restart)

    def test_real_worker_refuses_wrong_python_before_contact(self):
        with patch.object(rehearsal.sys, 'version_info', (3, 9)), patch.object(fixture, 'Transport') as transport:
            with self.assertRaisesRegex(ValueError, 'Python 3.8'):
                rehearsal.run_real('/nonexistent-synthetic-fixture')
            transport.assert_not_called()

    def test_incomplete_observations_cannot_become_qualified(self):
        for record in ({}, {'real': {}, 'faults': {}}, {'real': {'passed': True}, 'faults': {}}):
            with self.assertRaises(ValueError):
                rehearsal.validate_observations(record)

    def test_receipt_hashes_bind_captured_bytes_and_checkout_drift_blocks(self):
        with tempfile.TemporaryDirectory(prefix='phase3-preload-source-test-') as directory:
            root = Path(directory)
            paths = {name: root/name for name in ('phase3_preload.py', 'phase3-sms-preload-client.py')}
            for name, path in paths.items():
                path.write_bytes(('captured ' + name).encode())
            with patch.object(rehearsal, 'source_paths', return_value=paths):
                snapshot = rehearsal.capture_sources()
                tested = rehearsal.hashes(snapshot)
                rehearsal.require_unchanged_sources(snapshot)
                paths['phase3_preload.py'].write_bytes(b'new unexercised checkout')
                self.assertEqual(tested, rehearsal.hashes(snapshot))
                with self.assertRaisesRegex(ValueError, 'changed during qualification'):
                    rehearsal.require_unchanged_sources(snapshot)
                paths['phase3_preload.py'].write_bytes(snapshot['phase3_preload.py'])
                rehearsal.require_unchanged_sources(snapshot)

    def test_staged_source_tampering_blocks_receipt(self):
        with tempfile.TemporaryDirectory(prefix='phase3-preload-stage-test-') as directory:
            root = Path(directory)
            (root/'client.py').write_bytes(b'tested source')
            expected = rehearsal.hashes({'client.py': b'tested source'})
            rehearsal.require_staged_sources(root, expected)
            (root/'client.py').write_bytes(b'changed source')
            with self.assertRaisesRegex(ValueError, 'Staged preload source changed'):
                rehearsal.require_staged_sources(root, expected)


class HttpsFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='phase3-preload-local-tests-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)/'fixture'
        tls_material(cls.directory)

    def test_shared_transport_and_writer_against_independent_faults_and_tls(self):
        result = rehearsal.run_faults(self.directory)
        self.assertEqual({'success', *rehearsal.FAULTS, *rehearsal.TLS_CASES}, set(result))
        self.assertEqual(20, result['success']['secret_posts'])
        for mode in rehearsal.TLS_CASES:
            self.assertEqual(0, result[mode]['application_requests'])
        # The returned observations contain counters only, never fixture values.
        for forbidden in ('fixture-only', 'password', 'UserName', 'client_token', 'role_id'):
            self.assertNotIn(forbidden, json.dumps(result))

    def test_private_recording_wraps_actual_shared_transport(self):
        state = fixture.State()
        output = Path(self.temp.name)/'private-readback.jsonl'
        with fixture.Server(state, self.directory/'server.cer', self.directory/'server.key') as port:
            transport = fixture.Transport(port, self.directory/'root.cer', output,
                client=preload.Transport(self.directory/'root.cer', '127.0.0.1', hostname='localhost', port=port))
            binding = {'fixture': 'synthetic'}
            preload.execute(preload.synthetic_inputs(), transport, fixture.Journal(binding), binding, 'fixture-pod')
        private = [json.loads(line) for line in output.read_text().splitlines()]
        self.assertGreaterEqual(len(private), 20)
        self.assertTrue(any('fixture-only' in entry['body'] for entry in private))
        self.assertEqual(0o600, output.stat().st_mode & 0o777)
        self.assertFalse(any('fixture-only' in str(entry) for entry in transport.observations))

    def test_actual_client_journal_adapter_over_real_https(self):
        shutil.copyfile(ROOT/'bin/phase3-sms-preload-client.py', self.directory/'phase3-sms-preload-client.py')
        result = rehearsal.run_journal(self.directory)
        self.assertTrue(result['adapter_compiled'])
        self.assertTrue(result['real_https'])
        self.assertEqual(set(rehearsal.JOURNAL_CASES), set(result['cases']))
        for mode in rehearsal.JOURNAL_CASES:
            with self.subTest(mode=mode):
                self.assertTrue(result['cases'][mode]['passed'])
        self.assertEqual(1, result['cases']['stale-rv']['put_requests'])
        self.assertEqual(1, result['cases']['ambiguous-commit']['put_requests'])
        self.assertEqual(0, result['cases']['replaced-read-uid']['put_requests'])
        self.assertNotIn('isolated-fixture-token', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
