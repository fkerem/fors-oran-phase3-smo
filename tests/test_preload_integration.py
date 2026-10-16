"""Fresh preload integration with synthetic receipts and read-only API fixtures."""
import copy
from contextlib import contextmanager
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
import phase3_fresh as overlay_module
import phase3_sms as sms


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'bin'/filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fresh = module('preload_integration_fresh', 'phase3-fresh-start.py')
resume = module('preload_integration_resume', 'phase3-onap-resume-gate.py')
provenance = module('preload_integration_provenance', 'collect-phase3-provenance.py')
CLIENT = {'name': 'guarded-client', 'image': overlay_module.READINESS_IMAGE,
          'command': ['/phase3-sms-preload/client.py']}


class FixtureLoader:
    def __init__(self, value):
        self.value = value

    def create_module(self, spec):
        return self.value

    def exec_module(self, value):
        pass


@contextmanager
def gate_modules(values):
    original = importlib.util.spec_from_file_location

    def spec(name, path):
        value = values.get(Path(path).name)
        if value is not None:
            return importlib.machinery.ModuleSpec(name, FixtureLoader(value))
        return original(name, path)

    with patch.object(importlib.util, 'spec_from_file_location', side_effect=spec):
        yield


def job():
    return {'apiVersion': 'batch/v1', 'kind': 'Job',
            'metadata': {'name': sms.JOB, 'namespace': 'onap'},
            'spec': {'template': {'metadata': {'labels': sms.LABELS.copy()}, 'spec': {
                'initContainers': [{'name': 'ready', 'image': overlay_module.READINESS_IMAGE,
                                    'command': ['/app/ready.py', '--job-name', 'dependency']}],
                'containers': [{'name': 'stock', 'image': sms.IMAGE_TAG}]}}}}


def guarded(resource, context):
    result = copy.deepcopy(resource)
    result['spec'].update(suspend=True, backoffLimit=0)
    result['spec']['template']['spec'].update(containers=[copy.deepcopy(CLIENT)], restartPolicy='Never')
    return result


class PreloadIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve()
        self.pki = self.path/'pki'
        self.pki.mkdir()
        for name in ('root.cer', 'intermediate.cer', 'truststoreONAPall.jks', 'truststoreONAP.p12'):
            (self.pki/name).write_text('synthetic public trust')
        self.nodes = [{'metadata': {'name': 'node-'+str(i), 'uid': 'uid-'+str(i),
                                   'labels': {'kubernetes.io/hostname': 'node-'+str(i)}},
                       'spec': {}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
                      for i in range(3)]
        self.code = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': 'preload-code', 'namespace': 'onap'}, 'immutable': True, 'data': {'client.py': 'reviewed'}}
        self.rbac = [{'apiVersion': 'v1', 'kind': kind, 'metadata': {
            'name': 'preload-client', 'namespace': 'onap'}} for kind in ('ServiceAccount', 'Role', 'RoleBinding')]
        self.shared = SimpleNamespace(CONTRACT=1, helper_config=Mock(return_value=self.code),
            resources=Mock(return_value=self.rbac), patch_job=Mock(side_effect=guarded),
            is_client=Mock(side_effect=lambda c: c == CLIENT), require_qualification=Mock())
        self.context = {'schema': 1, 'baseline': 'fresh-isolated-lab-pki',
            'slice_urn': 'urn:publicid:IDN+emulab.net:fixture+slice+new',
            'node_uids': {n['metadata']['name']: n['metadata']['uid'] for n in self.nodes},
            'storage_node': fresh.select_storage_node(self.nodes), 'pki_directory': str(self.pki),
            'root_sha256': 'a'*64, 'secret_name': 'synthetic-pki', 'files_sha256': {},
            'sms_backend_contract': 1, 'sms_preload_contract': 1}
        self.receipt = {'root_sha256': 'a'*64, 'sms_backend_rehearsal': {},
                        'sms_preload_rehearsal': {'passed': True, 'fixture': True},'dmaap_rehearsal':{}}
        self.write_context()

    def write_context(self):
        receipt = json.dumps(self.receipt).encode()
        (self.path/'rehearsal.json').write_bytes(receipt)
        self.context['rehearsal_sha256'] = hashlib.sha256(receipt).hexdigest()
        (self.path/'context.json').write_text(json.dumps(self.context))

    def test_only_new_contract_patches_preload_and_preserves_exact_client_entrypoint(self):
        with patch.dict(sys.modules, phase3_preload=self.shared):
            changed = overlay_module.overlay([job()], self.context)[0]
            self.shared.patch_job.assert_called_once()
            pod = changed['spec']['template']['spec']
            self.assertEqual(CLIENT, pod['containers'][0])
            self.assertEqual('/phase3-helpers/phase3-readiness-wrapper.py', pod['initContainers'][0]['command'][0])
            self.assertTrue(changed['spec']['suspend'])
            self.assertEqual(0, changed['spec']['backoffLimit'])
            self.assertEqual('Never', pod['restartPolicy'])
            self.shared.patch_job.reset_mock()
            legacy = dict(self.context)
            legacy.pop('sms_preload_contract')
            held = overlay_module.overlay([job()], legacy)[0]
            self.shared.patch_job.assert_not_called()
            self.assertEqual('explicit-write-safety-review-required',
                held['metadata']['annotations']['phase3.onap.org/preload-gate'])

    def test_overlay_rejects_unknown_or_malformed_contract_before_reading_trust(self):
        for version in (2, 0, -1, None, '1', True, 1.0, [], {}):
            with self.subTest(version=version), patch.object(overlay_module, 'trust_config') as trust:
                context = dict(self.context, sms_preload_contract=version)
                with self.assertRaisesRegex(ValueError, 'Unreviewed SMS preload contract'):
                    overlay_module.overlay([job()], context)
                trust.assert_not_called()

    def test_verify_rejects_unknown_or_malformed_contract_before_external_checks(self):
        for version in (2, 0, -1, None, '1', True, 1.0, [], {}):
            self.context['sms_preload_contract'] = version
            self.write_context()
            with self.subTest(version=version), patch.object(fresh, 'run') as run, \
                    patch.object(fresh, 'cluster_nodes') as nodes, patch.object(fresh, 'kubectl') as kubectl:
                with self.assertRaisesRegex(ValueError, 'Unreviewed SMS preload contract'):
                    fresh.verify_context(self.path/'context.json')
                run.assert_not_called()
                nodes.assert_not_called()
                kubectl.assert_not_called()

    def test_readiness_exception_requires_exact_reviewed_client(self):
        altered = guarded(job(), self.context)
        altered['spec']['template']['spec']['containers'][0]['command'].append('unreviewed')
        self.shared.patch_job.side_effect = None
        self.shared.patch_job.return_value = altered
        with patch.dict(sys.modules, phase3_preload=self.shared), self.assertRaisesRegex(ValueError, 'entry point'):
            overlay_module.overlay([job()], self.context)

    def test_prepare_creates_code_and_scoped_resources_once_after_namespace(self):
        calls = []

        def kubectl(*args, data=None):
            calls.append((args, json.loads(data) if data else None))
            return b''

        with patch.dict(sys.modules, phase3_preload=self.shared), \
                patch.object(fresh, 'cluster_nodes', return_value=self.nodes), \
                patch.object(fresh, 'storage_inspection', return_value={'paths': []}), \
                patch.object(fresh, 'offline_rehearsal', return_value=self.receipt), \
                patch('phase3_dmaap.require_qualification'), \
                patch.object(fresh, 'assert_empty_onap'), patch.object(fresh, 'kubectl', side_effect=kubectl), \
                patch.object(fresh, 'secret', return_value={'kind': 'Secret'}), patch.object(fresh, 'private_write'):
            result = fresh.prepare(self.path, self.context['slice_urn'])
        self.assertEqual(1, result['sms_preload_contract'])
        namespace = next(i for i, (args, _) in enumerate(calls) if args == ('create', 'namespace', 'onap'))
        for expected in [self.code, *self.rbac]:
            indices = [i for i, (_, value) in enumerate(calls) if value == expected]
            self.assertEqual(1, len(indices))
            self.assertGreater(indices[0], namespace)
        self.shared.resources.assert_called_once()

    def test_real_shared_contract_survives_generic_readiness_rewriting(self):
        import phase3_preload
        coordinator = module('integration_real_preload_job', 'phase3-sms-preload.py')
        stock = job()
        stock['spec']['template']['spec']['containers'] = [{
            'name': 'aaf-sms-preload', 'image': sms.IMAGE_TAG, 'command': phase3_preload.STOCK_COMMAND.copy()}]
        original = copy.deepcopy(stock)
        result = overlay_module.overlay([stock], self.context)[0]
        self.assertEqual(original, stock)
        self.assertEqual(phase3_preload.patch_job(stock, self.context), result)
        self.assertEqual(result, coordinator.job_contract(result))
        pod = result['spec']['template']['spec']
        self.assertTrue(phase3_preload.is_client(pod['containers'][0]))
        self.assertEqual(phase3_preload.COMMAND, pod['containers'][0]['command'])
        self.assertTrue(result['spec']['suspend'])
        self.assertEqual('guarded-fresh-v1', result['metadata']['annotations']['phase3.onap.org/preload-gate'])
        self.assertEqual(['ServiceAccount', 'Role', 'RoleBinding'],
                         [r['kind'] for r in phase3_preload.resources(self.context)])
        self.assertNotIn('phase3-helpers', [v['name'] for v in pod['volumes']])
        self.assertTrue(phase3_preload.helper_config()['immutable'])
        result['spec']['suspend'] = False
        result['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}]}
        self.assertEqual(['Missing ONAP controller or Job inventory'], fresh.onap_errors([result], True))
        with self.assertRaisesRegex(ValueError, 'not acceptance'):
            fresh.onap_errors([result])
        result['spec']['template']['spec']['serviceAccountName'] = 'unreviewed'
        with self.assertRaisesRegex(ValueError, 'Pod template changed'):
            coordinator.job_contract(result)

    def test_real_shared_patch_refuses_drift_and_leaves_other_jobs_unpatched(self):
        import phase3_preload
        stock = job()
        stock['spec']['template']['spec']['containers'] = [{
            'name': 'aaf-sms-preload', 'image': sms.IMAGE_TAG, 'command': phase3_preload.STOCK_COMMAND.copy()}]
        for key, value in (('name', 'other'), ('image', 'unreviewed:latest'), ('command', ['/bin/sh'])):
            altered = copy.deepcopy(stock)
            altered['spec']['template']['spec']['containers'][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'stock preload entry point'):
                overlay_module.overlay([altered], self.context)
        altered = copy.deepcopy(stock)
        altered['metadata']['namespace'] = 'nonrtric'
        with self.assertRaisesRegex(ValueError, 'Job target'):
            overlay_module.overlay([altered], self.context)
        stock['metadata']['name'] = 'another-job'
        other = overlay_module.overlay([stock], self.context)[0]
        self.assertFalse(phase3_preload.is_client(other['spec']['template']['spec']['containers'][0]))
        self.assertNotIn('phase3.onap.org/preload-gate', other['metadata'].get('annotations', {}))

    def test_offline_rehearsal_calls_preload_check_and_records_qualification(self):
        destination = self.path/'offline'
        preload_rehearsal = SimpleNamespace(check=Mock(return_value={'qualified': True}))
        fixtures = {'phase3-readiness-wrapper.py': SimpleNamespace(patched_source=Mock())}
        fixtures['phase3-dmaap-rehearsal.py']=SimpleNamespace(check=Mock(return_value={'passed':True}))
        for filename in ('phase3-ves-rehearsal.py', 'phase3-sms-rehearsal.py', 'phase3-sms-backend-rehearsal.py'):
            fixtures[filename] = SimpleNamespace(check=Mock(return_value={'passed': True}))
        fixtures['phase3-sms-preload-rehearsal.py'] = preload_rehearsal

        def generate(path, experiment):
            path.mkdir()
            for name in ('server.p12', 'signer.p12', 'truststoreONAPall.jks'):
                (path/name).write_bytes(b'synthetic')
            return {'certificates': {'root': {'sha256': 'a'*64}}, 'pkcs12_packaging': {}, 'runtime': {}}

        def run(argv, **kwargs):
            output = destination/'offline-server-config'
            if output.exists():
                for name in ('local/org.osaaf.aaf.p12', 'local/org.osaaf.aaf.signer.p12', 'public/truststoreONAPall.jks'):
                    path = output/name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'synthetic')
            return b'source'

        digest = hashlib.sha256

        def sha256(blob):
            return SimpleNamespace(hexdigest=lambda: '5b6b326244d5d8a78fd3157c6c9838ba061f35629dcb291960f5f14446bffe1d') \
                if blob == b'source' else digest(blob)

        with gate_modules(fixtures), patch.object(fresh, 'generate', side_effect=generate), \
                patch.object(fresh, 'run', side_effect=run), patch.object(fresh, 'build_truststores'), \
                patch.object(fresh, 'docker_prefix', return_value=['fixture-docker']), \
                patch.object(fresh.hashlib, 'sha256', side_effect=sha256):
            result = fresh.offline_rehearsal(destination, 'synthetic')
        preload_rehearsal.check.assert_called_once_with(destination/'sms-preload-isolated', ['fixture-docker'])
        self.assertEqual({'qualified': True}, result['sms_preload_rehearsal'])
        self.assertEqual(result, json.loads((destination/'rehearsal.json').read_text()))

    def verify(self, actual_code=None):
        helper = {'metadata': {'name': 'existing-helper'}, 'immutable': True, 'data': {}}
        secret = {'data': {}}

        def kubectl(*args, data=None):
            if args[1] == 'secret':
                return json.dumps(dict(secret, immutable=True)).encode()
            return json.dumps((actual_code or self.code) if args[2] == 'preload-code' else helper).encode()

        with patch.dict(sys.modules, phase3_preload=self.shared), \
                patch.object(fresh, 'run', return_value=self.context['slice_urn'].encode()), \
                patch.object(fresh, 'cluster_nodes', return_value=self.nodes), \
                patch.object(fresh, 'helper_config', return_value=helper), \
                patch.object(fresh, 'secret', return_value=secret), \
                patch.object(fresh.phase3_sms_backend, 'require_qualification'), \
                patch.object(fresh.phase3_sms_backend, 'config', return_value=helper), \
                patch.object(fresh, 'kubectl', side_effect=kubectl):
            return fresh.verify_context(self.path/'context.json')

    def test_verify_requires_preload_qualification_and_immutable_code(self):
        self.verify()
        self.shared.require_qualification.assert_called_once_with(self.receipt['sms_preload_rehearsal'])
        with self.assertRaisesRegex(ValueError, 'preload helper'):
            self.verify(dict(self.code, data={'client.py': 'drifted'}))
        self.shared.require_qualification.side_effect = ValueError('qualification rejected')
        with self.assertRaisesRegex(ValueError, 'qualification rejected'):
            self.verify()

    def test_legacy_verification_does_not_adopt_preload_contract(self):
        self.context.pop('sms_preload_contract')
        self.receipt.pop('sms_preload_rehearsal')
        self.write_context()
        self.verify()
        self.shared.require_qualification.assert_not_called()
        self.shared.helper_config.assert_not_called()

    def test_complete_or_annotations_cannot_replace_current_verification(self):
        accepted = guarded(job(), self.context)
        accepted['spec']['suspend'] = False
        accepted['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}]}
        with patch.dict(sys.modules, phase3_preload=self.shared):
            with self.assertRaisesRegex(ValueError, 'not acceptance'):
                fresh.onap_errors([accepted])
            self.assertEqual(['Missing ONAP controller or Job inventory'], fresh.onap_errors([accepted], True))
            accepted['metadata']['annotations'] = {'phase3.onap.org/preload-gate': 'explicit-write-safety-review-required'}
            with self.assertRaisesRegex(ValueError, 'not acceptance'):
                fresh.onap_errors([accepted], True)
            accepted['metadata'].pop('annotations')
            accepted['spec']['template']['spec']['containers'][0]['command'].append('drift')
            with self.assertRaisesRegex(ValueError, 'exact reviewed'):
                fresh.onap_errors([accepted], True)

    def test_wait_onap_checks_current_preload_before_polling_and_after_wait(self):
        for answers in ([ValueError('stale preload')], [{'accepted': True}, ValueError('stale preload')]):
            backend_gate = SimpleNamespace(verify_acceptance=Mock(return_value={}))
            preload_gate = SimpleNamespace(verify_acceptance=Mock(side_effect=answers))
            with gate_modules({'phase3-sms-backend.py': backend_gate, 'phase3-sms-preload.py': preload_gate,
                               'phase3-dmaap-recovery.py':SimpleNamespace(verify_acceptance=Mock(return_value=None))}), \
                    patch.object(fresh, 'verify_context', return_value=self.context), \
                    patch.object(fresh, 'kubectl', return_value=b'{"items":[]}') as read, \
                    patch.object(fresh, 'onap_errors', return_value=['pending']) as errors, \
                    patch.object(fresh.time, 'sleep'), self.assertRaisesRegex(ValueError, 'stale preload'):
                fresh.wait_onap(self.path/'context.json', 600)
            if len(answers) == 1:
                read.assert_not_called()
            else:
                errors.assert_called_once_with([], preload_verified=True,dmaap_verified=False)

    def test_resume_requires_current_preload_before_onap_completion(self):
        preload_gate = SimpleNamespace(verify_acceptance=Mock(side_effect=ValueError('stale preload')))
        sample = {'pod': 'operator'}

        def run(args):
            if 'helm' in args:
                return '[]'
            return '{"items":[]}'

        with gate_modules({'phase3-sms-preload.py': preload_gate}), \
                patch.object(resume, 'acceptance_record', return_value=({}, {
                    'observations': [sample], 'stability_seconds': 3600})), \
                patch.object(resume.compat, 'operator_sample', return_value=sample), \
                patch.object(resume.compat, 'runtime_sample'), patch.object(resume.compat, 'kafka_sample'), \
                patch.object(resume, 'run', side_effect=run), patch.object(resume, 'onap_ready') as ready, \
                self.assertRaisesRegex(ValueError, 'stale preload'):
            resume.check(context_path=self.path/'context.json')
        ready.assert_not_called()

    def test_provenance_records_failure_when_current_preload_verification_fails(self):
        preload_gate = SimpleNamespace(verify_acceptance=Mock(side_effect=ValueError('stale preload')))

        def command(args):
            if args[0] == 'helm' and args[1] == 'list':
                return '[]'
            if 'get' in args:
                return '{"items":[]}'
            if args[:2] == ['kubectl', 'version']:
                return '{}'
            return 'fixture'

        for version in (1, 2):
            self.context['sms_preload_contract'] = version
            self.write_context()
            preload_gate.verify_acceptance.reset_mock()
            with self.subTest(version=version), gate_modules({'phase3-sms-preload.py': preload_gate}), \
                    patch.object(provenance, 'command', side_effect=command):
                result = provenance.collect(self.path/'context.json')
            self.assertEqual({'verified': False}, result['sms_preload_current'])
            self.assertIn('SMS preload current verification is not established', result['readiness_errors'])
            preload_gate.verify_acceptance.assert_called_once_with(self.path/'context.json')

    def test_status_requires_current_verification_even_without_preload_receipt(self):
        source = (ROOT/'bin/phase3-status.sh').read_text().split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]
        source = source.replace("Path('/local/setup/phase3-smo/fresh-start')", 'Path('+repr(str(self.path))+')')
        preload_gate = SimpleNamespace(verify_acceptance=Mock(side_effect=ValueError('stale preload')))
        with gate_modules({'phase3-sms-preload.py': preload_gate}), \
                patch.object(sys, 'argv', ['status', str(ROOT)]), patch('builtins.print'), \
                self.assertRaisesRegex(SystemExit, 'SMS preload current verification: NOT ESTABLISHED'):
            exec(compile(source, 'status-inline', 'exec'), {})
        preload_gate.verify_acceptance.assert_called_once_with(self.path/'context.json')

    def test_status_rejects_unknown_version_with_real_coordinator(self):
        coordinator = module('integration_real_preload_version', 'phase3-sms-preload.py')
        self.context['sms_preload_contract'] = 2
        self.write_context()
        source = (ROOT/'bin/phase3-status.sh').read_text().split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]
        source = source.replace("Path('/local/setup/phase3-smo/fresh-start')", 'Path('+repr(str(self.path))+')')
        with gate_modules({'phase3-sms-preload.py': coordinator}), \
                patch.object(sys, 'argv', ['status', str(ROOT)]), patch('builtins.print'), \
                patch.object(coordinator, 'postconditions') as current, \
                self.assertRaisesRegex(SystemExit, 'SMS preload current verification: NOT ESTABLISHED'):
            exec(compile(source, 'status-inline', 'exec'), {})
        current.assert_not_called()

    def test_status_preserves_retained_context_hold(self):
        self.context.pop('sms_preload_contract')
        self.write_context()
        source = (ROOT/'bin/phase3-status.sh').read_text().split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]
        source = source.replace("Path('/local/setup/phase3-smo/fresh-start')", 'Path('+repr(str(self.path))+')')
        preload_gate = SimpleNamespace(verify_acceptance=Mock())
        with gate_modules({'phase3-sms-preload.py': preload_gate}), \
                patch.object(sys, 'argv', ['status', str(ROOT)]), patch('builtins.print') as output:
            exec(compile(source, 'status-inline', 'exec'), {})
        preload_gate.verify_acceptance.assert_not_called()
        self.assertTrue(any('retained safety hold' in str(call) for call in output.call_args_list))

    def test_setup_orders_preload_after_backend_with_inherited_driver_lock(self):
        source = (ROOT/'setup-oran-smo.sh').read_text()
        backend = next(line for line in source.splitlines() if 'phase3-sms-backend.py' in line)
        preload = next(line for line in source.splitlines() if 'phase3-sms-preload.py' in line)
        self.assertIn(backend+'\n'+preload, source)
        self.assertIn('PHASE3_RECOVERY_LOCK_FD=9', preload)
        self.assertIn('run-fresh --context "$PHASE3_FRESH_CONTEXT" --timeout 600', preload)
        self.assertLess(source.index(preload), source.index('wait-onap'))
        self.assertLess(source.index(preload), source.index('touch "$OURDIR/setup-oran-smo-done"'))
        subprocess.run(['bash', '-n', str(ROOT/'setup-oran-smo.sh')], check=True)
        subprocess.run(['bash', '-n', str(ROOT/'bin/phase3-status.sh')], check=True)


if __name__ == '__main__':
    unittest.main()
