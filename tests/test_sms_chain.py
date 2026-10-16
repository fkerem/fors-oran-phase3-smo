import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
import phase3_sms as sms
from phase3_fresh import overlay
from phase3_lab_pki import CONFIG_IMAGE


def deployment():
    return {'kind': 'Deployment', 'metadata': {'name': sms.NAME, 'namespace': 'onap'}, 'spec': {
        'selector': {'matchLabels': {'app': 'aaf-sms'}}, 'replicas': 1,
        'template': {'metadata': {'labels': sms.LABELS.copy()}, 'spec': {
            'initContainers': [{'name': sms.INIT, 'image': 'docker.io/busybox:1.34.1',
                'command': ['/bin/sh'], 'args': sms.STOCK_ARGS.copy(), 'volumeMounts': [
                    {'mountPath': '/opt/app/osaaf', 'name': sms.NAME+'-aaf-config'},
                    {'mountPath': '/int-certs', 'name': sms.NAME+'-int-certs', 'readOnly': True}]}],
            'containers': [{'name': 'aaf-sms', 'image': sms.IMAGE_TAG, 'command': ['/sms/bin/sms']}],
            'volumes': [{'name': sms.NAME+'-aaf-config', 'emptyDir': {'medium': 'Memory'}},
                {'name': sms.NAME+'-int-certs', 'secret': {'secretName': sms.NAME+'-int-certs'}}]}}}}


class SmsContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        for n in ('root.cer', 'intermediate.cer', 'truststoreONAPall.jks', 'truststoreONAP.p12'):
            (self.path/n).write_text('public fixture')
        self.context = {'schema': 1, 'baseline': 'fresh-isolated-lab-pki',
                        'pki_directory': str(self.path), 'root_sha256': 'a'*64}

    def test_only_public_trust_is_packaged_and_content_addressed(self):
        cm = sms.config(self.context)
        self.assertTrue(cm['immutable'])
        self.assertEqual({'root.cer', 'intermediate.cer', 'phase3-sms-chain.sh'}, set(cm['data']))
        (self.path/'intermediate.cer').write_text('different public fixture')
        self.assertNotEqual(cm['metadata']['name'], sms.config(self.context)['metadata']['name'])

    def test_patch_preserves_issuer_storage_and_immutable_selector(self):
        original = deployment(); result = sms.patch_deployment(original, self.context)
        self.assertEqual(original['spec']['selector'], result['spec']['selector'])
        self.assertEqual('server', result['spec']['template']['metadata']['labels'][sms.ROLE])
        init = result['spec']['template']['spec']['initContainers'][0]
        self.assertTrue(sms.crypto_initializer(init)); self.assertEqual(CONFIG_IMAGE, init['image'])
        self.assertNotIn('/int-certs', [m['mountPath'] for m in init['volumeMounts']])
        self.assertNotIn(sms.ROLE, original['spec']['template']['metadata']['labels'])
        self.assertEqual(sms.config(self.context), sms.verify(result, self.context))

    def test_changed_image_command_mount_selector_and_volume_refuse(self):
        changes = [
            lambda r: r['spec']['template']['spec']['containers'][0].update(image='mutable:latest'),
            lambda r: r['spec']['selector']['matchLabels'].update(release='onap'),
            lambda r: r['spec']['template']['spec']['initContainers'][0].update(args=['changed']),
            lambda r: r['spec']['template']['spec']['initContainers'][0]['volumeMounts'].append({'name': 'signer', 'mountPath': '/keys'}),
            lambda r: r['spec']['template']['spec']['volumes'][0].update(emptyDir={}),
        ]
        for change in changes:
            r = deployment(); change(r)
            with self.assertRaises(ValueError): sms.patch_deployment(r, self.context)

    def test_service_cannot_select_preload_and_its_other_fields_remain_unchanged(self):
        service = {'kind': 'Service', 'metadata': {'name': sms.SERVICE},
            'spec': {'clusterIP': '10.0.0.1', 'selector': sms.LABELS.copy(),
                     'ports': [{'name': 'https', 'port': 10443, 'targetPort': 10443}]}}
        result = sms.patch_service(service)
        self.assertEqual(dict(sms.LABELS, **{sms.ROLE: 'server'}), result['spec']['selector'])
        changed = copy.deepcopy(result); changed['spec']['selector'].pop(sms.ROLE)
        self.assertEqual(service, changed)
        service['spec']['ports'][0]['targetPort'] = 80
        with self.assertRaises(ValueError): sms.patch_service(service)

    def test_fresh_preload_is_held_not_replayed_or_claimed_verified(self):
        job = {'kind': 'Job', 'metadata': {'name': sms.JOB}, 'spec': {'template': {
            'metadata': {'labels': sms.LABELS.copy()}, 'spec': {'containers': []}}}}
        result = overlay([job], self.context)[0]
        self.assertTrue(result['spec']['suspend'])
        self.assertEqual(0, result['spec']['backoffLimit'])
        self.assertEqual('Never', result['spec']['template']['spec']['restartPolicy'])
        self.assertEqual('preload', result['spec']['template']['metadata']['labels'][sms.ROLE])
        spec = importlib.util.spec_from_file_location('fresh_sms', ROOT/'bin/phase3-fresh-start.py')
        fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
        with self.assertRaisesRegex(ValueError, 'safely held'): fresh.onap_errors([result])
        result['spec']['suspend'] = False
        result['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}]}
        with self.assertRaisesRegex(ValueError, 'not acceptance'): fresh.onap_errors([result])

    def test_fresh_overlay_distinguishes_crypto_helper_from_aaf_bootstrap(self):
        result = overlay([deployment()], self.context)[0]
        init = result['spec']['template']['spec']['initContainers'][0]
        self.assertTrue(sms.crypto_initializer(init))
        self.assertNotIn('phase3-pki', json.dumps(init))
        self.assertNotIn('agent.sh', json.dumps(init))


repair_spec = importlib.util.spec_from_file_location('sms_repair_tests', ROOT/'bin/phase3-sms-repair.py')
repair = importlib.util.module_from_spec(repair_spec); repair_spec.loader.exec_module(repair)


class SmsRepairGuardTests(unittest.TestCase):
    def job(self):
        return {'metadata': {'uid': 'held-uid'}, 'spec': {'suspend': True}, 'status': {}}

    def test_only_suspended_noncompleted_podless_job_is_eligible_for_server_repair(self):
        job = self.job()
        with patch.object(repair, 'get', side_effect=lambda k: job if k.startswith('job/') else {'items': []}):
            self.assertEqual(job, repair.held_job())
            for state in ({'suspend': False}, {'suspend': True}):
                job['spec'] = state
                job['status'] = {} if state['suspend'] is False else {'succeeded': 1}
                with self.assertRaises(ValueError): repair.held_job()

    def test_owned_pod_or_active_execution_refuses_even_if_suspend_true(self):
        job = self.job(); pod = {'metadata': {'ownerReferences': [{'uid': 'held-uid'}]}}
        with patch.object(repair, 'get', side_effect=lambda k: job if k.startswith('job/') else {'items': [pod]}):
            with self.assertRaises(ValueError): repair.held_job()
            job['status']['active'] = 1
            with self.assertRaises(ValueError): repair.held_job()

    def test_metadata_audit_does_not_infer_absence_from_empty_or_backend_error(self):
        class Response:
            def __init__(self, status): self.status = status
            def read(self, limit): return b'{"secretnames":[]}'
        class Connection:
            def __init__(self, status): self.status = status
            def request(self, *args):
                if args[0] != 'GET': raise AssertionError('write request in read-only audit')
            def getresponse(self): return Response(self.status)
            def close(self): pass
        for status in (200, 500, 404):
            with patch.object(repair, 'expected_domains', return_value=['fixture']), patch.object(repair.ssl, 'create_default_context'), patch.object(repair.http.client, 'HTTPSConnection', return_value=Connection(status)):
                result = repair.partial_audit({'pki_directory': '/fixture'}, {'spec': {'clusterIP': '10.0.0.1'}})
                self.assertFalse(result['no_partial_effects_proved'])
                self.assertFalse(result['preload_replay_authorized'])
                self.assertFalse(result['observations'][0]['absence_proved'])

    def test_existing_executed_main_refusal_is_not_relaxed(self):
        source = (ROOT/'bin/phase3-onap-recovery.py').read_text()
        self.assertIn('Main execution observed or history missing; replay refused', source)
        source = (ROOT/'bin/phase3-sms-repair.py').read_text()
        self.assertNotIn("'delete'", source)
        self.assertNotIn("'suspend', 'value': False", source)
        self.assertNotIn('insecure', source.lower())


if __name__ == '__main__': unittest.main()
