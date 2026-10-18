"""Synthetic readiness and no-replay recovery controls; no cluster writes."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
import phase3_stateful_readiness as stateful
import phase3_checkout as checkout
spec = importlib.util.spec_from_file_location('final_readiness_tests', ROOT/'bin/phase3-final-readiness.py')
final = importlib.util.module_from_spec(spec); spec.loader.exec_module(final)


def fixture(strategy='OnDelete'):
    labels = {'strimzi.io/cluster': 'cluster', 'strimzi.io/kind': 'Kafka', 'strimzi.io/name': 'cluster-kafka'}
    item = {'kind': 'StatefulSet', 'metadata': {'name': 'cluster-kafka', 'namespace': 'onap', 'uid': 'sts',
        'generation': 1, 'labels': labels, 'ownerReferences': [{'kind': 'Kafka', 'name': 'cluster', 'uid': 'kafka',
        'apiVersion': 'kafka.strimzi.io/v1beta2', 'controller': False}]},
        'spec': {'replicas': 2, 'selector': {'matchLabels': labels}, 'updateStrategy': {'type': strategy}},
        'status': {'readyReplicas': 2, 'replicas': 2, 'currentReplicas': 2, 'updatedReplicas': 2,
                   'observedGeneration': 1, 'currentRevision': 'rev', 'updateRevision': 'rev'}}
    pods = [{'kind': 'Pod', 'metadata': {'name': 'cluster-kafka-'+str(n), 'namespace': 'onap', 'uid': 'pod'+str(n),
             'labels': dict(labels, **{'controller-revision-hash': 'rev'}),
             'ownerReferences': [{'kind': 'StatefulSet', 'uid': 'sts', 'controller': True}]},
             'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}]}} for n in range(2)]
    kafka = {'metadata': {'name': 'cluster', 'namespace': 'onap', 'uid': 'kafka', 'generation': 1},
             'status': {'observedGeneration': 1, 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
    return item, pods, [kafka]


class StatefulTests(unittest.TestCase):
    def test_strimzi_noncontroller_kafka_owner_is_valid(self):
        item, pods, kafkas = fixture()
        self.assertEqual([], stateful.errors([item], pods, kafkas))

    def test_stale_or_unready_replicas_and_revisions_fail(self):
        for field, value in [('readyReplicas', 1), ('replicas', 3), ('currentReplicas', 1),
                             ('updatedReplicas', 1), ('observedGeneration', 0), ('currentRevision', 'old'),
                             ('updateRevision', '')]:
            item, pods, kafkas = fixture();item['status'][field] = value
            self.assertTrue(stateful.errors([item], pods, kafkas), field)

    def test_pod_membership_ownership_readiness_and_revision_fail_closed(self):
        for mutate in [lambda p:p.pop(), lambda p:p.append(copy.deepcopy(p[0])),
                       lambda p:p[0]['metadata'].update(deletionTimestamp='now'),
                       lambda p:p[0]['metadata']['labels'].update({'controller-revision-hash': 'old'}),
                       lambda p:p[0]['metadata']['ownerReferences'][0].update(uid='other'),
                       lambda p:p[0]['metadata'].update(name='unexpected'),
                       lambda p:p[0]['status']['conditions'][0].update(status='False'),
                       lambda p:p[0]['status'].update(phase='Pending')]:
            item, pods, kafkas = fixture();mutate(pods)
            self.assertTrue(stateful.errors([item], pods, kafkas))

    def test_foreign_or_ambiguous_kafka_and_unknown_strategy_fail(self):
        for mutate in [lambda s,k:s['metadata']['ownerReferences'][0].update(uid='other'),
                       lambda s,k:k.append(copy.deepcopy(k[0])),
                       lambda s,k:k[0]['status'].update(observedGeneration=0),
                       lambda s,k:k[0]['status']['conditions'][0].update(status='False'),
                       lambda s,k:s['metadata']['labels'].update({'strimzi.io/cluster': 'other'}),
                       lambda s,k:s['spec']['updateStrategy'].update(type='Unknown'),
                       lambda s,k:s['spec']['selector'].update(matchExpressions=[{}])]:
            item, pods, kafkas = fixture();mutate(item, kafkas)
            self.assertTrue(stateful.errors([item], pods, kafkas))

    def test_rolling_update_and_partition_semantics(self):
        item, pods, kafkas = fixture('RollingUpdate')
        self.assertEqual([], stateful.errors([item], pods, kafkas))
        item['status']['updatedReplicas'] = 1
        self.assertTrue(stateful.errors([item], pods, kafkas))
        item['spec']['updateStrategy']['rollingUpdate'] = {'partition': 1}
        item['status']['currentRevision'] = 'old'
        self.assertEqual([], stateful.errors([item], pods, kafkas))

    def test_ondelete_wait_never_calls_rollout(self):
        item, pods, kafkas = fixture()
        def get(kind):return {'statefulsets': [item], 'pods': pods, 'kafkas.kafka.strimzi.io': kafkas}[kind]
        with patch.object(stateful, 'get', side_effect=get), patch.object(stateful, 'command') as command:
            stateful.wait(timeout=10)
            command.assert_not_called()

    def test_rolling_wait_preserves_readonly_rollout_check(self):
        item, pods, kafkas = fixture('RollingUpdate')
        def get(kind):return {'statefulsets': [item], 'pods': pods, 'kafkas.kafka.strimzi.io': kafkas}[kind]
        with patch.object(stateful, 'get', side_effect=get), patch.object(stateful, 'command') as command:
            stateful.wait(timeout=10)
            self.assertEqual(['kubectl', '-n', 'onap', 'rollout', 'status', 'statefulset/cluster-kafka'], command.call_args.args[0][:6])

    def test_wait_deadline_and_identity_change_stop(self):
        item, pods, kafkas = fixture();pods[0]['status']['phase'] = 'Pending'
        def get(kind):return {'statefulsets': [copy.deepcopy(item)], 'pods': pods, 'kafkas.kafka.strimzi.io': kafkas}[kind]
        with patch.object(stateful, 'get', side_effect=get), patch.object(stateful.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaisesRegex(ValueError, 'deadline'):stateful.wait(timeout=1)
        changed = copy.deepcopy(item);changed['metadata']['uid'] = 'replacement'
        with patch.object(stateful, 'get', side_effect=[[item], [changed]]):
            with self.assertRaisesRegex(ValueError, 'identity'):stateful.wait(timeout=1)

    def test_timeout_bounds(self):
        for value in (0, -1, 3601):
            with self.assertRaises(ValueError):stateful.wait(timeout=value)


class CheckoutTests(unittest.TestCase):
    def test_clean_exact_pin(self):
        with patch.object(checkout, 'command', side_effect=[checkout.PROFILE_PIN.encode(), b'']):
            self.assertFalse(checkout.verify(ROOT)['portal_normalization'])

    def test_wrong_pin_or_unrelated_changes_refused(self):
        for values in ([b'other'], [checkout.PROFILE_PIN.encode(), b' M setup-driver.sh\n'],
                       [checkout.PROFILE_PIN.encode(), b'M  test-common.py\n']):
            with patch.object(checkout, 'command', side_effect=values), self.assertRaises(ValueError):checkout.verify(ROOT)

    def test_exact_portal_normalization_only(self):
        # CI uses a shallow checkout; the fixture must not require parent history.
        original = (ROOT/'test-common.py').read_bytes()
        normalized = original.replace(b'2.25.305821105408246119474742976030998643995',
                                      b'2.25.305821105.408246119.47474297.603099864.3995')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);path = root/'test-common.py';path.write_bytes(normalized)
            for drift in (False, True):
                if drift:path.write_bytes(normalized+b'\n')
                with patch.object(checkout, 'command', side_effect=[checkout.PROFILE_PIN.encode(), b' M test-common.py\n', original, b'']):
                    if drift:
                        with self.assertRaises(ValueError):checkout.verify(root)
                    else:self.assertTrue(checkout.verify(root)['portal_normalization'])


class FinalizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name);self.setup = self.base/'setup';self.work = self.setup/'phase3-smo';self.work.mkdir(parents=True)
        self.review = self.base/'review.json';self.binding = {'source_commit': 'reviewed'}
        archive = self.base/'archive';archive.mkdir();(archive/'binding.json').write_text(json.dumps(self.binding))
        self.review.write_text(json.dumps({'passed': True, 'archive': {'directory': str(archive)}, 'binding': self.binding}))
        self.addCleanup(patch.stopall)
        patch.object(final, 'SETUP', self.setup).start()
        patch.object(final, 'verify_archive').start()
        self.inspect = patch.object(final, 'inspect', return_value=self.binding).start()

    def test_complete_orders_normal_checks_before_markers_and_has_no_provisioning(self):
        calls = []
        def logged(args, path):
            self.assertFalse(any((self.setup/n).exists() for n in final.MARKERS))
            calls.append(args)
            target = Path(args[args.index('--output')+1]) if '--output' in args else self.work/'provenance.json'
            target.write_text(json.dumps({'readiness_errors': []}))
        with patch.object(final, 'logged', side_effect=logged):final.apply(final.SLICE, ROOT, self.review)
        self.assertEqual(2, len(calls));self.assertIn('collect-phase3-provenance.py', calls[0][2]);self.assertEqual(str(ROOT/'setup-end.sh'), calls[1][0])
        self.assertTrue(all((self.setup/n).is_file() for n in final.MARKERS))
        accepted = json.loads((self.work/'final-readiness-acceptance.json').read_text())
        self.assertTrue(accepted['passed']);self.assertFalse(accepted['certificate_fault_cases_started'])
        self.assertEqual(0o600, (self.work/'final-readiness-attempt.json').stat().st_mode & 0o777)
        with self.assertRaises(FileExistsError):final.apply(final.SLICE, ROOT, self.review)

    def test_changed_review_binding_stops_before_attempt_or_completion(self):
        self.inspect.return_value = {'changed': True}
        with patch.object(final, 'logged') as logged, self.assertRaises(ValueError):final.apply(final.SLICE, ROOT, self.review)
        logged.assert_not_called();self.assertFalse((self.work/'final-readiness-attempt.json').exists())

    def test_failure_or_unhealthy_provenance_leaves_no_markers(self):
        def logged(args, path):
            (self.base/'final-provenance.json').write_text(json.dumps({'readiness_errors': ['failed']}))
        with patch.object(final, 'logged', side_effect=logged), self.assertRaises(ValueError):final.apply(final.SLICE, ROOT, self.review)
        self.assertFalse(any((self.setup/n).exists() for n in final.MARKERS))
        self.assertTrue((self.base/'final-readiness-failure.json').exists())
        self.assertTrue((self.work/'final-readiness-attempt.json').exists())

    def test_late_identity_change_blocks_markers(self):
        self.inspect.side_effect = [self.binding, self.binding, {'changed': True}]
        def logged(args, path):
            target = Path(args[args.index('--output')+1]) if '--output' in args else self.work/'provenance.json'
            target.write_text(json.dumps({'readiness_errors': []}))
        with patch.object(final, 'logged', side_effect=logged), self.assertRaises(ValueError):final.apply(final.SLICE, ROOT, self.review)
        self.assertFalse(any((self.setup/n).exists() for n in final.MARKERS))

    def test_exclusive_evidence_and_symlink_refusal(self):
        path = self.base/'new.json';final.write_new(path, {'passed': True})
        with self.assertRaises(FileExistsError):final.write_new(path, {})
        link = self.base/'link';link.symlink_to(path)
        with self.assertRaises(ValueError):final.sha(link)

    def test_wrong_slice_host_missing_prerequisites_and_completed_setup_stop(self):
        # Restore the actual inspector temporarily; no live command is executed.
        # The synthetic tests above patch inspect; load a separate module for its guards.
        spec = importlib.util.spec_from_file_location('final_guard_tests', ROOT/'bin/phase3-final-readiness.py')
        guard = importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
        with patch.object(guard, 'SETUP', self.setup), patch.object(guard.checkout, 'verify', return_value={}), \
                patch.object(guard, 'no_startup'), patch.object(guard, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'restricted'):guard.inspect('other', ROOT)
            command.side_effect = [guard.SLICE.encode(), b'worker']
            with self.assertRaisesRegex(ValueError, 'node-0'):guard.inspect(guard.SLICE, ROOT)
            command.side_effect = [guard.SLICE.encode(), b'node-0', b'', b'reviewed']
            with self.assertRaisesRegex(ValueError, 'prerequisite'):guard.inspect(guard.SLICE, ROOT)
            for name in guard.PREREQUISITES:(self.setup/name).touch()
            (self.setup/guard.MARKERS[0]).touch()
            command.side_effect = [guard.SLICE.encode(), b'node-0', b'', b'reviewed']
            with self.assertRaisesRegex(ValueError, 'marker'):guard.inspect(guard.SLICE, ROOT)

    def test_accepted_archive_tampering_is_detected(self):
        spec = importlib.util.spec_from_file_location('final_archive_tests', ROOT/'bin/phase3-final-readiness.py')
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        archive = self.base/'tamper-archive';archive.mkdir();data = archive/'setup.log';data.write_text('private diagnostic')
        module.write_new(archive/'SHA256SUMS.json', {'files': {'setup.log': module.sha(data)}})
        record = {'directory': str(archive), 'ledger_sha256': module.sha(archive/'SHA256SUMS.json')}
        module.verify_archive(record);data.write_text('changed')
        with self.assertRaises(ValueError):module.verify_archive(record)

    def test_strategy_helper_is_automatic_and_resume_precedes_setup_library(self):
        driver = (ROOT/'setup-driver.sh').read_text();smo = (ROOT/'setup-oran-smo.sh').read_text()
        self.assertLess(driver.index('--resume-final-readiness'), driver.index('. "$SRC/setup-lib.sh"'))
        self.assertNotIn('rollout status "$resource"', smo)
        self.assertIn('phase3_stateful_readiness.py', smo)
        subprocess.run(['bash', '-n', str(ROOT/'setup-driver.sh')], check=True)


if __name__ == '__main__':unittest.main()
