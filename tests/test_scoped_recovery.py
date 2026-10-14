import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bin'))
import phase3_scoped_recovery as guard


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'bin' / file)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


rollout = module('rollout', 'phase3-statefulset-recovery.py')
resume = module('resume', 'phase3-held-job-resume.py')


def fixture():
    name = guard.TARGETS[0]
    init = {'name': 'fix-permission', 'image': 'docker.io/busybox:1.34.1', 'command': ['/bin/sh'], 'args': ['-c',
            'chown -R 10001:10001 /data\nchown -R 10001:10001 /bootstrap/\nchown -R 10001:10001 /tmp/\ncp /config/my.cnf /actual/my.cnf\nchown -R 10001:10001 /actual\n'],
            'securityContext': {'runAsUser': 0}, 'volumeMounts': [
                {'mountPath': path, 'name': volume} for path, volume in [('/data', name), ('/bootstrap', 'previous-boot'),
                    ('/tmp', 'mariadb-tmp-folder'), ('/config/my.cnf', 'mariadb-galera-starting-config'), ('/actual', 'mariadb-galera-actual-config')]]}
    ps = {'containers': [{'name': 'mariadb-galera', 'image': 'docker.io/bitnami/mariadb-galera:10.5.8'}], 'initContainers': [init], 'volumes': [
        {'name': name, 'persistentVolumeClaim': {'claimName': name + '-' + name + '-0'}},
        {'name': 'previous-boot', 'emptyDir': {}}, {'name': 'mariadb-tmp-folder', 'emptyDir': {}},
        {'name': 'mariadb-galera-actual-config', 'emptyDir': {}},
        {'name': 'mariadb-galera-starting-config', 'configMap': {'name': 'configuration'}}]}
    pod = {'kind': 'Pod', 'metadata': {'name': name + '-0', 'namespace': 'onap', 'uid': 'pod-old', 'resourceVersion': '10',
            'ownerReferences': [{'kind': 'StatefulSet', 'uid': 'ss', 'controller': True}]},
           'spec': dict(copy.deepcopy(ps), nodeName='node-2'), 'status': {
               'containerStatuses': [{'name': 'mariadb-galera', 'state': {'waiting': {'reason': 'ImagePullBackOff'}}}],
               'initContainerStatuses': [{'name': 'fix-permission', 'state': {'terminated': {'exitCode': 0}}}]}}
    new = copy.deepcopy(ps); new['containers'][0]['image'] = guard.replacements()[ps['containers'][0]['image']]
    new['volumes'] = new['volumes'][1:]
    claim_spec = {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '3Gi'}}}
    ss = {'kind': 'StatefulSet', 'metadata': {'name': name, 'uid': 'ss', 'resourceVersion': '20', 'generation': 2},
          'spec': {'replicas': 1, 'podManagementPolicy': 'OrderedReady', 'updateStrategy': {'type': 'RollingUpdate'},
                   'volumeClaimTemplates': [{'metadata': {'name': name}, 'spec': copy.deepcopy(claim_spec)}],
                   'persistentVolumeClaimRetentionPolicy': {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}, 'template': {'spec': new}}}
    baseline = {'targets': {name: {'pod': copy.deepcopy(pod), 'owner_uid': 'ss', 'node_uid': 'nodeuid'}},
                'protections': {'storage': {'PersistentVolumeClaim/' + name + '-' + name + '-0': {'spec': dict(claim_spec, volumeName='pv')}}}}
    nodes = [{'metadata': {'name': 'node-2', 'uid': 'nodeuid', 'labels': {'kubernetes.io/hostname': 'node-2'}}}]
    return ss, pod, baseline, nodes


def job_fixture():
    name = 'onap-dmaap-dr-mariadb-init-config-job'
    job = {'kind': 'Job', 'metadata': {'name': name, 'namespace': 'onap', 'uid': 'job-new', 'resourceVersion': '40',
            'annotations': {'meta.helm.sh/release-name': guard.JOBS[name]}},
           'spec': {'suspend': True, 'backoffLimit': 0, 'parallelism': 1, 'completions': 1,
                    'template': {'spec': {'restartPolicy': 'Never', 'containers': [{'name': 'init', 'image': 'pinned'}],
                        'initContainers': [{'name': 'ready', 'command': ['/app/ready.py', '--container-name', 'mariadb-galera']}]}}}, 'status': {}}
    return job, {'uid': job['metadata']['uid'], 'spec': copy.deepcopy(job['spec'])}


class GuardTests(unittest.TestCase):
    def test_stalled_fixture_passes(self):
        self.assertEqual('node-2', guard.stalled_guard(*fixture())['node'])

    def test_owner_and_pod_uid_changes_rejected(self):
        for key in ('owner', 'pod', 'node'):
            ss, pod, baseline, nodes = fixture()
            if key == 'owner': ss['metadata']['uid'] = 'other'
            elif key == 'pod': pod['metadata']['uid'] = 'other'
            else: nodes[0]['metadata']['uid'] = 'other'
            with self.assertRaises(ValueError): guard.stalled_guard(ss, pod, baseline, nodes)

    def test_main_execution_and_missing_history_rejected(self):
        for value in ({'imageID': 'started'}, {'restartCount': 1}, {'lastState': {'terminated': {}}}, {'state': {'running': {}}}):
            ss, pod, baseline, nodes = fixture(); pod['status']['containerStatuses'][0].update(value)
            with self.assertRaises(ValueError): guard.stalled_guard(ss, pod, baseline, nodes)
        ss, pod, baseline, nodes = fixture(); pod['status']['containerStatuses'] = []
        with self.assertRaises(ValueError): guard.stalled_guard(ss, pod, baseline, nodes)

    def test_security_probe_volume_or_image_delta_rejected(self):
        for key in ('securityContext', 'readinessProbe', 'volumes', 'image'):
            ss, pod, baseline, nodes = fixture()
            if key == 'volumes': ss['spec']['template']['spec']['volumes'] = []
            elif key == 'image': ss['spec']['template']['spec']['containers'][0]['image'] = 'mutable:latest'
            else: ss['spec']['template']['spec']['containers'][0][key] = {'changed': True}
            with self.assertRaises(ValueError): guard.stalled_guard(ss, pod, baseline, nodes)

    def test_placement_only_override_allowed(self):
        ss, pod, baseline, nodes = fixture(); ss['spec']['template']['spec']['nodeSelector'] = {'kubernetes.io/hostname': 'node-2'}
        self.assertTrue(guard.stalled_guard(ss, pod, baseline, nodes)['placement_already_pinned'])
        ss['spec']['template']['spec']['nodeSelector']['other'] = 'selector'
        with self.assertRaises(ValueError): guard.stalled_guard(ss, pod, baseline, nodes)

    def test_rollout_partition_scale_retention_rejected(self):
        for key, value in [('replicas', 2), ('updateStrategy', {'type': 'OnDelete'}), ('persistentVolumeClaimRetentionPolicy', {'whenScaled': 'Delete'})]:
            ss, pod, baseline, nodes = fixture(); ss['spec'][key] = value
            with self.assertRaises(ValueError): guard.stalled_guard(ss, pod, baseline, nodes)

    def test_unsafe_initializer_and_failed_history_rejected(self):
        for field in ('command', 'image', 'mount', 'history'):
            ss, pod, baseline, nodes = fixture()
            if field == 'command': pod['spec']['initContainers'][0]['args'] = ['-c', 'rm data']
            elif field == 'image': pod['spec']['initContainers'][0]['image'] = 'new:tag'
            elif field == 'mount': pod['spec']['initContainers'][0]['volumeMounts'][0]['mountPath'] = '/'
            else: pod['status']['initContainerStatuses'][0]['restartCount'] = 1
            with self.assertRaises(ValueError): guard.init_contract(pod, ss['metadata']['name'])

    def test_automatic_mount_not_security_contract_removed(self):
        ss, pod, baseline, nodes = fixture(); before = guard.normalized_pod_spec(pod['spec'])
        pod['spec']['volumes'].append({'name': 'kube-api-access-demo', 'projected': {'sources': []}})
        pod['spec']['containers'][0]['volumeMounts'] = [{'name': 'kube-api-access-demo', 'mountPath': '/var/run/secrets/kubernetes.io/serviceaccount', 'readOnly': True}]
        self.assertEqual(before, guard.normalized_pod_spec(pod['spec']))
        pod['spec']['containers'][0]['volumeMounts'][0]['mountPath'] = '/data'
        with self.assertRaises(ValueError): guard.normalized_pod_spec(pod['spec'])

    def test_placement_patch_exact_preconditions(self):
        ss, _, _, _ = fixture(); patches = guard.placement_patch(ss, 'node-2')
        tests = {p['path']: p['value'] for p in patches if p['op'] == 'test'}
        self.assertEqual({'/metadata/uid': 'ss', '/metadata/resourceVersion': '20', '/spec': ss['spec']}, tests)
        self.assertEqual('/spec/template/spec/nodeSelector', patches[-1]['path'])

    def test_held_job_is_same_uid_no_execution(self):
        job, expected = job_fixture(); self.assertEqual('held', guard.held_guard(job, [], expected))
        job['metadata']['uid'] = 'old-failed-uid'
        with self.assertRaises(ValueError): guard.held_guard(job, [], expected)

    def test_held_job_attempt_and_retry_changes_rejected(self):
        for field in ('backoff', 'restart', 'history', 'start', 'failed'):
            job, expected = job_fixture(); pods = []
            if field == 'backoff': job['spec']['backoffLimit'] = 1
            elif field == 'restart': job['spec']['template']['spec']['restartPolicy'] = 'OnFailure'
            elif field == 'history': pods = [{'metadata': {'ownerReferences': [{'uid': 'job-new', 'controller': True}]}}]
            elif field == 'start': job['status']['startTime'] = 'earlier'
            else: job['status']['failed'] = 1
            with self.assertRaises(ValueError): guard.held_guard(job, pods, expected)

    def test_completed_job_is_preserved_not_replayed(self):
        job, expected = job_fixture(); job['spec']['suspend'] = False; job['status']['conditions'] = [{'type': 'Complete', 'status': 'True'}]
        pod = {'metadata': {'ownerReferences': [{'uid': 'job-new', 'controller': True}]}, 'status': {'phase': 'Succeeded'}}
        self.assertEqual('complete', guard.held_guard(job, [pod], expected))

    def test_duplicate_execution_rejected(self):
        job, expected = job_fixture(); job['spec']['suspend'] = False
        pod = {'metadata': {'ownerReferences': [{'uid': 'job-new', 'controller': True}]}}
        with self.assertRaises(ValueError): guard.held_guard(job, [pod, pod], expected)

    def test_excluded_job_never_eligible(self):
        job, expected = job_fixture()
        for name in guard.PRESERVE_JOBS:
            job['metadata']['name'] = name
            with self.assertRaises(ValueError): guard.held_guard(job, [], expected)

    def test_dependency_binding_is_exact_and_ambiguity_rejected(self):
        ss, _, _, _ = fixture(); job, _ = job_fixture(); bindings = guard.dependency_bindings(job, [ss], [job])
        self.assertEqual('ss', bindings[0]['uid'])
        with self.assertRaises(ValueError): guard.dependency_bindings(job, [ss, ss], [job])

    def test_pending_old_revision_dependency_not_accepted(self):
        ss, pod, _, _ = fixture(); job, _ = job_fixture(); bindings = guard.dependency_bindings(job, [ss], [job])
        ss['status'] = {'readyReplicas': 1, 'updatedReplicas': 1, 'observedGeneration': 2, 'currentRevision': 'old', 'updateRevision': 'new'}
        pod['status']['containerStatuses'][0]['ready'] = True
        self.assertFalse(guard.dependencies_ready(bindings, [ss], [job], [pod]))
        ss['status']['currentRevision'] = 'new'; self.assertTrue(guard.dependencies_ready(bindings, [ss], [job], [pod]))

    def test_dependency_drift_fails_closed(self):
        ss, pod, _, _ = fixture(); job, _ = job_fixture(); bindings = guard.dependency_bindings(job, [ss], [job]); ss['metadata']['uid'] = 'other'
        with self.assertRaises(ValueError): guard.dependencies_ready(bindings, [ss], [job], [pod])

    def test_policy_clamp_waits_for_exact_completed_job(self):
        job, _ = job_fixture(); dep = copy.deepcopy(job); dep['metadata']['name'] = 'onap-policy-galera-config'; dep['metadata']['uid'] = 'policy'
        job['spec']['template']['spec']['initContainers'][0]['command'] = ['/app/ready.py', '--job-name', dep['metadata']['name']]
        bindings = guard.dependency_bindings(job, [], [dep, job]); self.assertFalse(guard.dependencies_ready(bindings, [], [dep, job], []))
        dep['spec']['suspend'] = False; dep['status']['conditions'] = [{'type': 'Complete', 'status': 'True'}]
        self.assertTrue(guard.dependencies_ready(bindings, [], [dep, job], [])); self.assertEqual(bindings, guard.dependency_bindings(job, [], [dep, job]))

    def test_audit_hash_mode_freshness_guard(self):
        session = object.__new__(guard.Session); session.mode = 'jobs'; session.baseline_bytes = b'baseline'
        session.args = SimpleNamespace(expected_slice_urn='test', expected_commit='c')
        record = {'schema': 'phase3-scoped-audit-v1', 'mode': 'jobs', 'slice_urn': 'test', 'commit': 'c', 'baseline_sha256': hashlib.sha256(b'baseline').hexdigest(),
                  'image_lock_sha256': hashlib.sha256(guard.LOCK_PATH.read_bytes()).hexdigest(), 'recorded_utc': datetime.now(timezone.utc).isoformat()}
        with tempfile.TemporaryDirectory() as directory:
            session.work = Path(directory); session.args.approved_audit = str(Path(directory) / 'input.json')
            for invalid in ('hash', 'mode', 'age'):
                item = copy.deepcopy(record)
                if invalid == 'mode': item['mode'] = 'rollout'
                if invalid == 'age': item['recorded_utc'] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                blob = json.dumps(item).encode(); Path(session.args.approved_audit).write_bytes(blob)
                session.args.approved_audit_sha256 = 'wrong' if invalid == 'hash' else hashlib.sha256(blob).hexdigest()
                with self.assertRaises(ValueError): session.approved()

    def test_audit_does_not_apply(self):
        fake = SimpleNamespace(args=SimpleNamespace(apply=False), result={'status': 'running'}, audit=lambda: None, save_result=lambda: None)
        with patch.object(guard, 'arguments'), patch.object(guard, 'Session', return_value=fake), patch('builtins.print'):
            action = Mock(); self.assertEqual(0, guard.execute('jobs', action, 'description')); action.assert_not_called()

    def test_interruption_does_not_signal_workloads(self):
        with self.assertRaises(InterruptedError): guard.Session.interrupted(None, 15, None)

    def test_unscheduled_replacement_waits_wrong_node_rejected(self):
        ss, pod, _, _ = fixture(); pinned = copy.deepcopy(ss['spec']); pinned['template']['spec']['nodeSelector'] = {'kubernetes.io/hostname': 'node-2'}; ss['spec'] = pinned
        old = {'statefulset': copy.deepcopy(ss), 'pod': copy.deepcopy(pod), 'proof': {'node': 'node-2'}}
        pod['metadata']['uid'] = 'new'; pod['spec'].pop('nodeName'); self.assertFalse(rollout.replacement_ready(ss, pod, old, pinned))
        pod['spec']['nodeName'] = 'node-1'
        with self.assertRaises(ValueError): rollout.replacement_ready(ss, pod, old, pinned)

    def test_storage_script_refuses_nonempty_link_or_wrong_owner(self):
        self.assertIn('list(p.iterdir())', guard.STORAGE_SCRIPT); self.assertIn('str(p.resolve())!=path', guard.STORAGE_SCRIPT)
        self.assertIn('(s.st_uid,s.st_gid)!=(uid,gid)', guard.STORAGE_SCRIPT)

    def test_claim_template_security_and_storage_delta_rejected(self):
        ss, pod, baseline, nodes = fixture()
        ss['spec']['volumeClaimTemplates'][0]['spec']['resources']['requests']['storage'] = '30Gi'
        with self.assertRaises(ValueError): guard.stalled_guard(ss, pod, baseline, nodes)

    def test_generated_claim_name_not_arbitrary_mount_removed(self):
        ss, pod, baseline, nodes = fixture()
        ss['spec']['volumeClaimTemplates'][0]['metadata']['name'] = 'other'
        with self.assertRaises(ValueError): guard.stalled_guard(ss, pod, baseline, nodes)

    def test_controller_generated_claim_is_added_exactly(self):
        ss, pod, baseline, nodes = fixture()
        generated = guard.stateful_template_spec(ss, pod['metadata']['name'])
        self.assertEqual(pod['spec']['volumes'][0], generated['volumes'][0])

    def test_storage_writer_inventory_explicitly_includes_all_namespaces(self):
        text = (ROOT / 'bin' / 'phase3_scoped_recovery.py').read_text()
        self.assertIn("['kubectl', 'get', 'pods', '-A', '-o', 'json', '--request-timeout=30s']", text)

    def test_recovery_has_no_reinstall_or_force_delete(self):
        for name in ('phase3-statefulset-recovery.py', 'phase3-held-job-resume.py', 'phase3_scoped_recovery.py'):
            text = (ROOT / 'bin' / name).read_text()
            for forbidden in ('helm upgrade', 'helm install', '--force', 'setup-oran-smo.sh', 'setup-driver.sh'):
                self.assertNotIn(forbidden, text)


if __name__ == '__main__': unittest.main()
