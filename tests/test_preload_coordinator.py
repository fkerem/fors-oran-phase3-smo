"""Coordinator controls: synthetic metadata only, no Kubernetes/network calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
import phase3_preload as preload
spec = importlib.util.spec_from_file_location('preload_coordinator_tests', ROOT/'bin/phase3-sms-preload.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def job():
    stock = {'kind': 'Job', 'metadata': {'name': preload.JOB, 'namespace': 'onap',
                                       'uid': 'job-uid', 'resourceVersion': '1'},
        'spec': {'template': {'metadata': {'labels': {'app': 'aaf-sms', 'release': 'onap'}},
            'spec': {'containers': [{'name': 'aaf-sms-preload',
                'image': 'nexus3.onap.org:10001/onap/aaf/sms:4.0.2',
                'command': preload.STOCK_COMMAND.copy()}]}}}}
    return preload.patch_job(stock, {'sms_backend_contract': 1, 'sms_preload_contract': 1})


class CoordinatorTests(unittest.TestCase):
    def test_pinned_command_is_complete_and_alternate_launch_is_refused(self):
        self.assertEqual(9, len(preload.STOCK_COMMAND))
        self.assertEqual('https://aaf-sms.onap', preload.STOCK_COMMAND[-1])
        self.assertEqual(job(), gate.job_contract(job()))

    def test_job_accepts_reviewed_api_defaults_only(self):
        obj = job()
        pod = obj['spec']['template']['spec']
        pod.update(dnsPolicy='ClusterFirst', schedulerName='default-scheduler',
                   terminationGracePeriodSeconds=30, enableServiceLinks=True, serviceAccount=preload.SA)
        c = pod['containers'][0]
        c.update(terminationMessagePath='/dev/termination-log', terminationMessagePolicy='File', imagePullPolicy='IfNotPresent')
        self.assertEqual('v1', c['env'][1]['valueFrom']['fieldRef']['apiVersion'])
        gate.job_contract(obj)
        for key, value in (('imagePullPolicy', 'Always'), ('args', ['unreviewed']), ('envFrom', [{'secretRef': {'name': 'other'}}])):
            changed = copy.deepcopy(obj)
            changed['spec']['template']['spec']['containers'][0][key] = value
            with self.assertRaises(preload.Blocked):
                gate.job_contract(changed)

    def test_admitted_pod_must_match_job_except_known_defaults(self):
        expected = job()['spec']['template']['spec']
        actual = copy.deepcopy(expected)
        actual.update(nodeName='node-2', priority=0, preemptionPolicy='PreemptLowerPriority',
            tolerations=[{'key': 'node.kubernetes.io/'+n, 'operator': 'Exists', 'effect': 'NoExecute',
                          'tolerationSeconds': 300} for n in ('not-ready', 'unreachable')])
        self.assertEqual(expected, gate.normalized_pod(actual, admitted=True))
        actual['containers'][0]['command'].append('unreviewed')
        self.assertNotEqual(expected, gate.normalized_pod(actual, admitted=True))
        actual['tolerations'][0]['tolerationSeconds'] = 999
        with self.assertRaises(preload.Blocked):
            gate.normalized_pod(actual, admitted=True)

    def test_durable_latch_is_exclusive_private_and_fsynced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'latch.json'
            real_fsync = os.fsync
            with patch.object(gate.os, 'fsync', wraps=real_fsync) as fsync:
                gate.durable_write(path, {'fixture': 'synthetic-only'})
            self.assertEqual(2, fsync.call_count)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                gate.durable_write(path, {'changed': True})
            self.assertEqual({'fixture': 'synthetic-only'}, json.loads(path.read_bytes()))

    def test_any_existing_latch_blocks_before_audit_or_kubernetes(self):
        for name in ('sms-preload-attempt.json', 'sms-preload-armed.json', 'sms-preload-acceptance.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                gate.durable_write(Path(directory)/name, {})
                with patch.object(gate, 'audit') as audit, patch.object(gate, 'create') as create:
                    with self.assertRaisesRegex(preload.Blocked, 'no replay'):
                        gate.run_fresh(Path(directory)/'context.json', 600)
                    audit.assert_not_called()
                    create.assert_not_called()

    def test_retained_and_unknown_contexts_never_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'context.json'
            gate.durable_write(path, {'schema': 1})
            with patch.object(gate, 'postconditions') as check:
                self.assertIsNone(gate.verify_acceptance(path))
                check.assert_not_called()
            other = Path(directory)/'unknown.json'
            gate.durable_write(other, {'sms_preload_contract': 2})
            with self.assertRaisesRegex(preload.Blocked, 'Unreviewed'):
                gate.verify_acceptance(other)

    def test_changed_public_template_blocks_before_reading_credentials(self):
        cm = {'metadata': {'uid': 'template', 'resourceVersion': '1'}, 'data': {'has.json': '{}'}}
        with patch.object(gate, 'get', return_value=cm) as get:
            with self.assertRaisesRegex(preload.Blocked, 'templates changed'):
                gate.source_inputs()
            self.assertEqual(['configmap/'+preload.JOB], [c.args[0] for c in get.call_args_list])

    def test_cancellation_survives_conflict_and_avoids_status_version_race(self):
        armed = {'journal_uid': 'journal-uid', 'binding': {'job_uid': 'job-uid'}}
        journal = {'metadata': {'uid': 'journal-uid', 'resourceVersion': '1'},
                   'data': {'journal.json': json.dumps({'state': 'intent'})}}
        current_job = job()
        current_job['spec']['suspend'] = False
        attempts = [0]
        def get(name):
            return copy.deepcopy(journal if name.startswith('configmap/') else current_job)
        def replace(obj, state):
            attempts[0] += 1
            if attempts[0] == 1:
                raise preload.Blocked('synthetic CAS conflict')
            journal['data']['journal.json'] = json.dumps(state)
        def kubectl(*args, **kwargs):
            patch_data = json.loads(args[args.index('-p')+1])
            self.assertEqual([{'op': 'test', 'path': '/metadata/uid', 'value': 'job-uid'},
                              {'op': 'replace', 'path': '/spec/suspend', 'value': True}], patch_data)
            current_job['metadata']['resourceVersion'] = 'controller-status-changed'
            current_job['spec']['suspend'] = True
        with patch.object(gate, 'get', side_effect=get), patch.object(gate, 'replace_journal', side_effect=replace), \
                patch.object(gate, 'kubectl', side_effect=kubectl), patch.object(gate.time, 'sleep'):
            self.assertEqual({'journal_stopped': True, 'job_suspended': True}, gate.stop_attempt(armed))
        self.assertEqual(2, attempts[0])

    def test_cancellation_never_adopts_replacement_job_or_journal(self):
        armed = {'journal_uid': 'expected-journal', 'binding': {'job_uid': 'expected-job'}}
        obj = {'metadata': {'uid': 'replacement', 'resourceVersion': '1'}, 'spec': {'suspend': False}}
        with patch.object(gate, 'get', return_value=obj), patch.object(gate, 'kubectl') as write, \
                patch.object(gate, 'replace_journal') as replace, patch.object(gate.time, 'sleep'):
            self.assertEqual({'journal_stopped': False, 'job_suspended': False}, gate.stop_attempt(armed))
            write.assert_not_called()
            replace.assert_not_called()

    def test_partial_qualification_never_sufficient(self):
        for record in ({}, {'schema': 1, 'passed': True}, {'schema': 1, 'passed': True, 'contract': 1}):
            with self.assertRaises(preload.Blocked):
                preload.require_qualification(record)


if __name__ == '__main__':
    unittest.main()
