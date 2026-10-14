import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'bin'/file)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

packages=module('packages','phase3-ensure-skopeo.py')
rehearsal=module('rehearsal','phase3-image-rehearsal.py')
workflow=module('workflow','phase3-image-recovery.py')

class WorkflowTests(unittest.TestCase):
    def test_package_plan_rejects_upgrades_and_removals(self):
        self.assertEqual(['skopeo','new-lib'],packages.package_plan_safe('Inst skopeo (1.4.1)\nInst new-lib (1)\n'))
        for text in ('Inst old-lib [1] (2)\nInst skopeo (1)\n','Remv old-lib\nInst skopeo (1)\n','Inst different (1)\n'):
            with self.assertRaises(ValueError):packages.package_plan_safe(text)

    def exporter(self):
        return {'kind':'StatefulSet','spec':{'template':{'spec':{'securityContext':{'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001},'containers':[
            {'image':'docker.io/bitnami/mysqld-exporter:0.12.1-debian-10-r264','securityContext':{'readOnlyRootFilesystem':True,'privileged':False,'allowPrivilegeEscalation':False},
             'command':['sh','-c','DATA_SOURCE_NAME="$MARIADB_ROOT_USER:$MARIADB_ROOT_PASSWORD@(localhost:3306)/" /bin/mysqld_exporter $MARIADB_METRICS_EXTRA_FLAGS'],
             'env':[{'name':'MARIADB_METRICS_EXTRA_FLAGS','value':''}], 'livenessProbe':{'httpGet':{'path':'/metrics'}},'readinessProbe':{'httpGet':{'path':'/metrics'}}}]}}}}

    def test_exporter_contract_retained(self):
        contract=rehearsal.exporter_contract([self.exporter()]);self.assertEqual(10001,contract['uid']);self.assertEqual('',contract['flags'])

    def test_exporter_security_probe_and_flags_changes_rejected(self):
        for change in ('security','probe','flags','uid'):
            doc=self.exporter();spec=doc['spec']['template']['spec'];container=spec['containers'][0]
            if change=='security':container['securityContext']['readOnlyRootFilesystem']=False
            elif change=='probe':container['readinessProbe']['httpGet']['path']='/health'
            elif change=='flags':container['env'][0]={'name':'MARIADB_METRICS_EXTRA_FLAGS','valueFrom':{'secretKeyRef':{}}}
            else:spec['securityContext']['runAsUser']=0
            with self.assertRaises(ValueError):rehearsal.exporter_contract([doc])

    def test_apply_is_refused_before_deletion_when_prerequisites_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(work_dir=str(Path(directory)/'attempt'),apply=True,expected_slice_urn='urn:example',expected_commit='a'*40,
                                 cache_record='cache',rehearsal_record='rehearsal',worker_record='workers')
            with patch.object(workflow,'identity'),patch.object(workflow,'operator_gate',return_value={}), \
                 patch.object(workflow,'snapshot',return_value=([{'name':'eligible'}],{},{})), \
                 patch.object(workflow,'prerequisites',side_effect=ValueError('missing proof')),patch.object(workflow,'hold_and_delete') as deletion:
                result=workflow.apply(args)
            self.assertFalse(result['ready']);deletion.assert_not_called()
            self.assertTrue((Path(args.work_dir)/'result.json').exists())

    def test_audit_never_checks_apply_receipts_or_deletes(self):
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(work_dir=str(Path(directory)/'attempt'),apply=False,expected_slice_urn='urn:example',expected_commit='a'*40)
            with patch.object(workflow,'identity'),patch.object(workflow,'operator_gate',return_value={}), \
                 patch.object(workflow,'snapshot',return_value=([],{},{})),patch.object(workflow,'prerequisites') as prereq,patch.object(workflow,'hold_and_delete') as deletion:
                result=workflow.apply(args)
            self.assertTrue(result['audit_passed']);prereq.assert_not_called();deletion.assert_not_called()

    def test_work_directory_is_not_an_implicit_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):workflow.apply(SimpleNamespace(work_dir=directory))

    def test_delete_uses_exact_uid_resource_version_and_foreground(self):
        proof={'name':'job','uid':'old-uid','resource_version':'7'}
        job={'metadata':{'uid':'old-uid','resourceVersion':'8'}}
        first={'metadata':{'uid':'old-uid','resourceVersion':'7'}}
        with tempfile.TemporaryDirectory() as directory, patch.object(workflow,'get',side_effect=[first,{'items':[]},job,{'items':[]}]), \
             patch.object(workflow,'job_guard',return_value=proof),patch.object(workflow,'run',return_value=b'') as command:
            workflow.hold_and_delete(proof,Path(directory))
            options=json.loads((Path(directory)/'job-delete-options.json').read_text())
            self.assertEqual({'uid':'old-uid','resourceVersion':'8'},options['preconditions'])
            self.assertEqual('Foreground',options['propagationPolicy'])
            self.assertTrue(any('--raw' in call.args[0] for call in command.call_args_list))

    def test_resume_branch_does_not_reinstall_operator_or_onap(self):
        text=(ROOT/'setup-oran-smo.sh').read_text()
        branch=text.split('# No chart downloads, rendering, Strimzi reinstall or ONAP plugin replay on continuation.',1)[1].split('\nfi\nhelm upgrade --install oran-nonrtric',1)[0]
        self.assertIn('phase3-onap-resume-gate.py',branch)
        for forbidden in ('helm -n onap deploy','helm upgrade strimzi','smo-chart-preflight.py','setup-kubespray'):
            self.assertNotIn(forbidden,branch)

    def test_activation_checks_exact_identity_and_single_attempt_controls(self):
        with patch.object(workflow,'run',return_value=b'') as command:
            workflow.activate_job({'metadata':{'name':'eligible','uid':'new-uid','resourceVersion':'12'}})
        patches=json.loads(command.call_args.args[0][-1])
        tests={p['path']:p['value'] for p in patches if p['op']=='test'}
        self.assertEqual('new-uid',tests['/metadata/uid'])
        self.assertEqual('12',tests['/metadata/resourceVersion'])
        self.assertEqual(0,tests['/spec/backoffLimit'])
        self.assertEqual('Never',tests['/spec/template/spec/restartPolicy'])
        self.assertIs(True,tests['/spec/suspend'])

if __name__=='__main__':unittest.main()
