import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
spec=importlib.util.spec_from_file_location('deploy_resume_tests',ROOT/'bin/phase3-onap-deploy-resume.py')
resume=importlib.util.module_from_spec(spec);spec.loader.exec_module(resume)


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.setup=Path(self.temp.name)/'setup';self.parent=self.setup/'phase3-smo/fresh-start'
        self.parent.mkdir(parents=True);self.path=self.parent/'context.json'
        self.slice='urn:publicid:IDN+emulab.net:project+slice+fresh'
        self.context={'slice_urn':self.slice,'sms_backend_contract':1,'sms_preload_contract':1,'root_sha256':'root'}
        self.path.write_text(json.dumps(self.context))
        self.failure=self.parent/'sms-backend-blocked-1.json'
        self.failure.write_text(json.dumps({'failure_type':'Blocked','backend_accepted':False,'preload_authorized':False,
            'reason':'Fresh backend handoff timed out; no reset or recovery attempted'}))
        for name in resume.PREREQUISITES:(self.setup/name).touch()
        self.nodes=[{'status':{'conditions':[{'type':'Ready','status':'True'}]}}]*3
        def resource(kind,name,uid):return {'kind':kind,'metadata':{'name':name,'uid':uid},'spec':{},'status':{}}
        self.job=resource('Job',resume.preload.preload.JOB,'held-uid');self.job['spec']['suspend']=True
        completed=resource('Job','already-complete','complete-uid')
        completed['status']['conditions']=[{'type':'Complete','status':'True'}]
        claim=resource('PersistentVolumeClaim','claim','claim-uid')
        claim['spec']['volumeName']='volume';claim['status']['phase']='Bound'
        self.resources=[resource('Deployment','server','deployment-uid'),resource('StatefulSet','vault','sts-uid'),self.job,completed,claim]
        self.pv=resource('PersistentVolume','volume','pv-uid')
        self.record={'identity':{'pods':{'sms':'original'},'claims':{'claim':'claim-uid'}},
            'vault':{'initialized':True,'sealed':False},'quorum':[],
            'sms_backend_auth':{'role':{'present':False},'secret':{'present':False}}}
        self.objects=({}, {}, [], [], [])
        self.releases=[{'name':'onap-aaf','revision':'1','chart':'aaf-pinned','app_version':'pinned','status':'deployed'}]
        def command(args):
            if args[0]=='geni-get':return self.slice.encode()
            if args[0]=='hostname':return b'node-0.fresh.example'
            if args[0]=='helm':return json.dumps(self.releases).encode()
            self.fail('Unexpected command: '+args[0])
        def get(kind):
            if kind=='deployments,statefulsets,jobs,pvc':return {'items':copy.deepcopy(self.resources)}
            if kind=='pv':return {'items':[copy.deepcopy(self.pv)]}
            if kind=='kafkas.kafka.strimzi.io':return {'items':[{}]}
            self.fail('Unexpected read: '+kind)
        self.addCleanup(patch.stopall)
        patch.object(resume.backend,'command',side_effect=command).start()
        patch.object(resume.backend,'get',side_effect=get).start()
        patch.object(resume.fresh,'verify_context',return_value=self.context).start()
        patch.object(resume.fresh,'cluster_nodes',return_value=self.nodes).start()
        patch.object(resume.backend,'snapshot',side_effect=lambda:(copy.deepcopy(self.record),self.objects)).start()
        patch.object(resume.backend,'verify_pins').start()
        patch.object(resume.backend,'tls',return_value=('leaf',{},None)).start()
        patch.object(resume.backend,'operator_binding',return_value={'uid':'operator'}).start()
        patch.object(resume.backend.backend,'recovery_checks',return_value={'custody':'verified'}).start()
        patch.object(resume.preload,'job_contract',side_effect=lambda job:job).start()
        self.owned=patch.object(resume.preload,'owned_pods',return_value=[]).start()
        self.verify_backend=patch.object(resume.backend,'verify_acceptance',return_value={'backend_accepted':True}).start()
        self.verify_preload=patch.object(resume.preload,'verify_acceptance',return_value={'preload_accepted':True}).start()

    def inspect(self):return resume.inspect(self.slice,self.path)

    def save_review(self):
        binding,completed,*_=self.inspect()
        (self.parent/'onap-deploy-resume-review.json').write_text(json.dumps({'binding':binding,'completed_jobs':completed}))
        return binding

    def test_audit_has_no_writes_or_application_calls(self):
        before={p.name:p.read_bytes() for p in self.parent.iterdir()}
        with patch.object(resume.backend,'wait_fresh') as backend,patch.object(resume.preload,'run_fresh') as preload:
            result=resume.continue_startup(self.slice,self.path)
        self.assertTrue(result['eligible']);self.assertFalse(result['workloads_changed'])
        backend.assert_not_called();preload.assert_not_called()
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.parent.iterdir()})

    def test_wrong_allocation_old_context_missing_prerequisite_and_finished_refused(self):
        with self.assertRaises(resume.backend.Blocked):resume.inspect('other',self.path)
        self.context['sms_preload_contract']=0
        with self.assertRaises(resume.backend.Blocked):self.inspect()
        self.context['sms_preload_contract']=1
        marker=self.setup/resume.PREREQUISITES[0];marker.unlink()
        with self.assertRaises(resume.backend.Blocked):self.inspect()
        marker.touch();(self.setup/'setup-oran-smo-done').touch()
        with self.assertRaises(resume.backend.Blocked):self.inspect()

    def test_non_timeout_or_missing_failure_refused(self):
        self.failure.write_text('{}')
        with self.assertRaises(resume.backend.Blocked):self.inspect()
        self.failure.unlink()
        with self.assertRaises(resume.backend.Blocked):self.inspect()

    def test_sealed_uninitialized_or_existing_unaccepted_auth_refused(self):
        for key,value in (('sealed',True),('initialized',False)):
            original=self.record['vault'][key];self.record['vault'][key]=value
            with self.assertRaises(resume.backend.Blocked):self.inspect()
            self.record['vault'][key]=original
        self.record['sms_backend_auth']['role']['present']=True
        with self.assertRaises(resume.backend.Blocked):self.inspect()

    def test_unready_nodes_failed_jobs_unbound_storage_and_helm_failure_refused(self):
        self.nodes[0]['status']['conditions'][0]['status']='False'
        with self.assertRaises(resume.backend.Blocked):self.inspect()
        self.nodes[0]['status']['conditions'][0]['status']='True'
        self.resources[3]['status']['failed']=1
        with self.assertRaises(resume.backend.Blocked):self.inspect()
        del self.resources[3]['status']['failed']
        self.resources[-1]['status']['phase']='Pending'
        with self.assertRaises(resume.backend.Blocked):self.inspect()
        self.resources[-1]['status']['phase']='Bound';self.releases[0]['status']='failed'
        with self.assertRaises(resume.backend.Blocked):self.inspect()

    def test_preload_owned_pod_or_activation_is_not_adopted(self):
        self.owned.return_value=[{}]
        with self.assertRaises(resume.backend.Blocked):self.inspect()
        self.owned.return_value=[];self.job['spec']['suspend']=False
        with self.assertRaises(resume.backend.Blocked):self.inspect()

    def test_attempt_without_acceptance_never_retried(self):
        for filename in ('sms-backend-first-use-attempt.json','sms-preload-attempt.json','sms-preload-armed.json'):
            path=self.parent/filename;path.write_text('{}')
            with self.assertRaisesRegex(resume.backend.Blocked,'uncertain'):self.inspect()
            path.unlink()

    def test_binding_changes_and_completed_job_regression_refused(self):
        binding=self.save_review()
        self.assertEqual(binding,self.inspect()[0])
        self.record['identity']['pods']['sms']='replacement'
        with self.assertRaisesRegex(resume.backend.Blocked,'identity changed'):self.inspect()
        self.record['identity']['pods']['sms']='original'
        self.resources[3]['status']['conditions']=[]
        with self.assertRaisesRegex(resume.backend.Blocked,'identity changed'):self.inspect()

    def test_accepted_preload_activation_and_additional_completion_are_expected(self):
        binding=self.save_review()
        (self.parent/'sms-backend-acceptance.json').write_text('{}')
        (self.parent/'sms-preload-acceptance.json').write_text('{}')
        self.job['spec']['suspend']=False
        self.job['status']['conditions']=[{'type':'Complete','status':'True'}]
        self.assertEqual(binding,self.inspect()[0])
        self.verify_backend.assert_called();self.verify_preload.assert_called()

    def test_run_orders_preservation_then_backend_then_preload_then_onap(self):
        events=[]
        def preserve(*args):events.append('preserve');return '/private/fixture'
        def backend(*args,**kwargs):
            events.append('backend');self.assertEqual({'pods':{'sms':'original'},'claims':{'claim':'claim-uid'}},kwargs['expected_identity'])
            (self.parent/'sms-backend-acceptance.json').write_text('{}')
        def preload(*args):events.append('preload');(self.parent/'sms-preload-acceptance.json').write_text('{}')
        def onap(*args):events.append('onap')
        with patch.object(resume,'preserve',side_effect=preserve), \
             patch.object(resume.backend,'wait_fresh',side_effect=backend), \
             patch.object(resume.preload,'run_fresh',side_effect=preload), \
             patch.object(resume.fresh,'wait_onap',side_effect=onap), \
             patch.object(resume.subprocess,'run') as wait:
            wait.return_value.returncode=0
            result=resume.continue_startup(self.slice,self.path,True)
        self.assertEqual(['preserve','backend','preload','onap'],events)
        self.assertTrue(result['onap_accepted'])
        self.assertEqual(1230,wait.call_args.kwargs['timeout'])
        review=self.parent/'onap-deploy-resume-review.json'
        self.assertEqual(0o600,review.stat().st_mode&0o777)

    def test_valid_backend_receipt_is_verified_not_rebootstrapped(self):
        self.save_review();(self.parent/'sms-backend-acceptance.json').write_text('{}')
        with patch.object(resume,'preserve',return_value='/private/fixture'), \
             patch.object(resume.backend,'wait_fresh') as backend, \
             patch.object(resume.preload,'run_fresh',side_effect=RuntimeError('stop fixture')) as preload:
            with self.assertRaises(RuntimeError):resume.continue_startup(self.slice,self.path,True)
        backend.assert_not_called();preload.assert_called_once()

    def test_driver_mode_exits_before_infrastructure_and_uses_lock(self):
        driver=(ROOT/'setup-driver.sh').read_text()
        body=driver.split('if [ "$resume_after_onap_deploy" -eq 1 ]; then',1)[1].split('\nfi',1)[0]
        self.assertIn('PHASE3_RECOVERY_LOCK_FD=9',body)
        self.assertIn('--resume-after-onap-deploy',body)
        self.assertIn('exit 0',body);self.assertNotIn('setup-kubespray',body)
        smo=(ROOT/'setup-oran-smo.sh').read_text()
        self.assertIn('--startup-timeout 1800 --timeout 600',smo)


if __name__=='__main__':unittest.main()
