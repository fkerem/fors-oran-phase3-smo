import copy
from datetime import datetime,timedelta,timezone
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import phase3_dmaap as dmaap
spec=importlib.util.spec_from_file_location('dmaap_recovery_tests',ROOT/'bin/phase3-dmaap-recovery.py')
recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime.now(timezone.utc).replace(microsecond=0)
        started=(self.now-timedelta(minutes=5)).isoformat().replace('+00:00','Z')
        stamp=self.now.isoformat().replace('+00:00','Z')
        self.job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':dmaap.JOB,'namespace':'onap',
            'uid':'original-job','resourceVersion':'1','annotations':{'meta.helm.sh/release-name':'onap-dmaap'},'labels':{}},
            'spec':{'suspend':False,'backoffLimit':0,'selector':{'matchLabels':{'controller-uid':'original-job'}},
                'template':{'metadata':{'labels':{'controller-uid':'original-job','batch.kubernetes.io/controller-uid':'original-job',
                    'app.kubernetes.io/instance':'onap','app.kubernetes.io/name':'dmaap-bc'}},
                'spec':{'restartPolicy':'Never','containers':[{'name':'dmaap-provisioning-job',
                    'image':'nexus3.onap.org:10001/onap/dmaap/dbc-client:1.0.9',
                    'env':[{'name':'DELAY','value':'0'},{'name':'REQUESTID','value':'dmaap-bc-dmaap-provisioning'}]}]}}},
            'status':{'active':1}}
        self.pod={'metadata':{'uid':'original-pod','ownerReferences':[{'kind':'Job','uid':'original-job'}]},
            'status':{'containerStatuses':[{'name':'dmaap-provisioning-job','restartCount':0,'lastState':{},
                'imageID':'docker-pullable://'+dmaap.STOCK_IMAGE,'state':{'running':{'startedAt':started}}}]}}
        self.logs=('\n'.join([started+' ENTER config',started+' ENTER init',stamp+' get dmaap response=000',
            stamp+' get dmaap response=000'])+'\n').encode()
        self.script=b'synthetic reviewed script';self.cmdline=b'sh\x00./bin/dbc-client\x00'
        self.guard=patch.object(recovery,'default_credential',return_value='synthetic:only');self.guard.start();self.addCleanup(self.guard.stop)

    def proof(self):return recovery.prewrite_proof(self.job,self.pod,self.script,self.logs,self.cmdline)

    def test_full_startup_and_only_zero_readiness_responses_eligible(self):
        self.assertTrue(self.proof()['prewrite'])

    def test_main_run_is_not_sufficient_without_complete_prewrite_proof(self):
        original=self.logs
        for blob in (b'',original.replace(b'000',b'200'),original+b'+ doprov\n',original+b'-X POST\n',
                     original.replace(b'ENTER config',b'log was truncated')):
            self.logs=blob
            with self.assertRaises(ValueError):self.proof()

    def test_restart_termination_replacement_image_and_command_refused(self):
        original=copy.deepcopy(self.pod)
        for key,value in (('restartCount',1),('lastState',{'terminated':{'exitCode':1}}),
                          ('imageID','different'),('state',{'terminated':{'exitCode':0}})):
            self.pod=copy.deepcopy(original);self.pod['status']['containerStatuses'][0][key]=value
            with self.assertRaises(ValueError):self.proof()
        self.pod=original;self.cmdline=b'other\x00'
        with self.assertRaises(ValueError):self.proof()

    def test_preexisting_history_or_overrides_refused(self):
        baseline=copy.deepcopy(self.job)
        for key,value in (('suspend',True),):
            self.job=copy.deepcopy(baseline);self.job['spec'][key]=value
            with self.assertRaises(ValueError):self.proof()
        for key in ('failed','succeeded'):
            self.job=copy.deepcopy(baseline);self.job['status'][key]=1
            with self.assertRaises(ValueError):self.proof()
        self.job=copy.deepcopy(baseline)
        self.job['spec']['template']['spec']['containers'][0]['env'].append({'name':'RESP','value':'200'})
        with self.assertRaises(ValueError):self.proof()

    def test_replacement_held_and_excluded_from_server_selector(self):
        result=recovery.replacement(self.job)
        self.assertNotIn('uid',result['metadata']);self.assertNotIn('selector',result['spec'])
        self.assertNotIn('status',result)
        self.assertTrue(result['spec']['suspend']);self.assertEqual(0,result['spec']['backoffLimit'])
        labels=result['spec']['template']['metadata']['labels']
        self.assertNotIn('controller-uid',labels)
        selector={'app.kubernetes.io/instance':'onap','app.kubernetes.io/name':'dmaap-bc'}
        self.assertFalse(all(labels.get(k)==v for k,v in selector.items()))
        self.assertEqual(result,recovery.job_contract(result))
        result['spec']['template']['spec']['containers'][0]['args']=['extra']
        with self.assertRaises(ValueError):recovery.job_contract(result)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'context.json';self.path.write_text('{}')
        self.review=Path(self.temp.name)/'review.json'

    def test_expired_and_duplicate_recovery_latches_prevent_inspection_or_writes(self):
        import json
        old=datetime.now(timezone.utc)-timedelta(hours=1)
        self.review.write_text(json.dumps({'created_utc':old.isoformat()}))
        with patch.object(recovery,'audit') as audit,patch.object(recovery,'replace_original') as change:
            with self.assertRaisesRegex(ValueError,'expired'):
                recovery.apply_review(self.path,'slice',self.review,Path('/fixture'))
            audit.assert_not_called();change.assert_not_called()
        self.review.write_text(json.dumps({'created_utc':datetime.now(timezone.utc).isoformat()}))
        (self.path.parent/'dmaap-recovery-attempt.json').write_text('{}')
        with patch.object(recovery,'audit') as audit:
            with self.assertRaisesRegex(ValueError,'no replay'):
                recovery.apply_review(self.path,'slice',self.review,Path('/fixture'))
            audit.assert_not_called()

    def test_drift_rejected_before_preservation_or_replacement(self):
        import json
        self.review.write_text(json.dumps({'created_utc':datetime.now(timezone.utc).isoformat(),'binding':{'old':True}}))
        with patch.object(recovery,'audit',return_value=({}, {'new':True},(),[])), \
             patch.object(recovery,'save_original') as save,patch.object(recovery,'replace_original') as change:
            with self.assertRaisesRegex(ValueError,'changed'):
                recovery.apply_review(self.path,'slice',self.review,Path('/fixture'))
            save.assert_not_called();change.assert_not_called()

    def test_legacy_recovery_refusals_remain_in_place(self):
        old=(ROOT/'bin/phase3-onap-recovery.py').read_text()
        self.assertIn('Main execution observed or history missing; replay refused',old)
        self.assertIn('executed(main[0])',old)

    def test_driver_dmaap_continuation_exits_before_infrastructure(self):
        source=(ROOT/'setup-driver.sh').read_text()
        body=source.split('if [ "$resume_after_dmaap" -eq 1 ]; then')[1].split('\nfi')[0]
        self.assertIn('PHASE3_RECOVERY_LOCK_FD=9',body)
        self.assertIn('--review-file "$dmaap_review"',body)
        self.assertIn('--resume-after-onap',body);self.assertIn('exit 0',body)
        self.assertNotIn('setup-kubespray',body)

    def test_unaccepted_fresh_state_never_replayed(self):
        (self.path.parent/'dmaap-attempt.json').write_text('{}')
        with patch.object(recovery,'get') as get:
            with self.assertRaisesRegex(ValueError,'no replay'):recovery.run_held(self.path,{})
            get.assert_not_called()


if __name__=='__main__':unittest.main()
