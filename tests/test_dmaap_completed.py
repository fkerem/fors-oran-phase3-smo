import copy
from datetime import datetime,timedelta,timezone
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch,Mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import phase3_dmaap as dmaap
spec=importlib.util.spec_from_file_location('completed_recovery',ROOT/'bin/phase3-dmaap-recovery.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
spec=importlib.util.spec_from_file_location('completed_fresh',ROOT/'bin/phase3-fresh-start.py')
fresh=importlib.util.module_from_spec(spec);spec.loader.exec_module(fresh)


def successful_job():
    stock={'kind':'Job','metadata':{'name':dmaap.JOB,'namespace':'onap'},'spec':{'template':{
        'metadata':{'labels':{}},'spec':{'containers':[{'name':'dmaap-provisioning-job','image':dmaap.STOCK_IMAGE}]}}}}
    job=gate.replacement(stock);job['metadata']['uid']='synthetic-job'
    job['status']={'succeeded':1,'conditions':[{'type':'Complete','status':'True'}]}
    return job


class CompletedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.parent=Path(self.temp.name)/'fresh-start';self.parent.mkdir()
        self.path=self.parent/'context.json';gate.durable_write(self.path,{})
        self.job=successful_job()
        self.pod={'metadata':{'name':'synthetic-pod','uid':'synthetic-pod','ownerReferences':[
            {'kind':'Job','uid':'synthetic-job'}]},'spec':copy.deepcopy(self.job['spec']['template']['spec']),
            'status':{'phase':'Succeeded','containerStatuses':[{'restartCount':0,'lastState':{},
                'imageID':dmaap.IMAGE,'state':{'terminated':{'exitCode':0}}}]}}
        self.state={'state':'uncertain','reason':'coordinator-stopped-no-replay',
            'operation':'all-private-postconditions','posts_attempted':6,'posts_observed':6,'pod_uid':'synthetic-pod'}
        self.journal={'metadata':{'uid':'synthetic-journal'},'data':{'journal.json':dmaap.canonical(self.state).decode()}}
        self.armed={'journal_uid':'synthetic-journal','binding':{'server':{'address':'127.0.0.1'}}}
        self.context={'pki_directory':'/synthetic'}
        activated=copy.deepcopy(self.job['spec']);activated['suspend']=False
        self.transition={'replacement':{'uid':'synthetic-job','spec_sha256':gate.sha(activated)}}
        self.review=self.parent/'synthetic-review.json'

    def check(self):
        with patch.object(gate,'check_attempt',return_value=(self.context,self.job,[],self.state,'synthetic:only')), \
             patch.object(gate.preload,'owned_pods',return_value=[self.pod]), \
             patch.object(gate,'get',return_value=self.journal), \
             patch.object(gate,'completed_history',return_value={}) as history, \
             patch.object(gate,'ReadOnlyTransport'),patch.object(dmaap,'verify_values') as values, \
             patch.object(gate,'kubectl') as mutate,patch.object(gate,'run_held') as writer:
            result=gate.completed_postconditions(self.path,self.armed,b'synthetic',{})
            values.assert_called_once();history.assert_called_once()
            mutate.assert_not_called();writer.assert_not_called()
            return result

    def test_exact_completed_postconditions_no_writer_or_cluster_mutation(self):
        self.assertEqual('synthetic-job',self.check()[0]['metadata']['uid'])
        self.assertEqual('uncertain',self.state['state']);self.assertTrue(self.job['spec']['suspend'])

    def test_uncertainty_and_count_variants_refused(self):
        baseline=copy.deepcopy(self.state)
        for key,value in (('state','verified'),('reason','execution-stopped-no-replay'),
                          ('operation',5),('posts_attempted',5),('posts_attempted',True),
                          ('posts_observed',5),('posts_observed',6.0),('pod_uid','replaced')):
            with self.subTest(key=key,value=value):
                self.state=copy.deepcopy(baseline);self.state[key]=value
                self.journal['data']['journal.json']=dmaap.canonical(self.state).decode()
                with self.assertRaises(ValueError):self.check()

    def test_runtime_drift_refused(self):
        baseline=copy.deepcopy(self.pod)
        for key,value in (('restartCount',1),('lastState',{'terminated':{}}),('imageID','other'),
                          ('state',{'terminated':{'exitCode':1}})):
            with self.subTest(key=key):
                self.pod=copy.deepcopy(baseline);self.pod['status']['containerStatuses'][0][key]=value
                with self.assertRaises(ValueError):self.check()
        self.pod=copy.deepcopy(baseline);self.pod['spec']['serviceAccountName']='other'
        with self.assertRaises(ValueError):self.check()
        self.pod=copy.deepcopy(baseline);self.pod['status']['phase']='Running'
        with self.assertRaises(ValueError):self.check()

    def test_extra_or_missing_pod_and_replaced_journal_refused(self):
        with patch.object(gate,'check_attempt',return_value=(self.context,self.job,[],self.state,'synthetic:only')):
            for pods in ([],[self.pod,self.pod]):
                with patch.object(gate.preload,'owned_pods',return_value=pods):
                    with self.assertRaises(ValueError):gate.completed_postconditions(self.path,self.armed,b'',{})
            with patch.object(gate.preload,'owned_pods',return_value=[self.pod]), \
                 patch.object(gate,'get',return_value={'metadata':{'uid':'replaced'},'data':self.journal['data']}):
                with self.assertRaises(ValueError):gate.completed_postconditions(self.path,self.armed,b'',{})

    def test_only_exact_held_successful_replacement_eligible(self):
        expected={'uid':'synthetic-job','spec_sha256':gate.sha(self.job['spec'])}
        self.assertEqual(expected,gate.held_job_binding(self.job,self.transition))
        for status in ({'active':1},{'failed':1},{'succeeded':0},{'conditions':[]},
                       {'conditions':[{'type':'Complete','status':'True'},{'type':'Failed','status':'True'}]}):
            job=copy.deepcopy(self.job);job['status'].update(status)
            with self.assertRaises(ValueError):gate.held_job_binding(job,self.transition)
        for field,value in (('suspend',False),('backoffLimit',1)):
            job=copy.deepcopy(self.job);job['spec'][field]=value
            with self.assertRaises(ValueError):gate.held_job_binding(job,self.transition)

    def test_get_only_transport_rejects_every_write_before_network(self):
        with patch.object(dmaap.Transport,'__init__',return_value=None),patch.object(dmaap.Transport,'request') as call:
            transport=gate.ReadOnlyTransport(None,None,None)
            for method in ('POST','PUT','PATCH','DELETE'):
                with self.assertRaises(ValueError):transport.request(method,'/webapi/dmaap',{})
            with self.assertRaises(ValueError):transport.request('GET','/webapi/dmaap',{})
            call.assert_not_called();transport.request('GET','/webapi/dmaap');call.assert_called_once()

    def audit_binding(self):
        return {'synthetic':True,'environment':{'slice_urn':'synthetic-slice'},
                'job_uid':'synthetic-job','job_spec_sha256':'synthetic-spec'}

    def prepare_review(self,age=0):
        gate.durable_write(self.review,{'schema':1,'created_utc':(datetime.now(timezone.utc)-timedelta(seconds=age)).isoformat(),
                                      'binding':self.audit_binding()})

    def accept(self,**kw):return gate.accept_completed(self.path,'synthetic-slice',self.review,**kw)

    def test_expired_review_and_preexisting_latch_rejected_before_audit(self):
        self.prepare_review(age=1801)
        with patch.object(gate,'completed_audit') as audit:
            with self.assertRaisesRegex(ValueError,'expired'):self.accept()
            audit.assert_not_called()
        self.review.unlink();self.prepare_review()
        gate.durable_write(self.parent/gate.POSTEXEC_LATCH,{})
        with patch.object(gate,'completed_audit') as audit:
            with self.assertRaisesRegex(ValueError,'already exists'):self.accept()
            audit.assert_not_called()

    def test_acceptance_is_exclusive_and_separate_and_readonly_verified(self):
        self.prepare_review();binding=self.audit_binding()
        with patch.object(gate,'completed_audit',return_value=binding), \
             patch.object(gate,'preserve_completed',return_value={'directory':'synthetic','ledger_sha256':'synthetic'}), \
             patch.object(gate,'kubectl') as mutate,patch.object(gate,'run_held') as run:
            receipt=self.accept()
            self.assertTrue((self.parent/gate.POSTEXEC_RECEIPT).is_file())
            self.assertFalse((self.parent/'dmaap-acceptance.json').exists())
            self.assertEqual(0o600,(self.parent/gate.POSTEXEC_RECEIPT).stat().st_mode&0o777)
            with self.assertRaisesRegex(ValueError,'no overwrite'):self.accept()
            self.assertEqual('completed-comparator-verification',receipt['kind'])
            with patch.object(gate,'archive_ledger',return_value='synthetic'):
                result=gate.verify_acceptance(self.path)
                self.assertEqual('uncertain',result['journal_state'])
                self.assertEqual('synthetic-job',result['job_uid'])
                # Acceptance remains valid after the issuance review's age window.
                self.assertEqual(result,gate.verify_acceptance(self.path))
            mutate.assert_not_called();run.assert_not_called()

    def test_verification_rechecks_receipt_review_latch_archive_and_live_state(self):
        self.prepare_review();binding=self.audit_binding()
        with patch.object(gate,'completed_audit',return_value=binding), \
             patch.object(gate,'preserve_completed',return_value={'directory':'synthetic','ledger_sha256':'synthetic'}), \
             patch.object(gate,'archive_ledger',return_value='synthetic'):
            self.accept();gate.verify_acceptance(self.path)
            for name in (self.review.name,gate.POSTEXEC_LATCH):
                filename=self.parent/name;original=filename.read_bytes();filename.write_bytes(b'{}')
                with self.assertRaises((ValueError,KeyError)):gate.verify_acceptance(self.path)
                filename.write_bytes(original)
            with patch.object(gate,'archive_ledger',return_value='different'):
                with self.assertRaises(ValueError):gate.verify_acceptance(self.path)
            with patch.object(gate,'completed_audit',return_value={'changed':True}):
                with self.assertRaises(ValueError):gate.verify_acceptance(self.path)
            filename=self.parent/gate.POSTEXEC_RECEIPT
            receipt=dmaap.strict_json(filename.read_bytes());receipt['accepted_utc']='2099-01-01T00:00:00Z'
            filename.write_bytes(dmaap.canonical(receipt))
            with self.assertRaises(ValueError):gate.verify_acceptance(self.path)

    def test_ordinary_acceptance_conflicts_with_completed_closeout(self):
        gate.durable_write(self.parent/'dmaap-acceptance.json',{})
        with patch.object(gate,'completed_postconditions') as check:
            with self.assertRaisesRegex(ValueError,'Conflicting'):gate.completed_audit(self.path,'slice')
            check.assert_not_called()

    def history_fixture(self):
        original=Path(self.temp.name)/'original';original.mkdir()
        gate.durable_write(original/'synthetic-proof.json',{'synthetic':True})
        gate.durable_write(original/'SHA256SUMS.json',{'synthetic-proof.json':gate.digest(original/'synthetic-proof.json')})
        self.transition.update(private_archive=str(original),binding_before={
            'code_sha256':{'bin/phase3-dmaap-recovery.py':gate.COMPARATOR_SOURCE_SHA256}})
        for name in ('dmaap-armed.json','dmaap-attempt.json','dmaap-recovery-attempt.json'):
            gate.durable_write(self.parent/name,{'synthetic':True})
        gate.durable_write(self.parent/'dmaap-transition.json',self.transition)
        gate.durable_write(self.parent/'dmaap-blocked-synthetic.json',{
            'schema':1,'failure_type':'Blocked','reason':'Unreviewed Pod default',
            'application_replay_performed':False,'certificate_fault_cases_started':False})
        gate.durable_write(self.parent/'dmaap-stop-synthetic.json',{'journal_stopped':True,'job_suspended':True})
        archive=Path(self.temp.name)/'dmaap-closeout-synthetic';archive.mkdir()
        for filename in self.parent.iterdir():
            if filename.name!='context.json':(archive/filename.name).write_bytes(filename.read_bytes())
        for name,obj in (('job.json',self.job),('synthetic-pod.json',self.pod),('journal.json',self.journal)):
            gate.durable_write(archive/name,obj)
        log=b'2026-10-16T00:00:00Z DMAAP private postconditions verified; host acceptance remains required\n'
        (archive/'synthetic-pod-dmaap-provisioning-job.stdout').write_bytes(log)
        self.seal(archive)
        return archive,log

    def seal(self,archive):
        ledger=archive/'SHA256SUMS.json'
        if ledger.exists():ledger.unlink()
        gate.durable_write(ledger,{p.name:gate.digest(p) for p in archive.iterdir()})

    def history(self,log):
        with patch.object(gate.backend,'command',return_value=log),patch.object(gate,'kubectl') as mutate:
            result=gate.completed_history(self.path,self.job,self.pod,self.journal)
            mutate.assert_not_called();return result

    def test_original_comparator_failure_and_preserved_success_are_required(self):
        archive,log=self.history_fixture()
        self.assertEqual(str(archive),self.history(log)['directory'])
        filename=archive/'dmaap-blocked-synthetic.json'
        body=dmaap.strict_json(filename.read_bytes());body['reason']='different failure'
        filename.write_bytes(dmaap.canonical(body));self.seal(archive)
        with self.assertRaisesRegex(ValueError,'comparator failure changed'):self.history(log)

    def test_changed_log_and_unknown_failure_source_refused(self):
        archive,log=self.history_fixture()
        with self.assertRaisesRegex(ValueError,'log unavailable'):self.history(b'other')
        self.transition['binding_before']['code_sha256']['bin/phase3-dmaap-recovery.py']='unknown'
        (self.parent/'dmaap-transition.json').write_bytes(dmaap.canonical(self.transition))
        with self.assertRaisesRegex(ValueError,'inspected comparator'):self.history(log)

    def test_history_preserves_journal_and_attempt_bytes(self):
        archive,log=self.history_fixture();original=(archive/'journal.json').read_bytes()
        self.history(log);self.assertEqual(original,(archive/'journal.json').read_bytes())
        current=self.parent/'dmaap-attempt.json';current.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'attempt evidence changed'):self.history(log)

    def test_continuation_uses_separate_code_binding_without_rebasing(self):
        review={'binding':{'historical':True}};gate.durable_write(self.review,review)
        accepted={k:'current' for k in ('code_sha256','context_sha256','sms_receipts','operator','releases')}
        gate.durable_write(self.parent/'dmaap-transition.json',{'binding_before':review['binding']})
        gate.durable_write(self.parent/gate.POSTEXEC_RECEIPT,{'binding':{'environment':accepted}})
        gate.durable_write(self.parent/'onap-acceptance.json',{})
        history=(self.parent/'dmaap-transition.json').read_bytes()
        with patch.object(gate,'verify_acceptance',return_value={'acceptance_kind':'completed-comparator-verification'}), \
             patch.object(gate,'environment',return_value=({},accepted)) as env, \
             patch.object(gate,'get',return_value=self.job),patch.object(gate,'run_held') as writer:
            gate.continue_startup(self.path,'slice',self.review)
            env.assert_called_once_with(self.path,'slice',allow_transition=True,completed_job=self.job)
            writer.assert_not_called()
        self.assertEqual(history,(self.parent/'dmaap-transition.json').read_bytes())

    def test_changed_review_or_mid_accept_drift_never_writes_receipt(self):
        self.prepare_review()
        with patch.object(gate,'completed_audit',return_value={'different':True}):
            with self.assertRaisesRegex(ValueError,'bindings changed'):self.accept()
        self.assertFalse((self.parent/gate.POSTEXEC_LATCH).exists())
        with patch.object(gate,'completed_audit',side_effect=[self.audit_binding(),{'different':True}]), \
             patch.object(gate,'preserve_completed',return_value={}):
            with self.assertRaisesRegex(ValueError,'before acceptance'):self.accept()
        self.assertTrue((self.parent/gate.POSTEXEC_LATCH).exists())
        self.assertFalse((self.parent/gate.POSTEXEC_RECEIPT).exists())

    def test_preservation_failure_retains_latch_and_never_retries(self):
        self.prepare_review()
        with patch.object(gate,'completed_audit',return_value=self.audit_binding()), \
             patch.object(gate,'preserve_completed',side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):self.accept()
        self.assertTrue((self.parent/gate.POSTEXEC_LATCH).exists())
        self.assertFalse((self.parent/gate.POSTEXEC_RECEIPT).exists())

    def test_code_transition_only_allows_reviewed_verifiers(self):
        before={'code_sha256':{'bin/phase3-dmaap-recovery.py':'old','bin/phase3-dmaap-client.py':'same'},
                **{k:'same' for k in ('context_sha256','slice_urn','sms_receipts','operator','releases')}}
        after=copy.deepcopy(before);after['code_sha256']['bin/phase3-dmaap-recovery.py']='new'
        self.assertEqual(['bin/phase3-dmaap-recovery.py'],list(gate.code_transition(before,after)))
        for key in ('context_sha256','sms_receipts','operator','releases'):
            changed=copy.deepcopy(after);changed[key]='different'
            with self.assertRaises(ValueError):gate.code_transition(before,changed)
        after['code_sha256']['bin/phase3-dmaap-client.py']='changed'
        with self.assertRaises(ValueError):gate.code_transition(before,after)

    def test_readiness_does_not_treat_boolean_as_held_acceptance(self):
        with self.assertRaises(ValueError):fresh.onap_errors([self.job],True,True)
        acceptance={'dmaap_accepted':True,'acceptance_kind':'completed-comparator-verification','job_suspended':True,
                    'job_uid':'synthetic-job','job_spec_sha256':gate.sha(self.job['spec'])}
        self.assertEqual(['Missing ONAP controller or Job inventory'],fresh.onap_errors([self.job],True,dmaap_acceptance=acceptance))
        for key,value in (('job_uid','other'),('job_spec_sha256','other'),('dmaap_accepted',False),('job_suspended',False)):
            bad=dict(acceptance,**{key:value})
            with self.assertRaises(ValueError):fresh.onap_errors([self.job],True,dmaap_acceptance=bad)
        unrelated=copy.deepcopy(self.job);unrelated['metadata']['name']='unrelated-synthetic-job'
        with self.assertRaisesRegex(ValueError,'held without exact'):
            fresh.onap_errors([unrelated],True,dmaap_acceptance=acceptance)

    def test_private_ledger_rejects_tampering_and_symlinks(self):
        archive=Path(self.temp.name)/'archive';archive.mkdir();gate.durable_write(archive/'evidence.json',{'synthetic':1})
        gate.durable_write(archive/'SHA256SUMS.json',{'evidence.json':gate.digest(archive/'evidence.json')})
        gate.archive_ledger(archive)
        (archive/'evidence.json').write_text('{}')
        with self.assertRaises(ValueError):gate.archive_ledger(archive)
        (archive/'evidence.json').unlink();(archive/'evidence.json').symlink_to(self.path)
        with self.assertRaises(ValueError):gate.archive_ledger(archive)


if __name__=='__main__':unittest.main()
