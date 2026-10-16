import copy
from datetime import datetime,timedelta,timezone
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch,Mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import phase3_oru_readiness as policy
spec=importlib.util.spec_from_file_location('oru_gate_tests',ROOT/'tools/phase3-oru-readiness.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)


def targets():
    return [{'container':n,'pod_uid':'pod-'+n,'replicaset':'onap-'+n+'-synthetic',
             'replicaset_uid':'rs-'+n,'deployment':'onap-'+n,'deployment_uid':'dep-'+n,
             'deployment_spec_sha256':policy.sha({'replicas':1})} for n in policy.TARGETS]


def pod():
    return {'metadata':{'name':'synthetic-pod','uid':'synthetic-pod','namespace':'nonrtric'},
        'spec':{'serviceAccountName':policy.SA,'initContainers':[
            {'name':'oru-app-cert-initializer-readiness','image':policy.IMAGE,
             'command':['/phase3-helpers/phase3-readiness-wrapper.py'],'args':policy.ARGS,
             'env':[{'name':'NAMESPACE','value':'onap'}]}, {'name':'oru-app-aaf-config'}]},
        'status':{'initContainerStatuses':[
            {'name':'oru-app-cert-initializer-readiness','restartCount':0,'lastState':{},'state':{'running':{}}},
            {'name':'oru-app-aaf-config','restartCount':0,'lastState':{},'state':{'waiting':{}}}],
            'containerStatuses':[{'name':'oru-app','restartCount':0,'state':{'waiting':{}}}]}}


class ContractTests(unittest.TestCase):
    def test_grant_is_exact_namespace_subject_and_least_privilege(self):
        role,binding=policy.resources(targets())
        self.assertEqual('onap',role['metadata']['namespace'])
        self.assertEqual([{'kind':'ServiceAccount','name':policy.SA,'namespace':'nonrtric'}],binding['subjects'])
        self.assertEqual({'apiGroups':[''],'resources':['pods'],'verbs':['list']},role['rules'][0])
        self.assertEqual(['replicasets/status'],role['rules'][1]['resources'])
        self.assertEqual(['get'],role['rules'][1]['verbs']);self.assertEqual(3,len(role['rules'][1]['resourceNames']))
        self.assertEqual(['deployments'],role['rules'][2]['resources'])
        self.assertEqual(['onap-'+n for n in sorted(policy.TARGETS)],role['rules'][2]['resourceNames'])
        self.assertNotIn('*',str(role));self.assertNotIn('secrets',str(role));self.assertNotIn('ClusterRole',str(binding))

    def test_role_rule_subject_and_uid_contracts_fail_closed(self):
        role,binding=policy.resources(targets())
        for expected in (role,binding):
            actual=copy.deepcopy(expected);actual['metadata']['uid']='synthetic'
            self.assertEqual('synthetic',policy.check_resource(actual,expected)['uid'])
            if expected['kind']=='Role':actual['rules'][0]['verbs'].append('get')
            else:actual['subjects'][0]['namespace']='other'
            with self.assertRaises(ValueError):policy.check_resource(actual,expected)

    def test_targets_must_be_three_exact_aaf_deployments(self):
        for bad in ([],targets()[:2],list(reversed(targets()))):
            with self.assertRaises(ValueError):policy.resources(bad)
        bad=targets();bad[0]['deployment']='unrelated'
        with self.assertRaises(ValueError):policy.resources(bad)

    def test_dependency_owner_chain_and_readiness(self):
        pods=[];sets=[];deps=[]
        for t in targets():
            pods.append({'metadata':{'name':'p','uid':t['pod_uid'],'ownerReferences':[
                {'kind':'ReplicaSet','name':t['replicaset'],'uid':t['replicaset_uid'],'controller':True}]},
                'spec':{'containers':[{'name':t['container']}]},'status':{'conditions':[{'type':'Ready','status':'True'}]}})
            sets.append({'metadata':{'name':t['replicaset'],'uid':t['replicaset_uid'],'ownerReferences':[
                {'kind':'Deployment','name':t['deployment'],'uid':t['deployment_uid'],'controller':True}]}})
            deps.append({'metadata':{'name':t['deployment'],'uid':t['deployment_uid'],'generation':1},
                         'spec':{'replicas':1},'status':{'observedGeneration':1,'readyReplicas':1,'updatedReplicas':1}})
        self.assertEqual(targets(),policy.dependencies(pods,sets,deps))
        with self.assertRaises(ValueError):policy.dependencies(pods+pods[:1],sets,deps)
        sets[0]['metadata']['uid']='changed'
        with self.assertRaises(ValueError):policy.dependencies(pods,sets,deps)

    def test_agent_and_main_unattempted_required(self):
        p=pod();p['status']['initContainerStatuses'][0]['state']={'running':{'startedAt':'synthetic'}}
        p['status']['initContainerStatuses'][1]['state']={'waiting':{'reason':'PodInitializing'}}
        policy.check_pod(p,unattempted=True)
        for index in (0,1):
            bad=copy.deepcopy(p);bad['status']['initContainerStatuses'][index]['restartCount']=1
            with self.assertRaises(ValueError):policy.check_pod(bad,unattempted=True)
        bad=copy.deepcopy(p);bad['status']['containerStatuses'][0]['imageID']='executed'
        with self.assertRaises(ValueError):policy.check_pod(bad,unattempted=True)

    def test_explicit_readiness_restart_count_does_not_allow_agent_restart(self):
        p=pod();p['status']['initContainerStatuses'][0]['restartCount']=2
        p['status']['initContainerStatuses'][0]['lastState']={'terminated':{'exitCode':1}}
        policy.check_pod(p,readiness_restarts=2)
        with self.assertRaises(ValueError):policy.check_pod(p,readiness_restarts=1)
        p['status']['initContainerStatuses'][1]['restartCount']=1
        with self.assertRaises(ValueError):policy.check_pod(p,readiness_restarts=2)

    def test_source_arguments_namespace_image_and_pod_drift_refused(self):
        for change in ('args','image','namespace','uid'):
            p=pod()
            if change=='args':p['spec']['initContainers'][0]['args']=[]
            if change=='image':p['spec']['initContainers'][0]['image']='other'
            if change=='namespace':p['spec']['initContainers'][0]['env'][0]['value']='other'
            if change=='uid':p['metadata']['uid']='other'
            with self.assertRaises(ValueError):policy.check_pod(p,expected_uid='synthetic-pod')

    def test_failed_agent_is_not_retried(self):
        p=pod();p['status']['initContainerStatuses'][1]['state']={'terminated':{'exitCode':1}}
        with self.assertRaisesRegex(ValueError,'initializer failed'):policy.check_pod(p)

    def test_manifest_identity_and_write_hooks_never_authorize_replay(self):
        manifest=[{'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'synthetic'},'spec':{'template':{}}}]
        policy.identical_manifests(manifest,copy.deepcopy(manifest))
        bad=copy.deepcopy(manifest);bad[0]['spec']['template']['changed']=True
        with self.assertRaises(ValueError):policy.identical_manifests(manifest,bad)
        with self.assertRaises(ValueError):policy.manifest_map(manifest+manifest)
        for kind in ('Job','CronJob'):
            with self.assertRaises(ValueError):policy.manifest_map([{'apiVersion':'batch/v1','kind':kind,'metadata':{'name':'synthetic'}}])

    def test_retained_and_invalid_contexts_cannot_enter_fresh(self):
        for value in (None,False,True,0,2,'1',1.0):
            with self.assertRaises(ValueError):policy.fresh_contract({'oru_readiness_contract':value})
        policy.fresh_contract({'oru_readiness_contract':1})


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'context.json';gate.write(self.path,{})
        self.review=Path(self.temp.name)/'review.json'

    def review_at(self,age=0):
        gate.write(self.review,{'schema':1,'created_utc':(datetime.now(timezone.utc)-timedelta(seconds=age)).isoformat(),
                               'binding':{'synthetic':True,'readiness_history':[]}})

    def test_expired_review_and_latch_stop_before_reads_or_creates(self):
        self.review_at(1801)
        with patch.object(gate,'review_binding') as read:
            with self.assertRaisesRegex(ValueError,'expired'):gate.apply(None,self.path,'slice',self.review,False)
            read.assert_not_called()
        self.review.unlink();self.review_at();gate.write(self.path.parent/(gate.PREFIX+'attempt.json'),{})
        with patch.object(gate,'review_binding') as read:
            with self.assertRaisesRegex(ValueError,'latch'):gate.apply(None,self.path,'slice',self.review,False)
            read.assert_not_called()

    def test_binding_drift_before_mutation(self):
        self.review_at()
        with patch.object(gate,'review_binding',return_value={'changed':True,'readiness_history':[]}),patch.object(gate,'command') as call:
            with self.assertRaisesRegex(ValueError,'binding changed'):gate.apply(None,self.path,'slice',self.review,False)
            call.assert_not_called()

    def test_history_requires_complete_immutable_archives(self):
        a={'x':1,'readiness_history':[{'directory':'synthetic'}]}
        b={'x':1,'readiness_history':[{'directory':'equivalent'}]}
        with patch.object(gate,'verify_archive') as check:gate.check_history_binding(a,b);check.assert_called_once()
        with self.assertRaises(ValueError):gate.check_history_binding({'x':1,'readiness_history':[]},{'x':2,'readiness_history':[]})

    def test_actual_subject_positive_and_negative_checks(self):
        def result(args,**kwargs):
            denied=('secrets' in args or 'create' in args or 'kube-system' in args)
            return Mock(returncode=1 if denied else 0,stdout=b'no\n' if denied else b'yes\n')
        with patch.object(gate.subprocess,'run',side_effect=result) as run:
            gate.probe_identity({'targets':targets()})
            self.assertEqual(11,run.call_count)
            self.assertTrue(all('--as=system:serviceaccount:nonrtric:'+policy.SA in x.args[0] for x in run.call_args_list))
        with patch.object(gate.subprocess,'run',return_value=Mock(returncode=0,stdout=b'yes\n')):
            with self.assertRaises(ValueError):gate.probe_identity({'targets':targets()})

    def test_no_implicit_historical_checkout_upgrade(self):
        with patch.object(gate,'command',return_value=b'other\n'):
            with self.assertRaisesRegex(ValueError,'exact pin'):gate.accepted_checkout('/synthetic')

    def test_fresh_integration_precedes_nonrtric_and_verifies_after(self):
        text=(ROOT/'setup-oran-smo.sh').read_text()
        gate_at=text.index('phase3-oru-readiness.py" fresh')
        self.assertGreater(gate_at,text.index('phase3-fresh-start.py" wait-onap'))
        self.assertLess(gate_at,text.index('helm upgrade --install oran-nonrtric'))
        self.assertLess(text.index('phase3-oru-readiness.py" verify-fresh'),text.index('helm upgrade --install oran-simulator'))
        self.assertIn("'oru_readiness_contract':1",(ROOT/'bin/phase3-fresh-start.py').read_text())

    def test_continuation_has_no_force_uninstall_or_replay(self):
        import inspect
        source=inspect.getsource(gate.continue_startup)
        for forbidden in ('--force','--atomic','uninstall','setup-driver.sh','run_held','--run-fresh'):
            self.assertNotIn(forbidden,source)
        self.assertIn("'--no-hooks'",source);self.assertIn("'--require-ready'",source)

    def test_verification_is_readonly_and_identity_is_explicit(self):
        import inspect
        source=inspect.getsource(gate.verify_fresh)
        self.assertIn('elif bind_identity:write(identity,expected)',source)
        self.assertIn('identity acceptance missing',source)


if __name__=='__main__':unittest.main()
