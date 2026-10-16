import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'bin'),str(ROOT/'tools')]
import phase3_dmaap as dmaap
from Phase3DmaapFixture import Journal, State, plan


class DmaapTests(unittest.TestCase):
    def test_input_inventory_and_relationships(self):
        p=plan();self.assertEqual(p,dmaap.validate_plan(p))
        for change in ('extra','wrong-order','extra-field','wrong-location','duplicate-action'):
            p=plan()
            if change=='extra': p.append(copy.deepcopy(p[-1]))
            if change=='wrong-order': p[0],p[1]=p[1],p[0]
            if change=='extra-field': p[0]['body']['extra']='unreviewed'
            if change=='wrong-location': p[5]['body']['clients'][0]['dcaeLocationName']='other'
            if change=='duplicate-action': p[5]['body']['clients'][0]['action']=['pub','pub']
            with self.assertRaises(ValueError):dmaap.validate_plan(p)

    def test_positive_six_posts_each_preceded_by_intent(self):
        state,journal=State(),Journal({'fixture':True})
        result=dmaap.execute(plan(),state,journal,{'fixture':True},'fixture-pod')
        self.assertEqual('verified',result['state'])
        self.assertEqual(6,len([r for r in state.requests if r[0]=='POST']))
        self.assertEqual(list(range(6)),[j['operation'] for j in journal.history if j['state']=='intent'])
        dmaap.verify_values(plan(),state)
        old=copy.deepcopy(state.requests)
        with self.assertRaises(ValueError):dmaap.execute(plan(),state,journal,{'fixture':True},'another-pod')
        self.assertEqual(old,state.requests)

    def test_failures_never_retry_or_continue(self):
        for fault in ('conflict','server-error','redirect','malformed','lost-response','read-drift'):
            state,journal=State(fault),Journal({})
            with self.assertRaises(Exception):dmaap.execute(plan(),state,journal,{},'pod')
            self.assertEqual(1,len([r for r in state.requests if r[0]=='POST']),fault)
            self.assertEqual('uncertain',journal.record['state'])
            before=copy.deepcopy(state.requests)
            with self.assertRaises(ValueError):dmaap.execute(plan(),state,journal,{},'pod')
            self.assertEqual(before,state.requests)

    def test_nonempty_or_unknown_default_refused_before_post(self):
        for route in ('dmaap',*dmaap.COLLECTIONS):
            state,journal=State(),Journal({})
            if route=='dmaap': state.data[route]['version']='1'
            else: state.data[route].append({'existing':True})
            with self.assertRaises(ValueError):dmaap.execute(plan(),state,journal,{},'pod')
            self.assertFalse(any(m=='POST' for m,p in state.requests))

    def test_global_client_extras_drift_and_duplicates_refused(self):
        for fault in ('extra','drift','duplicate'):
            state,journal=State(),Journal({})
            dmaap.execute(plan(),state,journal,{},'pod')
            if fault=='extra':state.data['mr_clients'].append({'extra':True})
            if fault=='drift':state.data['mr_clients'][0]['action']=['view']
            if fault=='duplicate':state.data['topics'][0]['clients'][0]['mrClientId']=state.data['topics'][1]['clients'][0]['mrClientId']
            with self.assertRaises(ValueError):dmaap.verify_values(plan(),state)

    def test_partial_progress_is_not_reconciled(self):
        state,journal=State(),Journal({})
        dmaap.execute(plan(),state,journal,{},'pod')
        before=copy.deepcopy(state.requests)
        with self.assertRaises(ValueError):dmaap.execute(plan(),state,Journal({}),{},'new-pod')
        self.assertFalse(any(m=='POST' for m,p in state.requests[len(before):]))

    def test_unordered_relationship_comparison_requires_bijection(self):
        self.assertTrue(dmaap.matches([{'a':1},{'a':2}],[{'a':2,'b':0},{'a':1}]))
        self.assertFalse(dmaap.matches([{'a':1},{'a':1}],[{'a':1},{'a':2}]))
        self.assertFalse(dmaap.matches(False,0))

    def test_only_version_qualified_topic_boolean_string_is_normalized(self):
        body=plan()[3]['body']
        actual=copy.deepcopy(body);actual.update(status='VALID',statusValid=True,tnxEnabled='false')
        dmaap.check_record(body,actual)
        for invalid in ('False','0',0,False,None):
            actual['tnxEnabled']=invalid
            with self.assertRaises(ValueError):dmaap.check_record(body,actual)

    def test_held_job_scoped_identity_and_no_backoff(self):
        stock={'kind':'Job','metadata':{'name':dmaap.JOB},'spec':{'template':{
            'metadata':{'labels':{'app':'dmaap-bc','release':'onap'}},'spec':{'containers':[{
            'name':'dmaap-provisioning-job','image':'nexus3.onap.org:10001/onap/dmaap/dbc-client:1.0.9'}]}}}}
        job=dmaap.patch_job(stock)
        self.assertTrue(job['spec']['suspend']);self.assertEqual(0,job['spec']['backoffLimit'])
        self.assertEqual(600,job['spec']['activeDeadlineSeconds'])
        pod=job['spec']['template']['spec']
        self.assertEqual('Never',pod['restartPolicy']);self.assertNotIn('initContainers',pod)
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(dmaap.COMMAND,pod['containers'][0]['command'])
        self.assertEqual([dmaap.JOURNAL],dmaap.resources()[1]['rules'][0]['resourceNames'])
        self.assertEqual(['get','update'],dmaap.resources()[1]['rules'][0]['verbs'])
        self.assertNotIn('Authorization',dmaap.helper_config()['data']['phase3_dmaap.py'].split('CONTRACT =')[0])


if __name__=='__main__':unittest.main()
