import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import phase3_dmaap as dmaap
import phase3_fresh as overlay
spec=importlib.util.spec_from_file_location('dmaap_integration_fresh',ROOT/'bin/phase3-fresh-start.py')
fresh=importlib.util.module_from_spec(spec);spec.loader.exec_module(fresh)


def stock():
    return {'kind':'Job','metadata':{'name':dmaap.JOB,'namespace':'onap'},'spec':{'template':{
        'metadata':{'labels':{'app.kubernetes.io/name':'dmaap-bc','app.kubernetes.io/instance':'onap'}},
        'spec':{'restartPolicy':'Never','containers':[{'name':'dmaap-provisioning-job',
            'image':'nexus3.onap.org:10001/onap/dmaap/dbc-client:1.0.9'}]}}}}


class IntegrationTests(unittest.TestCase):
    def test_only_new_context_selects_held_guarded_client(self):
        context={'schema':1,'baseline':'fresh-isolated-lab-pki','pki_directory':'/synthetic','root_sha256':'root'}
        with patch.object(overlay,'trust_config',return_value={}):
            legacy=overlay.overlay([stock()],context)[0]
            self.assertFalse(dmaap.is_client(legacy['spec']['template']['spec']['containers'][0]))
            context['dmaap_contract']=1
            guarded=overlay.overlay([stock()],context)[0]
        self.assertEqual(dmaap.patch_job(stock()),guarded)
        self.assertTrue(guarded['spec']['suspend'])
        self.assertTrue(dmaap.is_client(guarded['spec']['template']['spec']['containers'][0]))

    def test_unknown_contract_rejected_before_external_or_trust_calls(self):
        for version in (0,2,None,'1',True,1.0,[],{}):
            context={'schema':1,'baseline':'fresh-isolated-lab-pki','dmaap_contract':version}
            with patch.object(overlay,'trust_config') as trust:
                with self.assertRaisesRegex(ValueError,'DMAAP contract'):overlay.overlay([],context)
                trust.assert_not_called()

    def test_complete_without_independent_dmaap_acceptance_fails(self):
        job=dmaap.patch_job(stock());job['spec']['suspend']=False
        job['status']={'conditions':[{'type':'Complete','status':'True'}]}
        with self.assertRaisesRegex(ValueError,'Complete alone'):
            fresh.onap_errors([job],True)
        self.assertEqual(['Missing ONAP controller or Job inventory'],fresh.onap_errors([job],True,True))
        job['spec']['backoffLimit']=1
        with self.assertRaises(ValueError):fresh.onap_errors([job],True,True)

    def test_new_startup_orders_backend_then_sms_then_dmaap_then_onap(self):
        text=(ROOT/'setup-oran-smo.sh').read_text()
        self.assertLess(text.index('phase3-sms-backend.py" wait-fresh'),text.index('phase3-sms-preload.py" run-fresh'))
        self.assertLess(text.index('phase3-sms-preload.py" run-fresh'),text.index('phase3-dmaap-recovery.py" --run-fresh'))
        self.assertLess(text.index('phase3-dmaap-recovery.py" --run-fresh'),text.index('phase3-fresh-start.py" wait-onap'))

    def test_stale_qualification_refused(self):
        for record in ({},{'schema':1,'passed':True,'contract':1}):
            with self.assertRaises(ValueError):dmaap.require_qualification(record)


if __name__=='__main__':unittest.main()
