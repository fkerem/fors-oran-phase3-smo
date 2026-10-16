import copy
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
import phase3_sms_backend as backend
from phase3_fresh import overlay


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'bin'/filename)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


gate=module('backend_gate_tests','phase3-sms-backend.py')
fresh=module('backend_fresh_tests','phase3-fresh-start.py')


def quorum():
    return {'kind':'StatefulSet','metadata':{'name':backend.QUORUM,'namespace':'onap'},'spec':{
        'replicas':3,'selector':{'matchLabels':{'app':'aaf-sms-quorumclient'}},
        'volumeClaimTemplates':[{'metadata':{'name':'existing-data'}}],
        'template':{'spec':{'containers':[{'name':'aaf-sms-quorumclient','image':backend.QUORUM_TAG,
            'command':['/quorumclient/bin/quorumclient'],'workingDir':'/quorumclient/',
            'volumeMounts':[{'mountPath':'/quorumclient/config.json','name':'aaf-sms-quorumclient','subPath':'config.json'},
                {'name':'existing-data','mountPath':'/quorumclient/auth'}]}],
            'volumes':[{'name':'aaf-sms-quorumclient','configMap':{'name':backend.QUORUM}}]}}}}


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name);(self.path/'root.cer').write_text('public root fixture')
        for n in ('intermediate.cer','truststoreONAPall.jks','truststoreONAP.p12'):(self.path/n).write_text('public fixture')
        self.context={'schema':1,'baseline':'fresh-isolated-lab-pki','pki_directory':str(self.path),
                      'root_sha256':'a'*64,'sms_backend_contract':1}

    def test_separate_content_addressed_immutable_public_config(self):
        cm=backend.config(self.context)
        self.assertTrue(cm['immutable']);self.assertEqual({'root.cer','config.json'},set(cm['data']))
        settings=json.loads(cm['data']['config.json'])
        self.assertEqual(backend.CA_PATH,settings.pop('cafile'))
        expected=backend.STOCK_CONFIG.copy();expected.pop('cafile')
        self.assertEqual(expected,settings)
        self.assertNotIn('disable_tls',settings)
        (self.path/'root.cer').write_text('new public root')
        self.assertNotEqual(cm['metadata']['name'],backend.config(self.context)['metadata']['name'])

    def test_quorum_patch_changes_only_image_and_public_config_mounts(self):
        original=quorum();result=backend.patch(original,self.context)
        self.assertEqual(original['spec']['selector'],result['spec']['selector'])
        self.assertEqual(original['spec']['volumeClaimTemplates'],result['spec']['volumeClaimTemplates'])
        pod=result['spec']['template']['spec'];container=pod['containers'][0]
        self.assertEqual(backend.QUORUM_IMAGE,container['image'])
        self.assertEqual(original['spec']['template']['spec']['containers'][0]['command'],container['command'])
        self.assertEqual(backend.config(self.context)['metadata']['name'],pod['volumes'][0]['configMap']['name'])
        self.assertTrue(container['volumeMounts'][-1]['readOnly'])
        self.assertEqual(original,quorum())

    def test_retained_context_does_not_change_quorum_or_helper_identity(self):
        context=dict(self.context);context.pop('sms_backend_contract')
        self.assertEqual(quorum(),backend.patch(quorum(),context))
        self.assertEqual(quorum(),overlay([quorum()],context)[0])
        from phase3_fresh import helper_config
        self.assertEqual({'phase3-readiness-wrapper.py','phase3-aaf-bootstrap.sh'},set(helper_config('onap')['data']))

    def test_unexpected_quorum_runtime_or_mounts_are_not_adopted(self):
        for mode in ('image','entrypoint','replicas','namespace','config','mount','collision'):
            obj=quorum();pod=obj['spec']['template']['spec'];c=pod['containers'][0]
            if mode=='image':c['image']='mutable:latest'
            elif mode=='entrypoint':c['command']=['different']
            elif mode=='replicas':obj['spec']['replicas']=2
            elif mode=='namespace':obj['metadata']['namespace']='other'
            elif mode=='config':pod['volumes'][0]['configMap']['name']='different'
            elif mode=='mount':c['volumeMounts'][0]['subPath']='different'
            else:pod['volumes'].append({'name':'phase3-sms-backend'})
            with self.assertRaises(ValueError):backend.patch(obj,self.context)

    def test_stock_config_must_be_exact_before_fresh_patch(self):
        cm={'kind':'ConfigMap','metadata':{'name':backend.QUORUM},'data':{'config.json':json.dumps(backend.STOCK_CONFIG)}}
        backend.check_stock_config(cm)
        for changed in ({'disable_tls':True},{'url':'http://other'},{'timeout':'1s'}):
            obj=copy.deepcopy(cm);obj['data']['config.json']=json.dumps(dict(backend.STOCK_CONFIG,**changed))
            with self.assertRaises(ValueError):backend.check_stock_config(obj)

    def test_vault_and_consul_exact_pins_preserve_other_fields(self):
        obj={'kind':'StatefulSet','metadata':{'name':backend.VAULT},'spec':{'replicas':1,'template':{'spec':{
            'containers':[{'name':'aaf-sms-vault','image':'docker.io/library/vault:1.3.3','args':['server']},
                {'name':'aaf-sms-vault-backend','image':'docker.io/library/consul:1.7.1','args':['agent']}]}}}}
        result=backend.patch(obj,self.context)
        for c,image in zip(result['spec']['template']['spec']['containers'],(backend.VAULT_IMAGE,backend.CONSUL_IMAGE)):
            self.assertEqual(image,c['image'])
        self.assertEqual(['server'],result['spec']['template']['spec']['containers'][0]['args'])
        obj['spec']['template']['spec']['containers'][0]['image']='docker.io/library/vault:latest'
        with self.assertRaises(ValueError):backend.patch(obj,self.context)

    def test_seal_status_is_not_readiness(self):
        sealed={'version':'1.3.3','initialized':True,'sealed':True,'n':3,'t':3}
        self.assertTrue(backend.vault_status(sealed)['sealed'])
        self.assertFalse(backend.vault_status(dict(sealed,sealed=False))['sealed'])
        uninitialized=dict(sealed,initialized=False,n=0,t=0)
        self.assertFalse(backend.vault_status(uninitialized)['initialized'])
        for change in ({'version':'1.4.0'},{'n':1},{'t':1}):
            with self.assertRaises(ValueError):backend.vault_status(dict(sealed,**change))

    def test_readonly_listener_polling_never_masks_status_or_trust_errors(self):
        from types import SimpleNamespace
        with patch.object(gate.subprocess,'run',return_value=SimpleNamespace(returncode=1,stderr=b'connection refused')):
            with self.assertRaises(gate.Pending):gate.vault_observation('fixture')
        with patch.object(gate.subprocess,'run',return_value=SimpleNamespace(returncode=1,stderr=b'unexpected error')):
            with self.assertRaises(gate.Blocked):gate.vault_observation('fixture')

    def test_missing_empty_and_incomplete_custody_refused_before_crypto(self):
        with patch.object(backend,'decrypt_shard') as decrypt:
            for entries in ([],[{'files':{}}]*3,[{'files':{'id':b'x','pbkey':b'x','prkey':b'x','shard':b''}}]*3):
                with self.assertRaises(ValueError):backend.recovery_checks(entries)
            decrypt.assert_not_called()

    def test_fresh_refuses_retained_context_before_api_or_bootstrap(self):
        context=dict(self.context);context.pop('sms_backend_contract')
        fake=type('Fresh',(),{'verify_context':staticmethod(lambda *a:context)})
        with patch.object(gate.importlib.util,'module_from_spec',return_value=fake), \
             patch.object(gate.importlib.util,'spec_from_file_location') as spec,patch.object(gate,'snapshot') as read:
            spec.return_value.loader.exec_module=lambda m:None
            with self.assertRaisesRegex(gate.Blocked,'Retained/pre-existing'):gate.wait_fresh('/fixture/context.json',600)
            read.assert_not_called()

    def test_storage_probe_adds_sms_only_for_new_contexts(self):
        with patch.object(fresh,'run',return_value=b'{"paths":[]}') as run:
            fresh.storage_inspection('slice')
            self.assertNotIn('sms-backend-v1',run.call_args.args[0][-1])
            fresh.storage_inspection('slice',include_sms=True)
            self.assertIn('sms-backend-v1',run.call_args.args[0][-1])
        for segment in ('sms/','consul/data-0','quorum/data-2'):self.assertIn(segment,fresh.STORAGE_INSPECTION)

    def test_no_existing_context_acceptance_or_application_write_interface(self):
        (self.path/'context.json').write_text('{"schema":1}')
        with patch.object(gate,'snapshot') as snapshot:
            self.assertIsNone(gate.verify_acceptance(self.path/'context.json'));snapshot.assert_not_called()
        source=inspect.getsource(gate)
        self.assertNotIn("'DELETE'",source);self.assertNotIn("'PATCH'",source)
        self.assertNotIn('/v1/sys/init',source);self.assertNotIn('/v1/sys/unseal',source)
        self.assertNotIn("request('POST','/v1/sms",source)
        self.assertIn('sms-backend-first-use-attempt.json',source)
        self.assertIn('attempt_path.exists()',source)

    def test_vault_service_must_target_exact_ready_backend(self):
        service={'spec':{'clusterIP':'10.0.0.1','ports':[{'port':8200,'targetPort':8200}]}}
        endpoint={'targetRef':{'uid':'vault-uid'},'conditions':{'ready':True}}
        entry={'metadata':{'labels':{'kubernetes.io/service-name':'aaf-sms-db'}},'endpoints':[endpoint]}
        def get(kind):return service if kind.startswith('service/') else {'items':[entry]}
        with patch.object(gate,'get',side_effect=get):
            self.assertEqual('10.0.0.1',gate.backend_address('vault-uid'))
            with self.assertRaises(gate.Blocked):gate.backend_address('other-vault')
            endpoint['conditions']['ready']=False
            with self.assertRaises(gate.Blocked):gate.backend_address('vault-uid')

    def test_partial_qualification_receipt_never_sufficient(self):
        for record in ({},{'passed':True,'images':backend.IMAGES},
                {'schema':1,'passed':True,'images':backend.IMAGES,'live_api_contacted':False}):
            with self.assertRaises(ValueError):backend.require_qualification(record)

    def test_pending_pod_replacement_is_detected_before_ready_snapshot(self):
        context=dict(self.context,slice_urn='fixture',storage_preflight={
            'paths':[{'path':p,'empty':True} for p in backend.STORAGE_PATHS]})
        fake=type('Fresh',(),{'verify_context':staticmethod(lambda *a:context)})
        with patch.object(gate.importlib.util,'module_from_spec',return_value=fake), \
             patch.object(gate.importlib.util,'spec_from_file_location') as spec, \
             patch.object(gate,'operator_binding',return_value={}),patch.object(gate.time,'sleep'), \
             patch.object(gate,'snapshot',side_effect=[gate.Pending('pending',{'sms':'first'}),
                                                     gate.Pending('pending',{'sms':'second'})]):
            spec.return_value.loader.exec_module=lambda m:None
            with self.assertRaisesRegex(gate.Blocked,'Pod changed'):
                gate.wait_fresh(self.path/'context.json',600)

    def test_backend_gate_precedes_onap_acceptance_and_marker(self):
        source=(ROOT/'setup-oran-smo.sh').read_text()
        self.assertLess(source.index('phase3-sms-backend.py'),source.index('wait-onap'))
        self.assertLess(source.index('phase3-sms-backend.py'),source.index('touch "$OURDIR/setup-oran-smo-done"'))
        self.assertIn('gnupg',source)

    def test_window_accepts_only_stable_identity_trust_and_material(self):
        (self.path/'store-password').write_bytes(b'synthetic-only-hmac-key')
        for scenario in ('stable','slow-startup','pod-change','material-change','tls-change'):
            directory=self.path/scenario;directory.mkdir()
            context=dict(self.context,slice_urn='fixture-slice',storage_preflight={
                'paths':[{'path':p,'empty':True} for p in backend.STORAGE_PATHS]})
            path=directory/'context.json';path.write_text(json.dumps(context))
            fake=type('Fresh',(),{'verify_context':staticmethod(lambda *a:context)})
            record={'identity':{'pods':{'sms':'first',backend.VAULT+'-0':'vault-uid'}},'pods_ready_without_restarts':True,
                'vault':{'initialized':True,'sealed':False},'sms_backend_auth':{
                    'role':{'present':True},'secret':{'present':True}}}
            second=copy.deepcopy(record)
            if scenario=='pod-change':second['identity']['pods']['sms']='second'
            custody={'sets':3,'encrypted_material_binding_sha256':'first'}
            changed=dict(custody,encrypted_material_binding_sha256='second') if scenario=='material-change' else custody
            auth={'role':b'fixture-role','secret':b'fixture-secret'}
            tick=[0]
            def sleep(seconds):tick[0]+=601 if scenario=='slow-startup' and tick[0]==0 else 121
            def get(kind):
                return {'metadata':{'uid':'held'},'spec':{'suspend':True}} if kind.startswith('job/') else {'items':[]}
            with patch.object(gate.importlib.util,'module_from_spec',return_value=fake), \
                 patch.object(gate.importlib.util,'spec_from_file_location') as spec, \
                 patch.object(gate,'snapshot',side_effect=(
                     [gate.Pending('initializer running',record['identity']['pods'])] if scenario=='slow-startup' else [])
                     +[(record,({},)),(second,({},))]), \
                 patch.object(gate,'operator_binding',return_value={'uid':'operator'}), \
                 patch.object(gate,'verify_pins'),patch.object(gate,'get',side_effect=get), \
                 patch.object(gate,'tls',side_effect=[('leaf',{},None),('changed' if scenario=='tls-change' else 'leaf',{},None)]), \
                 patch.object(gate,'read_private_files',side_effect=[(custody,auth),(changed,auth)]), \
                 patch.object(gate,'role_probe',return_value={'application_writes':False}), \
                 patch.object(gate.time,'monotonic',side_effect=lambda:tick[0]),patch.object(gate.time,'sleep',side_effect=sleep):
                spec.return_value.loader.exec_module=lambda m:None
                if scenario in ('stable','slow-startup'):
                    result=gate.wait_fresh(path,600)
                    self.assertTrue(result['backend_accepted']);self.assertEqual(120,result['restart_free_seconds'])
                    self.assertFalse(result.get('preload_authorized',False))
                    self.assertTrue((directory/'sms-backend-acceptance.json').is_file())
                    self.assertEqual('handoff',result['timing']['phase'])
                    if scenario=='slow-startup':self.assertGreater(result['timing']['elapsed_seconds'],600)
                else:
                    with self.assertRaises(gate.Blocked):gate.wait_fresh(path,600)
                    self.assertFalse((directory/'sms-backend-acceptance.json').exists())


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.tick = 0
        self.clock = patch.object(gate.time,'monotonic',side_effect=lambda:self.tick)
        self.clock.start();self.addCleanup(self.clock.stop)

    def test_startup_has_its_own_deadline_and_phase_diagnostic(self):
        budget=gate.BootstrapBudget(1800,600)
        self.tick=1799;budget.check()
        self.tick=1800
        with self.assertRaisesRegex(gate.Blocked,'startup timed out') as error:budget.ready()
        self.assertEqual('startup',error.exception.timing['phase'])
        self.assertEqual(1800,error.exception.timing['elapsed_seconds'])

    def test_readiness_starts_handoff_once_without_resetting_it(self):
        budget=gate.BootstrapBudget(1800,600)
        self.tick=700;budget.ready()
        self.tick=1200;budget.ready()
        self.assertEqual(700,budget.handoff_start)
        self.tick=1300
        with self.assertRaisesRegex(gate.Blocked,'handoff timed out') as error:budget.check()
        self.assertEqual(600,error.exception.timing['handoff_elapsed_seconds'])

    def test_invalid_budgets_refused(self):
        for startup,handoff in ((0,600),(-1,600),(1800,0),(1800,120)):
            with self.assertRaises(gate.Blocked):gate.BootstrapBudget(startup,handoff)


if __name__=='__main__':unittest.main()
