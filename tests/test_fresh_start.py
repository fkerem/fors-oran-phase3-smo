import ast
import base64
import copy
import datetime as dt
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
from phase3_lab_pki import generate, secret, CONFIG_IMAGE, AGENT_IMAGE, SANS, inspect_pkcs12, PKCS12_PACKAGING
from phase3_fresh import overlay, helper_config, select_storage_node, READINESS_IMAGE


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/'bin'/path)
    result=importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


readiness=module('fresh_readiness','phase3-readiness-wrapper.py')
fresh=module('fresh_start','phase3-fresh-start.py')


class ReadinessPredicateTests(unittest.TestCase):
    def run_predicate(self,conditions,succeeded=1):
        # Execute the actual replacement body, not a second test implementation.
        body='def predicate(response):\n    complete=False\n    job_name="fixture"\n    if True:\n'+readiness.NEW+'\n    return complete\n'
        env={'log':NS(info=lambda *a:None)}
        exec(compile(body,'predicate','exec'),env)
        return env['predicate'](NS(status=NS(conditions=conditions,succeeded=succeeded)))

    def test_completed_condition_permutations(self):
        conditions=[NS(type='Suspended',status='False'),NS(type='SuccessCriteriaMet',status='True'),NS(type='Complete',status='True')]
        for permutation in itertools.permutations(conditions):
            self.assertTrue(self.run_predicate(permutation))

    def test_pending_false_failed_missing_and_suspended_are_not_complete(self):
        for conditions in (None,[],[NS(type='SuccessCriteriaMet',status='True')],
                [NS(type='Complete',status='False')],
                [NS(type='Complete',status='True'),NS(type='Failed',status='True')],
                [NS(type='Complete',status='True'),NS(type='Suspended',status='True')]):
            self.assertFalse(self.run_predicate(conditions))

    def test_more_than_one_successful_completion_is_supported(self):
        self.assertTrue(self.run_predicate([NS(type='Complete',status='True')],succeeded=2))

    def test_source_hash_and_exact_predicate_are_required(self):
        with self.assertRaises(ValueError):readiness.patched_source(b'changed source')
        blob=readiness.OLD.encode()
        with patch.object(readiness,'SOURCE_SHA256',hashlib.sha256(blob).hexdigest()):
            self.assertEqual(readiness.NEW,readiness.patched_source(blob))
        blob=(readiness.OLD+'\n'+readiness.OLD).encode()
        with patch.object(readiness,'SOURCE_SHA256',hashlib.sha256(blob).hexdigest()):
            with self.assertRaises(ValueError):readiness.patched_source(blob)


class PkiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(); cls.path=Path(cls.temp.name)/'pki'
        cls.record=generate(cls.path,'test-allocation')

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_valid_chain_constraints_and_service_identities(self):
        root,intermediate,leaf=[x509.load_pem_x509_certificate((self.path/(n+'.cer')).read_bytes()) for n in ('root','intermediate','server')]
        self.assertEqual(root.subject,intermediate.issuer)
        self.assertEqual(intermediate.subject,leaf.issuer)
        for parent,child in ((root,root),(root,intermediate),(intermediate,leaf)):
            from cryptography.hazmat.primitives.asymmetric import padding
            parent.public_key().verify(child.signature,child.tbs_certificate_bytes,padding.PKCS1v15(),child.signature_hash_algorithm)
        self.assertEqual(1,root.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length)
        self.assertEqual(0,intermediate.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length)
        self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(SANS,sorted(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)))
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH,leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        # OpenSSL independently verifies chain, purpose, and hostname.
        good=subprocess.run(['openssl','verify','-CAfile',str(self.path/'root.cer'),'-untrusted',str(self.path/'intermediate.cer'),
            '-verify_hostname','aaf-locate.onap',str(self.path/'server.cer')],capture_output=True)
        self.assertEqual(0,good.returncode,good.stderr)
        wrong=subprocess.run(['openssl','verify','-CAfile',str(self.path/'root.cer'),'-untrusted',str(self.path/'intermediate.cer'),
            '-verify_hostname','wrong.invalid',str(self.path/'server.cer')],capture_output=True)
        self.assertNotEqual(0,wrong.returncode)
        expired=subprocess.run(['openssl','verify','-CAfile',str(self.path/'root.cer'),'-untrusted',str(self.path/'intermediate.cer'),
            '-attime',str(int((dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=400)).timestamp())),str(self.path/'server.cer')],capture_output=True)
        self.assertNotEqual(0,expired.returncode)

    def test_private_permissions_and_no_regeneration(self):
        self.assertEqual(0o700,self.path.stat().st_mode&0o777)
        self.assertTrue(all(p.stat().st_mode&0o777==0o600 for p in self.path.iterdir()))
        before=(self.path/'root.cer').read_bytes()
        with self.assertRaises(ValueError):generate(self.path,'different-allocation')
        self.assertEqual(before,(self.path/'root.cer').read_bytes())

    def test_explicit_packaging_and_runtime_metadata(self):
        self.assertEqual(PKCS12_PACKAGING,self.record['pkcs12_packaging'])
        self.assertIn('cryptography_openssl',self.record['runtime'])
        for name in ('server.p12','signer.p12'):
            self.assertEqual(PKCS12_PACKAGING,inspect_pkcs12(self.path/name,self.path/'store-password'))
        with patch('phase3_lab_pki.subprocess.run',return_value=NS(returncode=0,stderr=b'MAC: sha256, Iteration 50000')):
            with self.assertRaises(ValueError):inspect_pkcs12(self.path/'server.p12',self.path/'store-password')

    def test_expired_intermediate_is_rejected_with_a_current_leaf(self):
        password=(self.path/'store-password').read_bytes()
        root=x509.load_pem_x509_certificate((self.path/'root.cer').read_bytes())
        root_key=serialization.load_pem_private_key((self.path/'root-private.key').read_bytes(),password)
        signer=pkcs12.load_pkcs12((self.path/'signer.p12').read_bytes(),password)
        now=dt.datetime.now(dt.timezone.utc)
        expired=(x509.CertificateBuilder().subject_name(signer.cert.certificate.subject).issuer_name(root.subject)
                 .public_key(signer.key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now-dt.timedelta(days=30)).not_valid_after(now-dt.timedelta(days=1))
                 .add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(root_key,hashes.SHA256()))
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'expired.cer'; path.write_bytes(expired.public_bytes(serialization.Encoding.PEM))
            result=subprocess.run(['openssl','verify','-CAfile',str(self.path/'root.cer'),'-untrusted',str(path),
                                   str(self.path/'server.cer')],capture_output=True)
            self.assertNotEqual(0,result.returncode)
            self.assertIn(b'expired',result.stderr)

    def test_untrusted_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            other=Path(temp)/'other'; generate(other,'other-allocation')
            result=subprocess.run(['openssl','verify','-CAfile',str(other/'root.cer'),'-untrusted',str(self.path/'intermediate.cer'),
                                   str(self.path/'server.cer')],capture_output=True)
            self.assertNotEqual(0,result.returncode)

    def test_aliases_and_signer_chain_are_loadable(self):
        password=(self.path/'store-password').read_bytes()
        for file,alias,length in [('server.p12',b'aaf@aaf.osaaf.org',2),('signer.p12',b'aaf_intermediate_9',1)]:
            data=pkcs12.load_pkcs12((self.path/file).read_bytes(),password)
            self.assertEqual(alias,data.cert.friendly_name)
            self.assertEqual(length,len(data.additional_certs))
            self.assertIsNotNone(data.key)
            with self.assertRaises(ValueError):pkcs12.load_pkcs12((self.path/file).read_bytes(),b'wrong')

    def test_secret_excludes_root_signing_key(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            for file in ('server.p12','signer.p12','store-password','root.cer','intermediate.cer','server.cer','truststoreONAPall.jks','truststoreONAP.p12'):
                (p/file).write_bytes(b'private-fixture')
            obj=secret(p,'onap','fixture')
            self.assertTrue(obj['immutable'])
            self.assertNotIn('root-private.key',obj['data'])
            self.assertEqual('onap',obj['metadata']['namespace'])


class FreshOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.pki=Path(self.temp.name)
        for f in ('truststoreONAPall.jks','truststoreONAP.p12'):(self.pki/f).write_bytes(b'public trust fixture')
        self.context={'schema':1,'baseline':'fresh-isolated-lab-pki','pki_directory':str(self.pki),
                      'root_sha256':'a'*64,'secret_name':'private-pki','storage_node':{'hostname':'node-2'}}

    def resource(self,kind='Deployment',name='onap-fixture',container=None):
        return {'apiVersion':'apps/v1','kind':kind,'metadata':{'name':name,'namespace':'onap'},
                'spec':{'replicas':1,'template':{'spec':{'initContainers':[container or {'name':'ready','image':READINESS_IMAGE,'command':['/app/ready.py','--job-name','dependency']}], 'containers':[{'name':'main','image':'pinned:1'}]}}}}

    def test_readiness_mount_is_read_only_and_arguments_preserved(self):
        original=self.resource(); changed=overlay([original],self.context)[0]
        pod=changed['spec']['template']['spec']; init=pod['initContainers'][0]
        self.assertEqual(['/phase3-helpers/phase3-readiness-wrapper.py','--job-name','dependency'],init['command'])
        self.assertTrue(init['volumeMounts'][0]['readOnly'])
        self.assertEqual(365,pod['volumes'][0]['configMap']['defaultMode'])
        self.assertEqual('/app/ready.py',original['spec']['template']['spec']['initContainers'][0]['command'][0])

    def test_unknown_readiness_or_server_contract_refuses(self):
        for c in ({'name':'ready','image':READINESS_IMAGE,'command':['different']},
                  {'name':'ready','image':'nexus3.onap.org:10001/onap/oom/readiness:3.0.2','command':['/app/ready.py']},
                  {'name':'server-config','image':CONFIG_IMAGE,'command':['changed']}):
            with self.assertRaises(ValueError):overlay([self.resource(container=c)],self.context)

    def test_server_only_receives_secret_during_init(self):
        doc=self.resource(container={'name':'server-config','image':CONFIG_IMAGE,'command':['/bin/bash'],
            'args':['-c','cd /opt/app/aaf_config\nbin/agent.sh\n']})
        pod=overlay([doc],self.context)[0]['spec']['template']['spec']
        self.assertTrue(any(v.get('secret',{}).get('secretName')=='private-pki' for v in pod['volumes']))
        self.assertNotIn('volumeMounts',pod['containers'][0])
        self.assertEqual(['/bin/bash','/phase3-helpers/phase3-aaf-bootstrap.sh'],pod['initContainers'][0]['command'])

    def test_client_must_mount_both_reviewed_truststores(self):
        with self.assertRaises(ValueError):overlay([self.resource(container={'name':'agent','image':AGENT_IMAGE})],self.context)

    def test_replaces_public_trust_only(self):
        doc={'kind':'ConfigMap','metadata':{'name':'onap-cert-wrapper-certs'},'data':{'truststoreONAPall.jks.b64':'old','truststoreONAP.p12.b64':'old','other':'retain'}}
        result=overlay([doc],self.context)[0]
        self.assertEqual('retain',result['data']['other'])
        self.assertEqual(b'public trust fixture',base64.b64decode(result['data']['truststoreONAPall.jks.b64']))

    def test_volume_and_owner_are_bound_to_same_new_worker(self):
        ss=self.resource('StatefulSet','onap-mariadb-galera')
        pv={'kind':'PersistentVolume','metadata':{'name':'onap-mariadb-galera--0'},'spec':{'hostPath':{'path':'/storage/nfs/deployment-1/onap/data'}}}
        ss,pv=overlay([ss,pv],self.context)
        self.assertEqual('node-2',ss['spec']['template']['spec']['nodeSelector']['kubernetes.io/hostname'])
        self.assertEqual(['node-2'],pv['spec']['nodeAffinity']['required']['nodeSelectorTerms'][0]['matchExpressions'][0]['values'])
        for altered in (self.resource('StatefulSet','onap-mariadb-galera'),):
            altered['spec']['replicas']=2
            with self.assertRaises(ValueError):overlay([altered],self.context)

    def test_unreviewed_pv_path_and_conflicting_placement_refuse(self):
        pv={'kind':'PersistentVolume','metadata':{'name':'onap-sdnrdb-master-pv-0'},'spec':{'hostPath':{'path':'/arbitrary'}}}
        with self.assertRaises(ValueError):overlay([pv],self.context)
        ss=self.resource('StatefulSet','onap-policy-mariadb'); ss['spec']['template']['spec']['nodeSelector']={'kubernetes.io/hostname':'node-0'}
        with self.assertRaises(ValueError):overlay([ss],self.context)

    def test_job_never_automatically_retries_and_unknown_context_fails(self):
        job=overlay([self.resource('Job')],self.context)[0]
        self.assertEqual(0,job['spec']['backoffLimit'])
        self.assertEqual('Never',job['spec']['template']['spec']['restartPolicy'])
        with self.assertRaises(ValueError):overlay([],{'schema':999})

    def test_helpers_are_content_addressed_and_immutable(self):
        cm=helper_config('onap'); self.assertTrue(cm['immutable'])
        self.assertEqual(cm['metadata']['name'],helper_config('network')['metadata']['name'])
        self.assertNotIn('PRIVATE KEY',json.dumps(cm))

    def test_new_storage_uid_and_schedulability_are_required(self):
        node={'metadata':{'name':'node-2','uid':'fresh-uid','labels':{'kubernetes.io/hostname':'node-2'}},
              'spec':{},'status':{'conditions':[{'type':'Ready','status':'True'}]}}
        self.assertEqual('fresh-uid',select_storage_node([node])['uid'])
        for change in ({'unschedulable':True},{'taints':[{'effect':'NoSchedule'}]}):
            altered=copy.deepcopy(node); altered['spec']=change
            with self.assertRaises(ValueError):select_storage_node([altered])
        with self.assertRaises(ValueError):select_storage_node([])

    def test_failed_job_stops_acceptance(self):
        bad={'kind':'Job','metadata':{'name':'bad'},'status':{'conditions':[{'type':'Failed','status':'True'}]}}
        with self.assertRaises(ValueError):fresh.onap_errors([bad])
        self.assertTrue(fresh.onap_errors([]))

    def test_renderer_requires_fresh_context(self):
        env=dict(os.environ); env.pop('PHASE3_FRESH_CONTEXT',None)
        result=subprocess.run([sys.executable,str(ROOT/'bin/phase3-fresh-renderer.py')],input='',text=True,capture_output=True,env=env)
        self.assertNotEqual(0,result.returncode)

    def test_storage_probe_checks_peer_identity_before_paths(self):
        self.assertLess(fresh.STORAGE_INSPECTION.index('actual!=sys.argv[1]'),fresh.STORAGE_INSPECTION.index('for value in paths'))
        self.assertIn('any(path.iterdir())',fresh.STORAGE_INSPECTION)
        self.assertNotIn('mkdir',fresh.STORAGE_INSPECTION)
        self.assertNotIn('unlink',fresh.STORAGE_INSPECTION)
        with patch.object(fresh,'run',return_value=b'{"paths":[]}' ) as command:
            fresh.storage_inspection('urn:publicid:IDN+emulab.net:p+slice+fresh')
            self.assertIn('node-2',command.call_args.args[0])
            self.assertNotIn('pc12-fort.emulab.net',' '.join(command.call_args.args[0]))


class KongFreshIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.pki = self.path/'pki'; self.pki.mkdir()
        for name in ('root.cer', 'intermediate.cer', 'truststoreONAPall.jks'):
            (self.pki/name).write_text('synthetic fixture')
        self.nodes = [{'metadata': {'name': 'node-'+str(i), 'uid': 'fresh-'+str(i),
                                   'labels': {'kubernetes.io/hostname': 'node-'+str(i)}},
                       'spec': {}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}} for i in range(3)]
        self.slice = 'urn:publicid:IDN+emulab.net:fixture+slice+new'
        receipt = b'{"root_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dmaap_rehearsal":{}}'
        (self.path/'rehearsal.json').write_bytes(receipt)
        self.context = {'schema': 1, 'baseline': 'fresh-isolated-lab-pki', 'slice_urn': self.slice,
                        'node_uids': {n['metadata']['name']: n['metadata']['uid'] for n in self.nodes},
                        'storage_node': select_storage_node(self.nodes), 'pki_directory': str(self.pki),
                        'secret_name': 'synthetic-pki', 'files_sha256': {},
                        'rehearsal_sha256': hashlib.sha256(receipt).hexdigest()}

    def test_verify_rejects_malformed_contract_before_external_checks(self):
        for value in (0, 2, -1, None, '1', True, False, 1.0, [], {}):
            with self.subTest(value=value):
                path = self.path/'context.json'
                path.write_text(json.dumps(dict(self.context, kong_proxy_contract=value)))
                with patch.object(fresh, 'run') as run, patch.object(fresh, 'cluster_nodes') as nodes, \
                        patch.object(fresh, 'kubectl') as kubectl:
                    with self.assertRaisesRegex(ValueError, 'Unreviewed Kong proxy contract'):
                        fresh.verify_context(path)
                run.assert_not_called(); nodes.assert_not_called(); kubectl.assert_not_called()

    def test_verify_accepts_integer_one_and_leaves_retained_context_absent(self):
        helper = {'metadata': {'name': 'fixture-helper'}, 'immutable': True, 'data': {}}
        for extra in ({}, {'kong_proxy_contract': 1}):
            with self.subTest(extra=extra):
                path = self.path/'context.json'
                context = dict(self.context, **extra)
                path.write_text(json.dumps(context)); original = path.read_bytes()
                with patch.object(fresh, 'run', return_value=self.slice.encode()) as run, \
                        patch.object(fresh, 'cluster_nodes', return_value=self.nodes), \
                        patch.object(fresh, 'helper_config', return_value=helper), \
                        patch.object(fresh, 'secret', return_value={'data': {}}), \
                        patch.object(fresh, 'kubectl', return_value=json.dumps(helper).encode()), \
                        patch.object(fresh, 'private_write') as write:
                    self.assertEqual(context, fresh.verify_context(path))
                run.assert_called_once_with(['geni-get', 'slice_urn'])
                write.assert_not_called()
                self.assertEqual(original, path.read_bytes())

    def test_prepare_sets_integer_contract_without_adding_resources(self):
        import phase3_dmaap
        import phase3_preload
        receipt = json.loads((self.path/'rehearsal.json').read_text())
        with patch.object(fresh, 'cluster_nodes', return_value=self.nodes), \
                patch.object(fresh, 'storage_inspection', return_value={'paths': []}), \
                patch.object(fresh, 'offline_rehearsal', return_value=receipt), \
                patch.object(phase3_dmaap, 'require_qualification'), \
                patch.object(fresh, 'assert_empty_onap'), \
                patch.object(fresh, 'kubectl', return_value=b'') as kubectl, \
                patch.object(fresh, 'secret', return_value={'kind': 'Secret', 'metadata': {'name': 'fixture-pki', 'namespace': 'onap'}}):
            context = fresh.prepare(self.path, self.slice)
        self.assertIs(type(context['kong_proxy_contract']), int)
        self.assertEqual(1, context['kong_proxy_contract'])
        self.assertEqual(context, json.loads((self.path/'context.json').read_text()))
        resources = [json.loads(call.kwargs['data']) for call in kubectl.call_args_list if 'data' in call.kwargs]
        expected = [helper_config(ns) for ns in ('onap', 'nonrtric', 'network')]
        expected += [{'kind': 'Secret', 'metadata': {'name': 'fixture-pki', 'namespace': 'onap'}},
                     fresh.phase3_ves.config(context), fresh.phase3_sms.config(context), fresh.phase3_sms_backend.config(context),
                     phase3_preload.helper_config(), *phase3_preload.resources(context),
                     phase3_dmaap.helper_config(), *phase3_dmaap.resources()]
        self.assertEqual(expected, resources)
        self.assertEqual([('create', 'namespace', ns) for ns in ('onap', 'nonrtric', 'network')],
                         [call.args for call in kubectl.call_args_list if call.args[:2] == ('create', 'namespace')])

    def test_setup_orders_kong_verification_between_oru_and_simulators(self):
        source = (ROOT/'setup-oran-smo.sh').read_text()
        oru = source.index('phase3-oru-readiness.py" verify-fresh')
        kong = source.index('phase3-kong-proxy.py" verify-fresh')
        nts = source.index('helm upgrade --install oran-simulator')
        self.assertLess(oru, kong); self.assertLess(kong, nts)
        self.assertEqual(1, source.count('phase3-kong-proxy.py'))

    def run_setup_gate(self, contract, status=0):
        source = (ROOT/'setup-oran-smo.sh').read_text()
        oru = source.index('phase3-oru-readiness.py" verify-fresh')
        gate = source[source.index('if python3 - "$PHASE3_FRESH_CONTEXT"', oru):
                      source.index('helm upgrade --install oran-simulator', oru)]
        path = self.path/'context.json'
        path.write_text(json.dumps(dict(self.context, **contract))); original = path.read_bytes()
        shell = '''set -e
python3() {
    if [ "$1" = "$SRC/tools/phase3-kong-proxy.py" ]; then
        printf '%s\\n' "lock=$PHASE3_RECOVERY_LOCK_FD" "$@"
        return "$KONG_TEST_STATUS"
    fi
    command '''+shlex.quote(sys.executable)+''' "$@"
}
geni-get() { printf '%s\\n' "$KONG_TEST_SLICE"; }
'''+gate+'''printf '%s\\n' 'nts-install'
'''
        env = dict(os.environ, SRC=str(ROOT), PHASE3_FRESH_CONTEXT=str(path),
                   KONG_TEST_STATUS=str(status), KONG_TEST_SLICE=self.slice)
        result = subprocess.run(['bash', '-c', shell], text=True, capture_output=True, env=env)
        self.assertEqual(original, path.read_bytes())
        return result

    def test_setup_binds_new_identity_with_driver_fd9(self):
        result = self.run_setup_gate({'kong_proxy_contract': 1})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(['lock=9', str(ROOT/'tools/phase3-kong-proxy.py'), 'verify-fresh',
                          '--context', str(self.path/'context.json'), '--expected-slice', self.slice,
                          '--bind-identity', 'nts-install'], result.stdout.splitlines())

    def test_setup_skips_kong_for_retained_context(self):
        result = self.run_setup_gate({})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(['nts-install'], result.stdout.splitlines())

    def test_setup_kong_failure_stops_before_simulator_install(self):
        result = self.run_setup_gate({'kong_proxy_contract': 1}, status=7)
        self.assertEqual(7, result.returncode, result.stderr)
        self.assertNotIn('nts-install', result.stdout.splitlines())


if __name__=='__main__':unittest.main()
