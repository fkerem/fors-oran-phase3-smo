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
from phase3_lab_pki import generate, secret, CONFIG_IMAGE, AGENT_IMAGE, SANS
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


if __name__=='__main__':unittest.main()
