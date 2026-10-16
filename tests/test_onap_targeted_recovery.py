import copy
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'bin'))
import phase3_ves as ves
from phase3_fresh import overlay, READINESS_IMAGE
spec = importlib.util.spec_from_file_location('onap_recovery', ROOT/'bin/phase3-onap-recovery.py')
recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)


class VesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        (self.path/'root.cer').write_text('public root fixture')
        (self.path/'truststoreONAPall.jks').write_bytes(b'public JKS fixture')
        (self.path/'truststoreONAP.p12').write_bytes(b'public trust fixture')
        self.context = {'schema': 1, 'baseline': 'fresh-isolated-lab-pki', 'pki_directory': str(self.path), 'root_sha256': 'a'*64}
        self.doc = {'apiVersion':'apps/v1', 'kind':'Deployment', 'metadata':{'name':ves.NAME, 'namespace':'onap'},
                    'spec':{'template':{'spec':{'containers':[], 'initContainers':[{'name':'init-tls','image':ves.IMAGE_TAG,
                        'volumeMounts':[{'name':'tls-info','mountPath':'/opt/app/osaaf'}]}],
                        'volumes':[{'name':'tls-info','emptyDir':{}}]}}}}

    def test_exact_image_public_trust_and_latch_volumes(self):
        cm = ves.config(self.context)
        self.assertTrue(cm['immutable'])
        self.assertEqual({'truststoreONAPall.jks'}, set(cm['binaryData']))
        result = ves.patch_deployment(self.doc, self.context)
        self.assertEqual(cm, ves.verify(result, self.context))
        self.assertEqual(ves.IMAGE_TAG, self.doc['spec']['template']['spec']['initContainers'][0]['image'])
        volumes = result['spec']['template']['spec']['volumes']
        self.assertTrue(any(v.get('emptyDir', {}).get('medium') == 'Memory' for v in volumes))
        self.assertFalse(any('secret' in v for v in volumes))

    def test_source_image_mount_or_storage_drift_refused(self):
        for change in ('image', 'command', 'storage', 'mount'):
            doc = copy.deepcopy(self.doc)
            pod = doc['spec']['template']['spec']
            if change == 'image':pod['initContainers'][0]['image'] = 'mutable:latest'
            if change == 'command':pod['initContainers'][0]['command'] = ['different']
            if change == 'storage':pod['volumes'][0] = {'name':'tls-info','persistentVolumeClaim':{'claimName':'data'}}
            if change == 'mount':pod['initContainers'][0]['volumeMounts'] = []
            with self.assertRaises(ValueError):ves.patch_deployment(doc, self.context)

    def test_default_fresh_overlay_includes_ves_and_dmaap_timeout(self):
        job = {'kind':'Job','metadata':{'name':recovery.TARGETS['dmaap']},'spec':{'template':{'spec':{
            'initContainers':[{'name':'ready','image':READINESS_IMAGE,'command':['/app/ready.py'],
                               'args':['--container-name','dmaap-bc']}], 'containers':[]}}}}
        result, changed = overlay([self.doc,job], self.context)
        self.assertEqual(ves.IMAGE,result['spec']['template']['spec']['initContainers'][0]['image'])
        self.assertEqual(['--container-name','dmaap-bc','--timeout','30'],changed['spec']['template']['spec']['initContainers'][0]['args'])
        self.assertEqual(0, changed['spec']['backoffLimit'])

    def test_failed_wrapper_cannot_repeat_issuance(self):
        # Redirect only fixed roots into a disposable shell fixture. No cluster or CA.
        for name in ('state','dcae','agent','trust','home/.aaf'):(self.path/name).mkdir(parents=True,exist_ok=True)
        (self.path/'dcae/dcae-cert-setup.sh').write_text('echo attempted >>"'+str(self.path/'count')+'"\nexit 7\n')
        (self.path/'agent/agent.sh').write_text('fixture agent\n')
        for path in ('home/.aaf/truststoreONAPall.jks','trust/truststoreONAPall.jks'):(self.path/path).write_bytes(b'public trust')
        source=(ROOT/'bin/phase3-ves-bootstrap.sh').read_text()
        for old,new in [('/phase3-ves-attempt',str(self.path/'state')),('/opt/dcae',str(self.path/'dcae')),
                ('/opt/app/aaf_config/bin',str(self.path/'agent')),('/root/.aaf',str(self.path/'home/.aaf')),('/phase3-ves',str(self.path/'trust'))]:
            source=source.replace(old,new)
        for old,path in [('31aa68706dd52bcbdb30e243d76c370e60ca222ebf23fe7977de4be4c72b1b0c',self.path/'dcae/dcae-cert-setup.sh'),
                         ('8d5ec5e08a57033449511f9ac66773c105d47b79dee620b4314e867c3f4d276d',self.path/'agent/agent.sh')]:
            source=source.replace(old,hashlib.sha256(path.read_bytes()).hexdigest())
        first=subprocess.run(['bash','-c',source],capture_output=True,text=True)
        second=subprocess.run(['bash','-c',source],capture_output=True,text=True)
        self.assertNotEqual(0,first.returncode,first.stdout+first.stderr)
        self.assertIn('already attempted',second.stderr)
        self.assertEqual('attempted\n',(self.path/'count').read_text())


class JobTests(unittest.TestCase):
    def setUp(self):
        self.job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':recovery.TARGETS['dmaap'],'namespace':'onap','uid':'old','resourceVersion':'7',
                'annotations':{'meta.helm.sh/release-name':'onap-dmaap'}},'spec':{'backoffLimit':0,'selector':{'old':'selector'},
                'template':{'metadata':{'labels':{'controller-uid':'old','batch.kubernetes.io/controller-uid':'old','retain':'yes'}},'spec':{
                    'restartPolicy':'Never','initContainers':[{'name':'ready','image':READINESS_IMAGE,
                    'command':['/phase3-helpers/phase3-readiness-wrapper.py'],'args':['--container-name','dmaap-bc']}],
                    'containers':[{'name':'main','image':recovery.MAINS['dmaap']}]}}},
                'status':{'failed':1,'conditions':[{'type':'Failed','status':'True'}]}}
        self.pod={'metadata':{'uid':'pod','name':'failed','ownerReferences':[{'kind':'Job','uid':'old'}]},
                  'spec':copy.deepcopy(self.job['spec']['template']['spec']), 'status':{'phase':'Failed',
                    'containerStatuses':[{'name':'main','restartCount':0,'imageID':'','state':{'waiting':{'reason':'PodInitializing'}}}],
                    'initContainerStatuses':[{'name':'ready','state':{'terminated':{'exitCode':1}}}]}}

    def test_terminal_first_attempt_never_ran_main_is_eligible(self):
        self.assertEqual(self.pod,recovery.job_guard('dmaap',self.job,[self.pod]))
        result=recovery.new_job(self.job,'dmaap')
        self.assertTrue(result['spec']['suspend']); self.assertEqual(0,result['spec']['backoffLimit'])
        self.assertNotIn('uid',result['metadata']); self.assertNotIn('selector',result['spec'])
        self.assertEqual({'retain':'yes'},result['spec']['template']['metadata']['labels'])
        self.assertEqual(['--container-name','dmaap-bc','--timeout','30'],result['spec']['template']['spec']['initContainers'][0]['args'])

    def test_helm_contract_drift_is_not_adopted(self):
        expected=copy.deepcopy(self.job)
        recovery.manifest_guard(self.job,expected)
        for field,value in [('command',['different']),('env',[{'name':'CHANGED','value':'yes'}])]:
            changed=copy.deepcopy(self.job)
            changed['spec']['template']['spec']['containers'][0][field]=value
            with self.assertRaises(ValueError):recovery.manifest_guard(changed,expected)
        changed=copy.deepcopy(self.job)
        changed['spec']['template']['spec']['volumes']=[{'name':'unexpected','hostPath':{'path':'/data'}}]
        with self.assertRaises(ValueError):recovery.manifest_guard(changed,expected)

    def test_changed_review_refuses_before_preservation_or_mutation(self):
        review={'target':'dmaap','slice_urn':'expected','uid':'old'}
        with patch.object(recovery,'inspect',return_value=({'uid':'different'},None,None,None)), \
                patch.object(recovery,'preserve') as preserve, patch.object(recovery,'command') as mutate:
            with self.assertRaises(ValueError):recovery.apply(review,Path('/unused/review.json'))
            preserve.assert_not_called();mutate.assert_not_called()

    def test_execution_missing_history_changed_ownership_or_layout_refuses(self):
        for mode in ('execution','missing','ownership','layout','active','completed','restart'):
            job=copy.deepcopy(self.job); pod=copy.deepcopy(self.pod)
            if mode=='execution':pod['status']['containerStatuses'][0]['imageID']='executed'
            if mode=='missing':pod['status']['initContainerStatuses']=[]
            if mode=='ownership':job['metadata']['annotations']['meta.helm.sh/release-name']='different'
            if mode=='layout':pod['spec']['initContainers'][0]['args']=['changed']
            if mode=='active':job['status']['active']=1
            if mode=='completed':job['status']['succeeded']=1
            if mode=='restart':pod['status']['containerStatuses'][0]['restartCount']=1
            with self.assertRaises(ValueError,msg=mode):recovery.job_guard('dmaap',job,[pod])
        with self.assertRaises(ValueError):recovery.job_guard('dmaap',self.job,[])

    def test_sms_requires_correlated_preissuance_failures_not_just_failed_exit(self):
        pod={'status':{'podIP':'10.1.2.3','initContainerStatuses':[{'name':'aaf-sms-aaf-config','state':{
            'terminated':{'startedAt':'2026-10-16T00:01:49Z','finishedAt':'2026-10-16T00:01:58Z'}}}]}}
        cm={'metadata':{'uid':'cm'},'status':{'containerStatuses':[{'restartCount':0}]}}
        line='2026-10-16T00:01:53.839123174Z ip=10.1.2.3,status=403,meth=PUT,path=/cert/local,SVC1403 Sponsorship cannot be determined'
        proof=recovery.sms_proof(pod,cm,'FAILED to get Certificate',line)
        self.assertEqual(1,proof['preissuance_forbidden_count'])
        for altered in (line.replace('status=403','status=200'),line.replace('10.1.2.3','10.1.2.4'),line.replace('00:01:53','00:02:53'),''):
            with self.assertRaises(ValueError):recovery.sms_proof(pod,cm,'FAILED to get Certificate',altered)
        with self.assertRaises(ValueError):recovery.sms_proof(pod,cm,'Obtained Certificates',line)
        cm['status']['containerStatuses'][0]['restartCount']=1
        with self.assertRaises(ValueError):recovery.sms_proof(pod,cm,'FAILED to get Certificate',line)

    def test_jammy_timestamp_precision_is_normalized_without_changing_window(self):
        parsed=recovery.timestamp('2026-10-16T00:01:53.839123174Z')
        self.assertEqual(839123,parsed.microsecond)
        self.assertEqual(timezone.utc,parsed.tzinfo)
        for bad in ('2026-10-16T00:01:53', '2026-10-16T00:01:53.1234567890Z', 'invalid'):
            with self.assertRaises(ValueError):recovery.timestamp(bad)

    def test_prerequisites_require_two_minutes_stability(self):
        pod={'metadata':{'uid':'dep'},'spec':{'containers':[{'name':'dependency'}]},'status':{
            'conditions':[{'type':'Ready','status':'True','lastTransitionTime':datetime.now(timezone.utc).isoformat()}],
            'containerStatuses':[{'name':'dependency','restartCount':0}]}}
        with self.assertRaises(ValueError):recovery.ready_pods([pod],['dependency'])
        pod['status']['conditions'][0]['lastTransitionTime']=(datetime.now(timezone.utc)-timedelta(minutes=3)).isoformat()
        self.assertEqual('dep',recovery.ready_pods([pod],['dependency'])[0]['uid'])


if __name__=='__main__':unittest.main()
