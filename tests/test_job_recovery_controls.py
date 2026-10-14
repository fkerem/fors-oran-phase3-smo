import copy
from pathlib import Path
import sys
import unittest
import test_image_recovery as fixtures
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
import phase3_recovery_guards as guard

class JobControlTests(unittest.TestCase):
    def test_only_six_jobs_eligible_and_two_uncertain_excluded(self):
        self.assertEqual(6, len(guard.JOBS)); self.assertTrue(guard.PRESERVE_JOBS.isdisjoint(guard.JOBS))
        self.assertEqual({'onap-aaf-sms-preload','onap-sdnc-sdnrdb-init-job'}, guard.PRESERVE_JOBS)

    def test_held_jobs_are_suspended_never_restart_and_no_retries(self):
        job, _ = fixtures.RecoveryGuardTests().job()
        job.update(kind='Job'); job['spec']['backoffLimit']=20
        job['spec']['template']['spec']['restartPolicy']='Never'
        result=guard.held_job(job)
        self.assertTrue(result['spec']['suspend']); self.assertEqual(0,result['spec']['backoffLimit'])
        self.assertEqual(20,job['spec']['backoffLimit'])

    def test_uncertain_job_controls_are_refused(self):
        job, _ = fixtures.RecoveryGuardTests().job(); job.update(kind='Job')
        job['spec']['template']['spec']['restartPolicy']='Never'
        for name in guard.PRESERVE_JOBS:
            job['metadata']['name']=name
            with self.assertRaises(ValueError):guard.held_job(job)

    def test_controls_do_not_allow_other_template_edits(self):
        job, _ = fixtures.RecoveryGuardTests().job(); job.update(kind='Job')
        job['spec']['template']['spec']['restartPolicy']='Never'
        held=guard.held_job(job)
        self.assertEqual([job['metadata']['name']],guard.recovery_diff([job],[held])['held_single_attempt_jobs'])
        held['spec']['template']['spec']['restartPolicy']='OnFailure'
        with self.assertRaises(ValueError):guard.recovery_diff([job],[held])

    def test_config_write_must_be_pod_local(self):
        container={'name':'sdnc-update-config','image':'docker.io/dibi/envsubst:1','command':['sh'],
                   'args':['-c','cd /config-input && for PFILE in `ls -1 .`; do envsubst <${PFILE} >/config/${PFILE}; done'],
                   'volumeMounts':[{'mountPath':'/config-input','name':'input'},{'mountPath':'/config','name':'output'}]}
        spec={'volumes':[{'name':'input','configMap':{'name':'config'}},{'name':'output','emptyDir':{}}]}
        self.assertEqual('pod-local-config',guard.init_behavior(container,spec,'onap-sdnc-dbinit-job'))
        spec['volumes'][1]={'name':'output','persistentVolumeClaim':{'claimName':'production'}}
        with self.assertRaises(ValueError):guard.init_behavior(container,spec,'onap-sdnc-dbinit-job')

    def test_side_effecting_init_execution_blocks_replay(self):
        job,pods=fixtures.RecoveryGuardTests().job(); job['metadata'].update(name='onap-policy-galera-config')
        job['metadata']['annotations']['meta.helm.sh/release-name']='onap-policy'
        job['spec']['template']['spec']['containers'][0]['image']=guard.MAIN_IMAGES['onap-policy-galera-config']
        job['spec']['template']['spec']['initContainers'].append({'name':'onap-policy-galera-config','image':'docker.io/mariadb:10.5.8'})
        pods[0]['spec']=copy.deepcopy(job['spec']['template']['spec'])
        pods[0]['status']['initContainerStatuses'].append({'name':'onap-policy-galera-config','state':{'terminated':{'exitCode':1}}})
        with self.assertRaisesRegex(ValueError,'Side-effecting'):guard.job_guard(job,pods)

    def test_unknown_initializer_is_not_treated_as_readiness(self):
        container={'name':'unknown','image':guard.READINESS_IMAGE,'command':['/bin/sh','-c','modify']}
        with self.assertRaises(ValueError):guard.init_behavior(container,{},'onap-sdnc-dbinit-job')

    def test_retained_config_pod_cannot_write_a_persistent_volume(self):
        job,pods=fixtures.RecoveryGuardTests().job()
        job['metadata'].update(name='onap-sdnc-dbinit-job')
        job['metadata']['annotations']['meta.helm.sh/release-name']='onap-sdnc'
        spec=job['spec']['template']['spec'];spec['containers'][0]['image']=guard.MAIN_IMAGES['onap-sdnc-dbinit-job']
        spec['initContainers'].append({'name':'sdnc-update-config','image':'docker.io/dibi/envsubst:1','command':['sh'],
            'args':['-c','cd /config-input && for PFILE in `ls -1 .`; do envsubst <${PFILE} >/config/${PFILE}; done'],
            'volumeMounts':[{'mountPath':'/config-input','name':'input'},{'mountPath':'/config','name':'output'}]})
        spec['volumes']=[{'name':'input','configMap':{'name':'config'}},{'name':'output','emptyDir':{}}]
        pods[0]['spec']=copy.deepcopy(spec)
        pods[0]['status']['initContainerStatuses'].append({'name':'sdnc-update-config','state':{'terminated':{'exitCode':0}}})
        self.assertEqual('pod-local-config',guard.job_guard(job,pods)['reviewed_init_behaviors']['sdnc-update-config'])
        pods[0]['spec']['volumes'][1]={'name':'output','persistentVolumeClaim':{'claimName':'production'}}
        with self.assertRaisesRegex(ValueError,'emptyDir'):guard.job_guard(job,pods)

if __name__=='__main__':unittest.main()
