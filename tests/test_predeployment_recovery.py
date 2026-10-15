import copy
import fcntl
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'bin'))
spec = importlib.util.spec_from_file_location('predeployment',ROOT/'bin/phase3-predeployment-recovery.py')
recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.setup = Path(self.temp.name).resolve()/'setup'; self.setup.mkdir()
        self.work = self.setup/'phase3-smo'; self.work.mkdir()
        self.trial = self.work/'fresh-start'; (self.trial/'pki').mkdir(parents=True)
        for name in ('server.p12','signer.p12','public-metadata.json','store-password'):
            (self.trial/'pki'/name).write_bytes(b'private test fixture')
        (self.trial/'command-1.stderr').write_text('Algorithm HmacPBESHA256 not available')
        self.logs = Path(self.temp.name)/'logs'; self.logs.mkdir()
        (self.logs/'setup.log').write_text('old failed setup')
        for name in recovery.PREREQUISITES:(self.setup/name).touch()
        self.nodes = [{'metadata':{'name':'node-'+str(i),'uid':'uid-'+str(i),'labels':{'kubernetes.io/hostname':'node-'+str(i)}},
                       'spec':{},'status':{'conditions':[{'type':'Ready','status':'True'}]}} for i in range(3)]
        self.slice = 'urn:publicid:IDN+emulab.net:p+slice+new'
        self.namespaces = []; self.releases = []; self.volumes = []
        def command(argv):
            if argv[0]=='geni-get':return self.slice
            if argv[0]=='hostname':return 'node-0.new.example'
            if argv[0]=='git':return 'a'*40
            if argv[0]=='helm':return json.dumps(self.releases)
            return json.dumps({'items':self.namespaces if argv[2]=='namespaces' else self.volumes})
        self.addCleanup(patch.stopall)
        patch.object(recovery,'command',side_effect=command).start()
        patch.object(recovery.fresh,'cluster_nodes',side_effect=lambda:copy.deepcopy(self.nodes)).start()
        patch.object(recovery.fresh,'storage_inspection',return_value={'paths':[]}).start()

    def preserve(self,apply=False):
        return recovery.preserve(self.slice,apply,self.setup,self.logs)

    def test_audit_does_not_change_any_file(self):
        before=recovery.failed_trial(self.work)
        self.assertFalse(self.preserve()['applied'])
        self.assertEqual(before,recovery.failed_trial(self.work))
        self.assertEqual([],list(self.work.glob('predeployment-recovery-*')))

    def test_wrong_allocation_missing_prerequisite_or_unready_node_refused(self):
        with self.assertRaises(ValueError):recovery.cluster_state('wrong',self.setup)
        marker=self.setup/recovery.PREREQUISITES[0]; marker.unlink()
        with self.assertRaises(ValueError):self.preserve()
        marker.touch(); self.nodes[0]['status']['conditions'][0]['status']='False'
        with self.assertRaises(ValueError):self.preserve()

    def test_any_smo_namespace_release_volume_or_context_refuses(self):
        for collection,entry in [(self.namespaces,{'metadata':{'name':'onap'}}),
                (self.releases,{'name':'strimzi-kafka-operator','namespace':'other'}),
                (self.volumes,{'metadata':{'name':'onap-data'},'spec':{}})]:
            collection.append(entry)
            with self.assertRaises(ValueError):self.preserve()
            collection.clear()
        (self.trial/'context.json').write_text('{}')
        with self.assertRaises(ValueError):self.preserve()

    def test_unknown_failure_and_symlink_are_not_adopted(self):
        error=self.trial/'command-1.stderr'; error.write_text('different error')
        with self.assertRaises(ValueError):self.preserve()
        error.write_text('Algorithm HmacPBESHA256 not available')
        (self.trial/'linked').symlink_to(self.logs/'setup.log')
        with self.assertRaises(ValueError):self.preserve()

    def test_apply_requires_driver_lock(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(ValueError):self.preserve(True)
        self.assertTrue(self.trial.exists())

    def test_preservation_keeps_every_byte_and_original_logs(self):
        before=recovery.failed_trial(self.work)
        with (self.setup/'phase3-driver.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.dict(os.environ,{'PHASE3_RECOVERY_LOCK_FD':str(lock.fileno())}):
                record=self.preserve(True)
        archive=Path(record['private_receipt']).parent
        self.assertFalse(self.trial.exists())
        self.assertEqual('old failed setup',(self.logs/'setup.log').read_text())
        for name,digest in before.items():self.assertEqual(digest,recovery.digest(archive/'failed-fresh-start'/name))
        self.assertEqual(0o700,archive.stat().st_mode&0o777)
        self.assertEqual(0o600,Path(record['private_receipt']).stat().st_mode&0o777)
        self.assertFalse((self.setup/'setup-driver-done').exists())
        with self.assertRaises(ValueError):self.preserve()

    def test_uid_change_stops_before_preservation(self):
        state=recovery.cluster_state(self.slice,self.setup)
        other=copy.deepcopy(state); other['node_uids']['node-2']='changed'
        with (self.setup/'phase3-driver.lock').open('w') as lock:
            with patch.dict(os.environ,{'PHASE3_RECOVERY_LOCK_FD':str(lock.fileno())}):
                with patch.object(recovery,'cluster_state',side_effect=[state,other]):
                    with self.assertRaises(ValueError):self.preserve(True)
        self.assertTrue(self.trial.exists())

    def test_normal_startup_has_no_recovery_flags_and_resume_skips_infrastructure(self):
        profile=(ROOT/'profile.py').read_text(); driver=(ROOT/'setup-driver.sh').read_text()
        self.assertIn('/local/repository/setup-driver.sh >',profile)
        self.assertNotIn('--resume-before-smo',profile)
        body=driver.split('if [ "$resume_before_smo" -eq 1 ]; then',1)[1].split('\nfi',1)[0]
        self.assertIn('setup-oran-smo.sh',body); self.assertIn('setup-end.sh',body)
        self.assertNotIn('setup-kubespray.sh',body); self.assertIn('exit 0',body)
        self.assertIn('flock -n 9',driver)
        self.assertIn('phase3-fresh-start.py" prepare',(ROOT/'setup-oran-smo.sh').read_text())

    @unittest.skipUnless(shutil.which('flock'),'Linux driver-lock integration runs in CI')
    def test_driver_lock_inheritance_concurrency_and_failed_stage(self):
        # Execute the actual driver with only its two fixed filesystem roots
        # redirected into this disposable fixture; no real setup-lib is sourced.
        home=Path(self.temp.name).resolve()/'driver'; (home/'bin').mkdir(parents=True)
        driver=(ROOT/'setup-driver.sh').read_text().replace('/local/setup/',str(self.setup)+'/').replace('/local/logs/',str(self.logs)+'/')
        (home/'setup-driver.sh').write_text(driver)
        (home/'setup-lib.sh').write_text('OURDIR='+str(self.setup)+'\nHOSTNAME=node-0\n')
        (home/'bin/phase3-predeployment-recovery.py').write_text(
            'import os\nassert os.environ["PHASE3_RECOVERY_LOCK_FD"] == "9"\nos.fstat(9)\n')
        for name,body in [('setup-oran-smo.sh','exit 7'),('setup-end.sh','exit 99')]:
            path=home/name; path.write_text('#!/bin/bash\n'+body+'\n');path.chmod(0o700)
        args=['bash',str(home/'setup-driver.sh'),'--resume-before-smo','--expected-slice',self.slice]
        result=subprocess.run(args,capture_output=True,text=True)
        self.assertEqual(7,result.returncode,result.stderr)
        self.assertFalse((self.setup/'setup-driver-done').exists())
        with (self.setup/'phase3-driver.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=subprocess.run(args,capture_output=True,text=True)
            self.assertEqual(1,result.returncode)
            self.assertIn('driver lock',result.stderr)


if __name__=='__main__':unittest.main()
