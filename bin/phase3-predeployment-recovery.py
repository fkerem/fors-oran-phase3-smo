#!/usr/bin/env python3
"""Audit, or explicitly preserve one failed PKI trial before SMO deployment."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('phase3_fresh_start', ROOT/'bin/phase3-fresh-start.py')
fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fresh)
SMO_NAMESPACES = {'onap','nonrtric','network','strimzi-system'}
PREREQUISITES = ('disk-space-done','nfs-server-done','nginx-done','ssl-done',
                 'kubespray-done','kubernetes-extra-done')


def command(argv):
    result = subprocess.run(argv,capture_output=True,text=True,timeout=90)
    if result.returncode:
        raise ValueError('Recovery inspection failed: '+argv[0])
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cluster_state(expected_slice, setup):
    actual = command(['geni-get','slice_urn']).strip()
    if actual != expected_slice:
        raise ValueError('Recovery allocation mismatch')
    if command(['hostname']).strip().split('.')[0] != 'node-0':
        raise ValueError('Predeployment recovery is node-0 only')
    for name in PREREQUISITES:
        if not (setup/name).is_file():
            raise ValueError('Infrastructure prerequisite missing: '+name)
    if any((setup/name).exists() for name in ('setup-driver-done','setup-oran-smo-done')):
        raise ValueError('Setup already completed; recovery refused')
    nodes = fresh.cluster_nodes()
    if not all(any(c['type']=='Ready' and c['status']=='True' for c in n.get('status',{}).get('conditions',[])) for n in nodes):
        raise ValueError('All three Nodes must be Ready')
    storage = fresh.select_storage_node(nodes)
    namespaces = json.loads(command(['kubectl','get','namespaces','-o','json']))['items']
    if SMO_NAMESPACES.intersection(n['metadata']['name'] for n in namespaces):
        raise ValueError('SMO/operator namespace already exists; separate recovery review required')
    releases = json.loads(command(['helm','list','--all','--all-namespaces','-o','json']))
    if any(r.get('namespace') in SMO_NAMESPACES or r['name'].startswith(('onap','oran-','strimzi-')) for r in releases):
        raise ValueError('Existing SMO/operator release; recovery refused')
    volumes = json.loads(command(['kubectl','get','pv','-o','json']))['items']
    if any(v.get('spec',{}).get('claimRef',{}).get('namespace') in SMO_NAMESPACES
           or any(t in v['metadata']['name'] for t in ('onap','mariadb','sdnrdb')) for v in volumes):
        raise ValueError('Existing SMO persistent volume; recovery refused')
    return {'slice_urn':actual,'node_uids':{n['metadata']['name']:n['metadata']['uid'] for n in nodes},
            'storage_node':storage,'storage_preflight':fresh.storage_inspection(actual),
            'prerequisites':{name:digest(setup/name) for name in PREREQUISITES}}


def failed_trial(work):
    trial = work/'fresh-start'
    if trial.is_symlink() or not trial.is_dir() or trial.resolve() != trial:
        raise ValueError('Expected canonical failed fresh-start directory')
    if any((trial/name).exists() for name in ('context.json','rehearsal.json','onap-acceptance.json','offline-server-config')):
        raise ValueError('Trial progressed beyond the reviewed failure; recovery refused')
    errors = sorted(trial.glob('command-*.stderr'),key=lambda p:p.stat().st_mtime_ns)
    if not errors or b'Algorithm HmacPBESHA256 not available' not in errors[-1].read_bytes():
        raise ValueError('Not the reviewed predeployment PKCS12 failure')
    paths = list(trial.rglob('*'))
    if any(p.is_symlink() or (not p.is_file() and not p.is_dir()) for p in paths):
        raise ValueError('Unreviewed special file in failed trial')
    for name in ('pki/server.p12','pki/signer.p12','pki/public-metadata.json','pki/store-password'):
        if not (trial/name).is_file():
            raise ValueError('Failed trial inventory is incomplete')
    return {str(p.relative_to(trial)):digest(p) for p in paths if p.is_file()}


def preserve(expected_slice, apply=False, setup=Path('/local/setup'), logs=Path('/local/logs')):
    setup = setup.resolve(); work = setup/'phase3-smo'
    state = cluster_state(expected_slice,setup)
    files = failed_trial(work)
    if not apply:
        return {'passed':True,'applied':False,'state':state,'failed_trial_hashes':files}
    # Only the driver holding its exclusive lock can call the apply path.
    fd = int(os.environ.get('PHASE3_RECOVERY_LOCK_FD','-1'))
    if fd < 0:
        raise ValueError('Recovery requires the exclusive setup-driver lock')
    lock = setup/'phase3-driver.lock'
    held = os.fstat(fd); expected = lock.stat()
    if (held.st_dev,held.st_ino) != (expected.st_dev,expected.st_ino):
        raise ValueError('Recovery lock does not match this allocation')
    if cluster_state(expected_slice,setup) != state or failed_trial(work) != files:
        raise ValueError('Allocation or trial changed during inspection')
    archive = Path(tempfile.mkdtemp(prefix='predeployment-recovery-',dir=str(work)))
    os.chmod(archive,0o700)
    originals = [p for p in (logs/'setup.log',logs/'setup-oran-smo.sh.log',work/'chart-lock.json') if p.is_file()]
    for pattern in ('image-preflight-*/*.json','prepared/*-changes.json'):
        originals.extend(work.glob(pattern))
    captured = {}
    for index,source in enumerate(originals):
        if source.is_symlink():
            raise ValueError('Refusing symlinked evidence')
        target = archive/('%03d-'%index+source.name)
        with target.open('xb') as output:
            os.chmod(target,0o600); output.write(source.read_bytes())
        captured[str(source)] = {'copy':target.name,'sha256':digest(target)}
    # One exact, validated owned directory is renamed, never removed or overwritten.
    if cluster_state(expected_slice,setup) != state or failed_trial(work) != files:
        raise ValueError('State changed before preserving failed PKI')
    (work/'fresh-start').rename(archive/'failed-fresh-start')
    for name,expected_hash in files.items():
        if digest(archive/'failed-fresh-start'/name) != expected_hash:
            raise ValueError('Preserved failed-trial hash mismatch')
    record = {'schema':1,'passed':True,'applied':True,'preserved_utc':datetime.now(timezone.utc).isoformat(),
              'state':state,'failed_trial_hashes':files,'copied_evidence':captured,
              'profile_commit':command(['git','-C',str(ROOT),'rev-parse','HEAD']).strip(),
              'workloads_changed':False,'certificate_fault_cases_started':False}
    fresh.private_write(archive/'preservation.json',(json.dumps(record,indent=2)+'\n').encode())
    return {'passed':True,'applied':True,'private_receipt':str(archive/'preservation.json')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-slice',required=True)
    parser.add_argument('--apply',action='store_true')
    args = parser.parse_args()
    try:
        record = preserve(args.expected_slice,args.apply)
        print('Predeployment recovery inspection passed; applied='+str(record['applied']))
        if record.get('private_receipt'):print('Private preservation receipt: '+record['private_receipt'])
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.TimeoutExpired) as error:
        parser.exit(1,'Predeployment recovery refused: '+str(error)+'\n')


if __name__ == '__main__':
    main()
