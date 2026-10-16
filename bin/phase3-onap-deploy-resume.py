#!/usr/bin/env python3
"""Continue a timeout before SMS first use; never replay ONAP deployment."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = Path('/local/setup/phase3-smo/fresh-start/context.json')
PREREQUISITES = ('disk-space-done', 'nfs-server-done', 'nginx-done',
                 'ssl-done', 'kubespray-done', 'kubernetes-extra-done')


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'bin'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backend = load('deploy_resume_backend', 'phase3-sms-backend.py')
preload = load('deploy_resume_preload', 'phase3-sms-preload.py')
fresh = load('deploy_resume_fresh', 'phase3-fresh-start.py')


def digest(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise backend.Blocked('Continuation evidence must be a regular, non-symlink file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def failed_timeout(parent):
    files = sorted(parent.glob('sms-backend-blocked-*.json'), key=lambda p:p.stat().st_mtime_ns)
    if not files:
        raise backend.Blocked('No retained pre-first-use backend timeout')
    path = files[-1]
    record = json.loads(path.read_text())
    if (record.get('failure_type') != 'Blocked' or record.get('backend_accepted') is not False
            or record.get('preload_authorized') is not False
            or record.get('reason') not in (
                'Fresh backend handoff timed out; no reset or recovery attempted',
                'Fresh backend startup timed out; no reset or recovery attempted')):
        raise backend.Blocked('Failure is not the reviewed pre-first-use timeout')
    return {path.name:digest(path)}


def job_inventory(resources):
    completed = {}
    for resource in resources:
        if resource['kind'] != 'Job':
            continue
        status = resource.get('status', {})
        conditions = status.get('conditions', [])
        if status.get('failed', 0) or any(c.get('type') == 'Failed' and c.get('status') == 'True' for c in conditions):
            raise backend.Blocked('An ONAP Job failed; separate review required')
        if any(c.get('type') == 'Complete' and c.get('status') == 'True' for c in conditions):
            completed[resource['metadata']['name']] = resource['metadata']['uid']
    return completed


def stage_state(path):
    parent = path.parent
    backend_ready = (parent/'sms-backend-acceptance.json').exists()
    preload_ready = (parent/'sms-preload-acceptance.json').exists()
    if backend_ready:
        if backend.verify_acceptance(path) is None:
            raise backend.Blocked('Fresh backend receipt is not accepted')
    elif (parent/'sms-backend-first-use-attempt.json').exists():
        raise backend.Blocked('First-use outcome is uncertain; no retry')
    if preload_ready:
        if not backend_ready or preload.verify_acceptance(path) is None:
            raise backend.Blocked('Fresh preload receipt is not accepted')
    elif any((parent/name).exists() for name in ('sms-preload-attempt.json', 'sms-preload-armed.json')):
        raise backend.Blocked('Preload outcome is uncertain; no retry')
    if (parent/'onap-acceptance.json').exists():
        receipt = json.loads((parent/'onap-acceptance.json').read_text())
        context = json.loads(path.read_text())
        if (not preload_ready or receipt.get('passed') is not True
                or receipt.get('slice_urn') != context['slice_urn']
                or receipt.get('root_sha256') != context['root_sha256']):
            raise backend.Blocked('ONAP receipt is not bound to this fresh context')
        load('deploy_resume_accepted', 'phase3-onap-resume-gate.py').check(context_path=str(path))
    return backend_ready, preload_ready


def inspect(expected_slice, path=CONTEXT):
    path = Path(path)
    setup = path.parent.parent.parent
    if (backend.command(['geni-get', 'slice_urn']).decode().strip() != expected_slice
            or backend.command(['hostname']).decode().strip().split('.')[0] != 'node-0'):
        raise backend.Blocked('Post-deployment continuation allocation mismatch')
    if any(not (setup/name).is_file() for name in PREREQUISITES):
        raise backend.Blocked('Infrastructure prerequisite missing; do not replay setup')
    if any((setup/name).exists() for name in ('setup-driver-done', 'setup-oran-smo-done')):
        raise backend.Blocked('Setup already completed')
    context = fresh.verify_context(path)
    if context['slice_urn'] != expected_slice or context.get('sms_backend_contract') != 1 or context.get('sms_preload_contract') != 1:
        raise backend.Blocked('Only the qualified fresh backend/preload context can continue')
    nodes = fresh.cluster_nodes()
    if not all(any(c['type']=='Ready' and c['status']=='True' for c in n['status']['conditions']) for n in nodes):
        raise backend.Blocked('All allocation Nodes must be Ready')
    stages = stage_state(path)
    resources = backend.get('deployments,statefulsets,jobs,pvc')['items']
    if not {'Deployment', 'StatefulSet', 'Job', 'PersistentVolumeClaim'}.issubset({r['kind'] for r in resources}):
        raise backend.Blocked('ONAP deployment inventory is incomplete')
    completed = job_inventory(resources)
    jobs = [r for r in resources if r['kind'] == 'Job' and r['metadata']['name'] == preload.preload.JOB]
    if len(jobs) != 1:
        raise backend.Blocked('Expected exactly one retained guarded preload Job')
    job = preload.job_contract(jobs[0])
    if not stages[1] and (job['spec'].get('suspend') is not True or preload.owned_pods(job)
                         or any(job.get('status', {}).get(k, 0) for k in ('active', 'failed', 'succeeded'))):
        raise backend.Blocked('Preload must remain held and unattempted')
    record, objects = backend.snapshot()
    if not record['vault']['initialized'] or record['vault']['sealed']:
        raise backend.Blocked('Retained backend must be initialized and unsealed; no repair')
    backend.verify_pins(context, objects)
    leaf, _, _ = backend.tls(context, objects[0])
    # Validate durable shards before permitting the normal first-use request.
    for entry in record['quorum']:
        if any(not v.get('present') or int(v.get('mode', '0'), 8) != 0o600 for v in entry['files'].values()):
            raise backend.Blocked('Durable owner-private quorum custody unavailable')
    custody = backend.backend.recovery_checks([{'files': {
        name:backend.execute(e['name'], 'aaf-sms-quorumclient', ['cat', filename])
        for name, filename in e['paths'].items()}} for e in objects[3]])
    if not stages[0] and any(v.get('present') for v in record['sms_backend_auth'].values()):
        raise backend.Blocked('Unaccepted backend auth already exists; separate review required')
    claims = [r for r in resources if r['kind'] == 'PersistentVolumeClaim']
    if any(r.get('status', {}).get('phase') != 'Bound' for r in claims):
        raise backend.Blocked('ONAP storage must remain Bound')
    volumes = backend.get('pv')['items']
    names = {r['spec']['volumeName'] for r in claims}
    resources += [r for r in volumes if r['metadata']['name'] in names]
    protected = {}
    for resource in resources:
        spec = copy.deepcopy(resource['spec'])
        if resource['kind'] == 'Job' and resource['metadata']['name'] == preload.preload.JOB:
            spec.pop('suspend', None)  # Only this guarded activation is expected.
        protected[resource['kind']+'/'+resource['metadata']['name']] = {
            'uid':resource['metadata']['uid'], 'spec_sha256':hashlib.sha256(preload.preload.canonical(spec)).hexdigest()}
    releases = json.loads(backend.command(['helm', 'list', '--all', '-n', 'onap', '-o', 'json']))
    if not releases or any(r['status'] != 'deployed' for r in releases):
        raise backend.Blocked('ONAP release deployment is not complete')
    code = [ROOT/'setup-driver.sh', ROOT/'setup-oran-smo.sh', *sorted((ROOT/'bin').glob('*.py'))]
    binding = {'slice_urn':expected_slice, 'context_sha256':digest(path),
        'backend_identity':record['identity'], 'custody':custody, 'leaf_sha256':leaf,
        'operator':backend.operator_binding(), 'protected':protected,
        'releases':sorted([{k:r[k] for k in ('name', 'revision', 'chart', 'app_version', 'status')} for r in releases], key=lambda r:r['name']),
        'code_sha256':{str(p.relative_to(ROOT)):digest(p) for p in code}}
    review = path.parent/'onap-deploy-resume-review.json'
    if review.exists():
        previous = json.loads(review.read_text())
        if (previous.get('binding') != binding or any(completed.get(k) != v for k,v in previous['completed_jobs'].items())):
            raise backend.Blocked('Reviewed allocation/code/completed Job identity changed')
    else:
        failed_timeout(path.parent)
    return binding, completed, stages, record, objects


def preserve(path, record, objects):
    work = path.parent.parent
    directory = Path(tempfile.mkdtemp(prefix='onap-deploy-resume-', dir=str(work)))
    os.chmod(directory, 0o700)
    backend.preserve(directory/'backend', record, objects)
    sources = [path, path.parent/'rehearsal.json', work/'chart-lock.json',
               Path('/local/logs/setup.log'), Path('/local/logs/setup-oran-smo.sh.log')]
    sources += sorted(path.parent.glob('sms-*.json'))
    hashes = {}
    for index, source in enumerate(sources):
        if source.exists():
            original = digest(source)
            destination = directory/('%03d-' % index+source.name)
            fresh.private_write(destination, source.read_bytes())
            if digest(destination) != original:
                raise backend.Blocked('Original startup evidence preservation failed')
            hashes[str(source)] = {'copy':destination.name, 'sha256':original}
    fresh.private_write(directory/'inventory.json', backend.command(
        ['kubectl', '-n', 'onap', 'get', 'pods,deployments,statefulsets,jobs,pvc', '-o', 'json']))
    fresh.private_write(directory/'preservation.json', json.dumps({'files':hashes,
        'preserved_utc':datetime.now(timezone.utc).isoformat()}, indent=2).encode())
    return str(directory)


def continue_startup(expected_slice, path=CONTEXT, apply=False):
    path = Path(path)
    binding, completed, stages, record, objects = inspect(expected_slice, path)
    if not apply:
        return {'eligible':True, 'binding_sha256':hashlib.sha256(preload.preload.canonical(binding)).hexdigest(),
                'backend_accepted':stages[0], 'preload_accepted':stages[1], 'workloads_changed':False}
    archive = preserve(path, record, objects)
    review = path.parent/'onap-deploy-resume-review.json'
    if not review.exists():
        preload.durable_write(review, {'schema':1, 'binding':binding, 'completed_jobs':completed,
            'original_timeout':failed_timeout(path.parent), 'private_archive':archive})
    if inspect(expected_slice, path)[0] != binding:
        raise backend.Blocked('Allocation changed before continuation')
    if not stages[0]:
        print('Continuing fresh backend acceptance; no infrastructure replay', flush=True)
        backend.wait_fresh(path, 600, 1800, expected_identity=binding['backend_identity'])
    else:
        backend.verify_acceptance(path)
    inspect(expected_slice, path)
    if not stages[1]:
        print('Starting the single guarded preload attempt', flush=True)
        preload.run_fresh(path, 600)
    else:
        preload.verify_acceptance(path)
    inspect(expected_slice, path)
    if not (path.parent/'onap-acceptance.json').exists():
        if not backend.get('kafkas.kafka.strimzi.io')['items']:
            raise backend.Blocked('Expected ONAP Kafka resource missing')
        result = subprocess.run(['kubectl', '-n', 'onap', 'wait', 'kafkas.kafka.strimzi.io', '--all',
                                 '--for=condition=Ready', '--timeout=20m'], capture_output=True, timeout=1230)
        if result.returncode:
            raise backend.Blocked('Kafka readiness deadline failed; no recovery attempted')
        fresh.wait_onap(path, 3600)
    return {'eligible':True, 'onap_accepted':True, 'private_archive':archive}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-slice', required=True)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.apply and os.environ.get('PHASE3_RECOVERY_LOCK_FD') != '9':
            raise backend.Blocked('Continuation apply requires the setup-driver lock')
        if args.apply:
            with backend.driver_lock():
                result = continue_startup(args.expected_slice, args.context, apply=True)
        else:
            result = continue_startup(args.expected_slice, args.context)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        # Never interpolate subprocess output, HTTP bodies, or credential data.
        print('Post-deployment continuation stopped: '+(str(error) if isinstance(error, backend.Blocked) else 'private validation failed'))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
