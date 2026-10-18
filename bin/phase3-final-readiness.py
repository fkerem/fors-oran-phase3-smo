#!/usr/bin/env python3
"""Audit and finish the exact retained r4 rollout-check failure; no deployment replay."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import phase3_checkout as checkout
import phase3_stateful_readiness as stateful

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SETUP = Path('/local/setup')
SLICE = 'urn:publicid:IDN+emulab.net:oransec+slice+p3-smo-cert-r4'
ERROR = 'error: rollout status is only available for RollingUpdate strategy type'
LOGS = {'/local/logs/setup.log': '5bff8ca18a270bc616241c8da6f752074035fb90a7e95b7216f8d878d07b6684',
        '/local/logs/setup-oran-smo.sh.log': 'a925c1f9e6bd339a8f69d436f21d9a24c2ff2f784d16135dd3f85f1ad7c4f4ac'}
MARKERS = ('setup-oran-smo-done', 'setup-driver-done')
PREREQUISITES = ('disk-space-done', 'nfs-server-done', 'nginx-done',
                 'ssl-done', 'kubespray-done', 'kubernetes-extra-done')
SCOPES = ('onap', 'nonrtric', 'network', 'strimzi-system')


def command(args, timeout=180):
    p = subprocess.run(args, capture_output=True, timeout=timeout)
    if p.returncode:
        raise ValueError('Required final-readiness operation failed; private output suppressed')
    return p.stdout


def sha(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Evidence must be a regular non-symlink file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def write_new(path, value):
    path = Path(path)
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def load(root, relative, name):
    spec = importlib.util.spec_from_file_location(name, root/relative)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def no_startup():
    ancestors = set(); pid = os.getpid()
    while pid > 1:
        ancestors.add(pid)
        fields = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        pid = int(fields[1])
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            args = path.read_bytes().split(b'\0')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if int(path.parent.name) not in ancestors and any(
                token.endswith((b'/setup-driver.sh', b'/setup-oran-smo.sh')) for token in args):
            raise ValueError('Another startup/continuation process exists')


def get(kind):
    return json.loads(command(['kubectl', 'get', kind, '-A', '-o', 'json',
                               '--request-timeout=30s']))['items']


def accepted_checks(root, context):
    sys.path[:0] = [str(root/'bin'), str(root/'tools')]
    fresh = load(root, 'bin/phase3-fresh-start.py', 'final_accepted_fresh')
    record = fresh.verify_context(context)
    required = ('sms_backend_contract', 'sms_preload_contract', 'dmaap_contract',
                'oru_readiness_contract', 'kong_proxy_contract')
    if record.get('slice_urn') != SLICE or any(type(record.get(k)) is not int or record[k] != 1 for k in required):
        raise ValueError('All exact fresh-allocation acceptance contracts are required')
    onap = json.loads((context.parent/'onap-acceptance.json').read_text())
    if (onap.get('passed') is not True or onap.get('slice_urn') != SLICE
            or onap.get('root_sha256') != record['root_sha256']):
        raise ValueError('Fresh ONAP acceptance binding is missing')
    gate = load(root, 'bin/phase3-onap-resume-gate.py', 'final_accepted_gate')
    result = gate.check(context_path=str(context))
    if result.get('ready') is not True or result.get('operator_stability_seconds', 0) < 3600:
        raise ValueError('Current one-hour operator/ONAP acceptance is required')
    oru = load(root, 'tools/phase3-oru-readiness.py', 'final_accepted_oru')
    oru.verify_fresh(context, bind_identity=False)
    kong = load(root, 'tools/phase3-kong-proxy.py', 'final_accepted_kong')
    kong.verify_fresh(context, SLICE, bind_identity=False)
    return record


def identity(obj):
    m = obj['metadata']
    result = {'kind': obj['kind'], 'namespace': m.get('namespace'), 'name': m['name'],
              'uid': m['uid'], 'generation': m.get('generation'),
              'spec_sha256': hashlib.sha256(canonical(obj.get('spec', {}))).hexdigest()}
    if obj['kind'] == 'Pod':
        result['containers'] = [{'name': c['name'], 'id': c.get('containerID'),
                                 'image': c.get('imageID'), 'restarts': c.get('restartCount', 0)}
                                for c in obj.get('status', {}).get('containerStatuses', [])
                                +obj.get('status', {}).get('initContainerStatuses', [])]
    return result


def snapshot(root):
    resources = {kind: get(kind) for kind in ('nodes', 'deployments,statefulsets', 'pods', 'pvc',
                                             'services', 'kafkas.kafka.strimzi.io', 'jobs')}
    nodes, workloads, pods, pvcs, services, kafkas, jobs = resources.values()
    releases = json.loads(command(['helm', 'list', '--all', '--all-namespaces', '-o', 'json']))
    assessor = load(root, 'bin/collect-phase3-provenance.py', 'final_assess_only')
    ready = stateful.ready
    simple_nodes = [{'name': n['metadata']['name'], 'ready': ready(n)} for n in nodes]
    simple_workloads = [{'namespace': w['metadata']['namespace'], 'name': w['metadata']['name'],
        'ready': w.get('status', {}).get('readyReplicas', 0) == w.get('spec', {}).get('replicas', 1)
        and w.get('status', {}).get('observedGeneration', 0) >= w['metadata'].get('generation', 1)} for w in workloads]
    simple_pods = [{'namespace': p['metadata']['namespace'], 'name': p['metadata']['name'],
                   'ready': ready(p), 'phase': p.get('status', {}).get('phase')} for p in pods]
    simple_pvcs = [{'namespace': p['metadata']['namespace'], 'name': p['metadata']['name'],
                   'phase': p.get('status', {}).get('phase')} for p in pvcs]
    simple_services = [{'namespace': s['metadata']['namespace'], 'name': s['metadata']['name']} for s in services]
    simple_kafkas = [{'namespace': k['metadata']['namespace'], 'name': k['metadata']['name'],
        'generation': k['metadata'].get('generation', 1), 'observed_generation': k.get('status', {}).get('observedGeneration', 0),
        'ready': ready(k)} for k in kafkas]
    simple_jobs = [{'namespace': j['metadata']['namespace'], 'name': j['metadata']['name'],
        'complete': any(c.get('type') == 'Complete' and c.get('status') == 'True' for c in j.get('status', {}).get('conditions', []))} for j in jobs]
    errors = assessor.assess(simple_nodes, simple_workloads, simple_pods, simple_pvcs,
                             releases, simple_services, simple_kafkas, simple_jobs)
    errors.extend(stateful.errors(workloads, pods, kafkas))
    if any(p['phase'] != 'Succeeded' and not p['ready'] for p in simple_pods):
        errors.append('An allocation Pod is not Ready or successfully completed')
    if any(j.get('status', {}).get('failed', 0) for j in jobs if j['metadata'].get('namespace') in SCOPES):
        errors.append('A required Job has failed execution history')
    if errors:
        raise ValueError('Current full-SMO readiness failed: '+errors[0])
    bound = []
    for kind, items in resources.items():
        for obj in items:
            if kind == 'nodes' or obj['metadata'].get('namespace') in SCOPES:
                bound.append(identity(obj))
    return {'resources': sorted(bound, key=lambda x:(x['kind'], x['namespace'] or '', x['name'])),
            'releases': sorted([{k: r.get(k) for k in ('namespace', 'name', 'revision', 'chart', 'status')}
                                for r in releases if r.get('namespace') in SCOPES], key=lambda r:(r['namespace'], r['name']))}


def inspect(expected_slice, accepted, after=False):
    if expected_slice != SLICE or command(['geni-get', 'slice_urn']).decode().strip() != SLICE:
        raise ValueError('Final continuation is restricted to the reviewed r4 allocation')
    if command(['hostname', '-s']).decode().strip() != 'node-0':
        raise ValueError('Final continuation must run on node-0')
    original = checkout.verify(accepted)
    if command(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=no']).strip():
        raise ValueError('Reviewed recovery checkout must remain clean')
    source = command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).decode().strip()
    no_startup()
    if any(not (SETUP/name).is_file() or (SETUP/name).is_symlink() for name in PREREQUISITES):
        raise ValueError('An infrastructure prerequisite is missing')
    if any((SETUP/name).exists() or (SETUP/name).is_symlink() for name in MARKERS):
        raise ValueError('A completion marker already exists; no adoption/replay')
    work = SETUP/'phase3-smo'; context = work/'fresh-start/context.json'
    for name, expected in LOGS.items():
        if sha(name) != expected:
            raise ValueError('Retained original startup log changed')
    if Path('/local/logs/setup-oran-smo.sh.log').read_text().splitlines()[-1].strip() != ERROR:
        raise ValueError('Not the reviewed final rollout-status failure')
    if not after and (work/'provenance.json').exists():
        raise ValueError('Final provenance already attempted; separate review required')
    if not after and (work/'final-readiness-acceptance.json').exists():
        raise ValueError('Final readiness already accepted; no adoption')
    before = {p.name: sha(p) for p in context.parent.glob('*.json')}
    record = accepted_checks(accepted, context)
    charts = {'chart-lock.json': sha(work/'chart-lock.json')}
    lock = json.loads((work/'chart-lock.json').read_text())
    for name in ('onap', 'nonrtric', 'ru-du-simulators'):
        change = json.loads((work/'prepared'/(name+'-changes.json')).read_text())
        if (change['original_sha256'] != lock['charts'][name]['sha256']
                or sha(work/'prepared'/(name+'.tgz')) != change['prepared_sha256']):
            raise ValueError('Prepared chart differs from accepted lock')
        charts[name] = sha(work/'prepared'/(name+'.tgz'))
    health = snapshot(accepted)
    if before != {p.name: sha(p) for p in context.parent.glob('*.json')}:
        raise ValueError('Accepted private evidence changed during validation')
    return {'schema': 1, 'slice': SLICE, 'source_commit': source, 'accepted_checkout': original,
            'node_uids': record['node_uids'], 'public_root_sha256': record['root_sha256'],
            'accepted_receipts': before, 'charts': charts, 'health': health, 'logs': LOGS}


def preserve(review, binding):
    directory = Path(tempfile.mkdtemp(prefix='final-readiness-evidence-', dir=str(review.parent)))
    os.chmod(directory, 0o700)
    files = {}
    for name in LOGS:
        dest = directory/Path(name).name
        shutil.copyfile(name, dest); os.chmod(dest, 0o600); files[dest.name] = sha(dest)
        if files[dest.name] != LOGS[name]:
            raise ValueError('Startup archive copy failed verification')
    write_new(directory/'binding.json', binding); files['binding.json'] = sha(directory/'binding.json')
    write_new(directory/'SHA256SUMS.json', {'files': files})
    return {'directory': str(directory), 'ledger_sha256': sha(directory/'SHA256SUMS.json')}


def verify_archive(record):
    directory = Path(record['directory'])
    if directory.is_symlink() or sha(directory/'SHA256SUMS.json') != record['ledger_sha256']:
        raise ValueError('Preserved original evidence archive changed')
    for name, expected in json.loads((directory/'SHA256SUMS.json').read_text())['files'].items():
        if Path(name).name != name or sha(directory/name) != expected:
            raise ValueError('Preserved evidence bytes changed')


def logged(args, path):
    with Path(path).open('xb') as output:
        os.chmod(path, 0o600)
        result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, timeout=900)
    if result.returncode:
        raise ValueError('Normal final-readiness/end-stage check failed; no retry')


def apply(expected_slice, accepted, review):
    old = json.loads(review.read_text())
    if old.get('passed') is not True:
        raise ValueError('Successful reviewed audit is required')
    verify_archive(old['archive'])
    if json.loads((Path(old['archive']['directory'])/'binding.json').read_text()) != old['binding']:
        raise ValueError('Review binding differs from its preserved source evidence')
    if inspect(expected_slice, accepted) != old['binding']:
        raise ValueError('Reviewed final-readiness binding changed')
    attempt = SETUP/'phase3-smo/final-readiness-attempt.json'
    write_new(attempt, {'schema': 1, 'review_sha256': sha(review), 'started_utc': datetime.now(timezone.utc).isoformat()})
    try:
        work = SETUP/'phase3-smo'
        output = review.parent/'final-provenance.json'
        logged([sys.executable, '-B', str(accepted/'bin/collect-phase3-provenance.py'),
                '--output', str(output), '--require-ready'], review.parent/'provenance.log')
        if json.loads(output.read_text()).get('readiness_errors') != []:
            raise ValueError('Full provenance was not accepted')
        if inspect(expected_slice, accepted) != old['binding']:
            raise ValueError('State changed during final provenance collection')
        logged([str(accepted/'setup-end.sh')], review.parent/'normal-end-stage.log')
        if inspect(expected_slice, accepted, after=True) != old['binding']:
            raise ValueError('State changed during normal completion checks')
        current = json.loads((work/'provenance.json').read_text())
        if current.get('readiness_errors') != []:
            raise ValueError('Normal final provenance failed')
        # Enrich the mutable status report, never rewrite historical acceptance.
        current['statefulset_readiness'] = {'verified': True, 'source_commit': old['binding']['source_commit']}
        current['retained_final_readiness'] = {'source_commit': old['binding']['source_commit'],
            'review_sha256': sha(review), 'original_profile_commit': checkout.PROFILE_PIN,
            'certificate_fault_cases_started': False}
        temporary = review.parent/'accepted-provenance.json'
        write_new(temporary, current)
        os.replace(str(temporary), str(work/'provenance.json'))
        # Check again after status publication; marker creation is exclusively gated.
        if inspect(expected_slice, accepted, after=True) != old['binding']:
            raise ValueError('State changed before completion marker publication')
        receipt = {'schema': 1, 'passed': True, 'slice': SLICE,
                   'review_sha256': sha(review), 'provenance_sha256': sha(work/'provenance.json'),
                   'completed_utc': datetime.now(timezone.utc).isoformat(),
                   'certificate_fault_cases_started': False}
        write_new(review.parent/'final-readiness-acceptance.json', receipt)
        write_new(work/'final-readiness-acceptance.json', receipt)
        for name in MARKERS:
            write_new(SETUP/name, {'verified_final_readiness_completion': True,
                                  'acceptance_sha256': sha(review.parent/'final-readiness-acceptance.json')})
    except BaseException as error:
        write_new(review.parent/'final-readiness-failure.json', {'schema': 1,
                  'failure_type': type(error).__name__, 'reason': str(error), 'automatic_retry': False})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--expected-slice', required=True)
    parser.add_argument('--accepted-checkout', type=Path, required=True)
    parser.add_argument('--review-file', type=Path, required=True)
    args = parser.parse_args(); os.umask(0o077)
    if args.audit == args.apply:
        parser.error('Select exactly one of --audit or --apply')
    review = args.review_file.resolve(); accepted = args.accepted_checkout.resolve(strict=True)
    try:
        if (not review.parent.is_dir() or review.parent.is_symlink()
                or review.parent.stat().st_mode & 0o077 or review.parent.stat().st_uid != os.getuid()):
            raise ValueError('A new private review directory is required')
        lock_path = SETUP/'phase3-driver.lock'
        if not lock_path.is_file() or lock_path.is_symlink():
            raise ValueError('Existing startup lock is required')
        if args.apply:
            fd = int(os.environ['PHASE3_RECOVERY_LOCK_FD'])
            if (os.fstat(fd).st_ino, os.fstat(fd).st_dev) != (lock_path.stat().st_ino, lock_path.stat().st_dev):
                raise ValueError('Driver lock binding differs')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            apply(args.expected_slice, accepted, review)
        else:
            with lock_path.open('r+') as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                if review.exists() or (SETUP/'phase3-smo/final-readiness-attempt.json').exists():
                    raise ValueError('Review or final attempt exists; no replay')
                binding = inspect(args.expected_slice, accepted)
                archive = preserve(review, binding)
                write_new(review, {'schema': 1, 'passed': True, 'binding': binding, 'archive': archive,
                                   'audited_utc': datetime.now(timezone.utc).isoformat()})
    except Exception as error:
        print('Final-readiness gate blocked ('+type(error).__name__+'); no deployment replay', file=sys.stderr)
        # Caller keeps stderr private; raw diagnostics never go to the public report.
        failure = review.parent/('audit-failure-'+str(os.getpid())+'.json')
        if not failure.exists():
            write_new(failure, {'failure_type': type(error).__name__, 'reason': str(error)})
        return 2
    print('Final-readiness '+('audit' if args.audit else 'continuation')+' passed; certificate tests remain separate')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
