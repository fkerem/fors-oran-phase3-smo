#!/usr/bin/env python3
"""Audit then explicitly recover one reviewed ONAP target. No broad Helm replay."""
import argparse
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
import yaml
import phase3_ves
from phase3_fresh import READINESS_IMAGE, helper_config
from phase3_lab_pki import AGENT_IMAGE, private_write
from phase3_recovery_guards import executed

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fresh_start', ROOT/'bin/phase3-fresh-start.py')
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
spec = importlib.util.spec_from_file_location('resume_gate', ROOT/'bin/phase3-onap-resume-gate.py')
resume_gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(resume_gate)
TARGETS = {'ves': phase3_ves.NAME, 'sms': 'onap-aaf-sms-preload', 'dmaap': 'onap-dmaap-bc-dmaap-provisioning'}
RELEASES = {'sms': 'onap-aaf', 'dmaap': 'onap-dmaap', 'ves': 'onap-dcaegen2-services'}
MAINS = {'sms': 'nexus3.onap.org:10001/onap/aaf/sms:4.0.2',
         'dmaap': 'nexus3.onap.org:10001/onap/dmaap/dbc-client:1.0.9'}
AGENT_COMMAND = ['sh', '-c', '/opt/app/aaf_config/bin/agent.sh\n. /opt/app/aaf_config/bin/retrieval_check.sh\n/opt/app/aaf_config/bin/aaf-add-config.sh\n']
CONTEXT = Path('/local/setup/phase3-smo/fresh-start/context.json')


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def command(argv, data=None, timeout=90):
    result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise ValueError('Recovery command failed: '+argv[0]+'; no private output printed')
    return result.stdout


def get(resource):
    return json.loads(command(['kubectl', '-n', 'onap', 'get', resource, '-o', 'json', '--request-timeout=30s']))


def logs(pod, container):
    return command(['kubectl', '-n', 'onap', 'logs', pod, '-c', container, '--timestamps']).decode()


def condition(resource, name):
    return any(c['type'] == name and c['status'] == 'True' for c in resource.get('status', {}).get('conditions', []))


def contract(container):
    result = {k: copy.deepcopy(container[k]) for k in ('name', 'image', 'command', 'args', 'env', 'envFrom', 'volumeMounts') if k in container}
    if 'volumeMounts' in result:
        result['volumeMounts'] = [m for m in result['volumeMounts'] if m.get('mountPath') != '/var/run/secrets/kubernetes.io/serviceaccount']
    return result


def manifest_guard(job, expected):
    """Admission defaults may differ, but executable/config/storage inputs may not."""
    actual = job['spec']['template']['spec']; baseline = expected['spec']['template']['spec']
    for group in ('initContainers', 'containers'):
        if [contract(c) for c in actual.get(group, [])] != [contract(c) for c in baseline.get(group, [])]:
            raise ValueError('Job executable contract differs from retained Helm manifest')
    def volumes(spec):
        result = copy.deepcopy(spec.get('volumes', []))
        for volume in result:
            for key in ('configMap', 'secret'):
                if volume.get(key, {}).get('defaultMode') == 420:
                    volume[key].pop('defaultMode')
            if volume.get('hostPath', {}).get('type') == '':
                volume['hostPath'].pop('type')
        return result
    if (volumes(actual) != volumes(baseline) or actual.get('restartPolicy') != baseline.get('restartPolicy')
            or actual.get('serviceAccountName', 'default') != baseline.get('serviceAccountName', 'default')):
        raise ValueError('Job configuration/storage differs from retained Helm manifest')


def job_guard(target, job, pods):
    meta = job['metadata']; status = job.get('status', {})
    if (target not in MAINS or meta.get('namespace') != 'onap' or meta['name'] != TARGETS[target]
            or meta.get('annotations', {}).get('meta.helm.sh/release-name') != RELEASES[target]
            or 'helm.sh/hook' in meta.get('annotations', {}) or meta.get('deletionTimestamp')):
        raise ValueError('Unreviewed Job identity/ownership')
    if (not condition(job, 'Failed') or status.get('active', 0) or status.get('succeeded', 0)
            or status.get('failed') != 1 or job['spec'].get('backoffLimit') != 0):
        raise ValueError('Expected exactly one terminal failed first-attempt Job')
    owned = [p for p in pods if any(o.get('kind') == 'Job' and o.get('uid') == meta['uid'] for o in p['metadata'].get('ownerReferences', []))]
    if len(owned) != 1 or owned[0].get('status', {}).get('phase') != 'Failed':
        raise ValueError('Incomplete retained failed-Pod history')
    pod = owned[0]; spec = job['spec']['template']['spec']
    if spec.get('restartPolicy') != 'Never' or len(spec.get('containers', [])) != 1 or spec['containers'][0]['image'] != MAINS[target]:
        raise ValueError('Unexpected main image or restart policy')
    main_command = spec['containers'][0].get('command', [])
    if target == 'dmaap' and (main_command or spec['containers'][0].get('args')):
        raise ValueError('Unexpected DMAAP main entry point')
    if target == 'sms' and main_command != ['/sms/bin/preload', '-cacert', '/opt/app/osaaf/local/aaf_root_ca.cer',
            '-jsondir', '/preload/config', '-serviceport', '10443', '-serviceurl', 'https://aaf-sms.onap']:
        raise ValueError('Unexpected SMS main entry point')
    for group in ('initContainers', 'containers'):
        if [contract(c) for c in spec.get(group, [])] != [contract(c) for c in pod['spec'].get(group, [])]:
            raise ValueError('Retained Pod differs from audited Job')
    main = pod['status'].get('containerStatuses', [])
    if len(main) != 1 or main[0]['name'] != spec['containers'][0]['name'] or executed(main[0]):
        raise ValueError('Main execution observed or history missing; replay refused')
    declared = spec.get('initContainers', [])
    states = {s['name']: s for s in pod['status'].get('initContainerStatuses', [])}
    if set(states) != {c['name'] for c in declared}:
        raise ValueError('Incomplete initializer execution history')
    if target == 'dmaap':
        if (len(declared) != 1 or declared[0]['image'] != READINESS_IMAGE
                or declared[0].get('command') != ['/phase3-helpers/phase3-readiness-wrapper.py']
                or declared[0].get('args') != ['--container-name', 'dmaap-bc']):
            raise ValueError('Unreviewed DMAAP readiness initializer')
    else:
        if [c['name'] for c in declared] != ['aaf-sms-cert-init-readiness', 'aaf-sms-aaf-config', 'aaf-sms-update-config', 'aaf-sms-readiness']:
            raise ValueError('Unexpected SMS initializer ordering')
        agent = declared[1]
        if agent['image'] != AGENT_IMAGE or agent.get('command') != AGENT_COMMAND or agent.get('args'):
            raise ValueError('Unreviewed SMS agent')
        env = {e['name']: e.get('value') for e in agent.get('env', [])}
        if env.get('APP_FQI') != 'aaf-sms@aaf-sms.onap.org' or env.get('aaf_locator_fqdn') != 'aaf-sms':
            raise ValueError('Unexpected SMS issuance identity')
        if states[agent['name']].get('state', {}).get('terminated', {}).get('exitCode') != 1:
            raise ValueError('Not the reviewed SMS retrieval failure')
        for later in declared[2:]:
            if executed(states[later['name']]):
                raise ValueError('SMS post-certificate initializer already ran')
        # Certificate output may be recreated only in the reviewed Pod-local volume.
        volumes = {v['name']: v for v in spec.get('volumes', [])}
        mount = next((m for m in agent.get('volumeMounts', []) if m['mountPath'] == '/opt/app/osaaf'), {})
        if 'emptyDir' not in volumes.get(mount.get('name'), {}):
            raise ValueError('SMS issuance artifacts are not Pod-local')
    return pod


def sms_proof(pod, cm, client_log, cm_log):
    """Only the same Pod IP/time window's pre-issuance 403 is replay-eligible."""
    if cm['status']['containerStatuses'][0].get('restartCount') != 0:
        raise ValueError('Certificate-manager log history is incomplete')
    state = next(s for s in pod['status']['initContainerStatuses'] if s['name'] == 'aaf-sms-aaf-config')['state']['terminated']
    start = datetime.fromisoformat(state['startedAt'].replace('Z', '+00:00'))
    end = datetime.fromisoformat(state['finishedAt'].replace('Z', '+00:00'))
    ip = pod['status'].get('podIP')
    if not ip or 'FAILED to get Certificate' not in client_log or 'Obtained Certificates' in client_log:
        raise ValueError('Ambiguous client-side issuance result')
    requests = []
    for line in cm_log.splitlines():
        if 'ip='+ip+',' not in line or 'meth=PUT,path=/cert/' not in line:
            continue
        stamp = datetime.fromisoformat(line.split()[0].replace('Z', '+00:00'))
        if not start <= stamp <= end:
            continue
        if not ('status=403,' in line and 'SVC1403' in line and 'Sponsorship cannot be determined' in line):
            raise ValueError('Possible certificate issuance or different server failure; replay refused')
        requests.append(line)
    if not requests or len(requests) > 2:
        raise ValueError('Missing or unexpected certificate request history')
    return {'pod_ip': ip, 'cm_uid': cm['metadata']['uid'], 'preissuance_forbidden_count': len(requests),
            'matched_requests_sha256': sha(requests), 'client_log_sha256': hashlib.sha256(client_log.encode()).hexdigest()}


def ready_pods(pods, names):
    result = []
    now = datetime.now(timezone.utc)
    for name in names:
        matches = [p for p in pods if not p['metadata'].get('deletionTimestamp') and any(c['name'] == name for c in p['spec'].get('containers', []))]
        if len(matches) != 1 or not condition(matches[0], 'Ready'):
            raise ValueError('Prerequisite not uniquely Ready: '+name)
        pod = matches[0]
        transition = next(c['lastTransitionTime'] for c in pod['status']['conditions'] if c['type'] == 'Ready')
        if (now-datetime.fromisoformat(transition.replace('Z', '+00:00'))).total_seconds() < 120:
            raise ValueError('Prerequisite has not been Ready for two minutes: '+name)
        result.append({'uid': pod['metadata']['uid'], 'restarts': {s['name']: s.get('restartCount', 0) for s in pod['status']['containerStatuses']}})
    return result


def inspect(target, expected_slice, rehearsal=None):
    context = fresh.verify_context(CONTEXT)
    if context['slice_urn'] != expected_slice or command(['hostname']).decode().strip().split('.')[0] != 'node-0':
        raise ValueError('Recovery allocation mismatch')
    if Path('/local/setup/setup-driver-done').exists() or Path('/local/setup/setup-oran-smo-done').exists():
        raise ValueError('Setup already complete')
    pods = get('pods')['items']
    obj = get(('deployment/' if target == 'ves' else 'job/')+TARGETS[target])
    record = {'schema': 1, 'target': target, 'slice_urn': expected_slice,
              'context_sha256': hashlib.sha256(CONTEXT.read_bytes()).hexdigest(), 'root_sha256': context['root_sha256'],
              'uid': obj['metadata']['uid'], 'resource_version': obj['metadata']['resourceVersion'],
              'object_sha256': sha(obj)}
    memory, gate = resume_gate.acceptance_record('/local/setup/phase3-smo/compatibility')
    operator_deploy = json.loads(command(['kubectl', '-n', 'strimzi-system', 'get', 'deployment/strimzi-cluster-operator', '-o', 'json']))
    operator_pods = json.loads(command(['kubectl', '-n', 'strimzi-system', 'get', 'pods', '-o', 'json']))['items']
    sample = resume_gate.compat.operator_sample(operator_deploy, operator_pods, memory)
    if sample is None or any(sample[k] != gate['observations'][-1][k] for k in sample):
        raise ValueError('Operator changed after its one-hour gate')
    record['operator'] = sample
    if target == 'ves':
        if obj['metadata'].get('annotations', {}).get('meta.helm.sh/release-name') != RELEASES[target]:
            raise ValueError('VES ownership mismatch')
        phase3_ves.patch_deployment(obj, context)
        replicasets = get('replicasets')['items']
        rsuids = {r['metadata']['uid'] for r in replicasets if any(o.get('uid') == obj['metadata']['uid'] for o in r['metadata'].get('ownerReferences', []))}
        owned = [p for p in pods if any(o.get('uid') in rsuids for o in p['metadata'].get('ownerReferences', [])) and not p['metadata'].get('deletionTimestamp')]
        if len(owned) != 1 or any(executed(s) for s in owned[0]['status'].get('containerStatuses', [])):
            raise ValueError('VES main ran, or Pod history differs from review')
        record['pod_uid'] = owned[0]['metadata']['uid']
        if not rehearsal:
            raise ValueError('Exact-image isolated VES rehearsal receipt is required')
        receipt = json.loads(Path(rehearsal).read_text())
        control = receipt.get('ves_rehearsal', {})
        if not receipt.get('passed') or not control.get('passed') or control.get('image') != phase3_ves.IMAGE:
            raise ValueError('VES rehearsal did not pass with the reviewed image')
        record['rehearsal'] = {'path': str(Path(rehearsal).resolve()), 'sha256': hashlib.sha256(Path(rehearsal).read_bytes()).hexdigest()}
        record['dependencies'] = ready_pods(pods, ('aaf-locate', 'aaf-cm', 'aaf-service'))
    else:
        manifest = command(['helm', 'get', 'manifest', RELEASES[target], '-n', 'onap']).decode()
        baselines = [r for r in yaml.safe_load_all(manifest) if r and r.get('kind') == 'Job' and r['metadata']['name'] == TARGETS[target]]
        if len(baselines) != 1:
            raise ValueError('Missing retained Helm Job manifest')
        manifest_guard(obj, baselines[0])
        record['helm_job_sha256'] = sha(baselines[0])
        pod = job_guard(target, obj, pods)
        record['pod_uid'] = pod['metadata']['uid']
        if target == 'sms':
            cm = next(p for p in pods if any(c['name'] == 'aaf-cm' for c in p['spec'].get('containers', [])))
            record['issuance_proof'] = sms_proof(pod, cm, logs(pod['metadata']['name'], 'aaf-sms-aaf-config'), logs(cm['metadata']['name'], 'aaf-cm'))
            record['dependencies'] = ready_pods(pods, ('aaf-locate', 'aaf-cm', 'aaf-service', 'aaf-sms', 'aaf-sms-quorumclient', 'dcae-ves-collector'))
        else:
            record['dependencies'] = ready_pods(pods, ('dmaap-bc', 'dcae-ves-collector'))
            if not condition(get('job/'+TARGETS['sms']), 'Complete'):
                raise ValueError('SMS must complete before DMAAP recovery')
    return record, context, obj, owned if target == 'ves' else [pod]


def new_job(job, target):
    result = {k: copy.deepcopy(job[k]) for k in ('apiVersion', 'kind', 'metadata', 'spec')}
    result['metadata'] = {k: result['metadata'][k] for k in ('name', 'namespace', 'labels', 'annotations') if k in result['metadata']}
    spec = result['spec']; spec.pop('selector', None); spec['suspend'] = True; spec['backoffLimit'] = 0
    labels = spec['template'].get('metadata', {}).get('labels', {})
    for key in ('controller-uid', 'job-name', 'batch.kubernetes.io/controller-uid', 'batch.kubernetes.io/job-name'):
        labels.pop(key, None)
    if target == 'dmaap':
        spec['template']['spec']['initContainers'][0]['args'] += ['--timeout', '30']
    return result


def preserve(directory, obj, pods):
    files = {}
    def save(name, value):
        data = value if isinstance(value, bytes) else json.dumps(value, indent=2).encode()+b'\n'
        private_write(directory/name, data); files[name] = hashlib.sha256(data).hexdigest()
    save('before.json', obj)
    for index, pod in enumerate(pods):
        save('pod-'+str(index)+'.json', pod)
        for status in pod['status'].get('initContainerStatuses', [])+pod['status'].get('containerStatuses', []):
            if status.get('containerID'):
                save('pod-'+str(index)+'-'+status['name']+'.log', logs(pod['metadata']['name'], status['name']).encode())
    save('preservation.json', {'files_sha256': files.copy(), 'private': True})
    for name, digest in files.items():
        if hashlib.sha256((directory/name).read_bytes()).hexdigest() != digest:
            raise ValueError('Preserved evidence verification failed')


def apply(review, path):
    target = review['target']
    rehearsal = review.get('rehearsal', {}).get('path')
    current, context, obj, pods = inspect(target, review['slice_urn'], rehearsal)
    if current != review:
        raise ValueError('Audited state changed; a new review is required')
    directory = path.parent/(path.stem+'-apply')
    directory.mkdir(mode=0o700)
    preserve(directory, obj, pods)
    # Preserve diagnostics first, then revalidate all refusal gates immediately before mutation.
    if inspect(target, review['slice_urn'], rehearsal)[0] != review:
        raise ValueError('State changed during evidence preservation')
    if target == 'ves':
        cm = phase3_ves.config(context)
        command(['kubectl', 'create', '-f', '-'], json.dumps(cm).encode())
        updated = phase3_ves.patch_deployment(obj, context)
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': review['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': review['resource_version']},
                 {'op': 'replace', 'path': '/spec/template', 'value': updated['spec']['template']}]
        command(['kubectl', '-n', 'onap', 'patch', 'deployment/'+TARGETS[target], '--type=json', '-p', json.dumps(patch)])
        command(['kubectl', '-n', 'onap', 'rollout', 'status', 'deployment/'+TARGETS[target], '--timeout=15m'], timeout=930)
    else:
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Foreground',
                   'preconditions': {'uid': review['uid'], 'resourceVersion': review['resource_version']}}
        command(['kubectl', 'delete', '--raw', '/apis/batch/v1/namespaces/onap/jobs/'+TARGETS[target], '-f', '-'], json.dumps(options).encode())
        deadline = time.monotonic()+90
        while command(['kubectl', '-n', 'onap', 'get', 'job/'+TARGETS[target], '--ignore-not-found', '-o', 'name']).strip():
            if time.monotonic() > deadline:
                raise ValueError('Exact failed Job deletion did not complete; no force deletion')
            time.sleep(2)
        held = json.loads(command(['kubectl', 'create', '-f', '-', '-o', 'json'], json.dumps(new_job(obj, target)).encode()))
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': held['metadata']['uid']},
                 {'op': 'test', 'path': '/spec', 'value': held['spec']},
                 {'op': 'test', 'path': '/spec/suspend', 'value': True}, {'op': 'replace', 'path': '/spec/suspend', 'value': False}]
        command(['kubectl', '-n', 'onap', 'patch', 'job/'+TARGETS[target], '--type=json', '-p', json.dumps(patch)])
        deadline = time.monotonic()+1800
        while True:
            live = get('job/'+TARGETS[target])
            if live['metadata']['uid'] != held['metadata']['uid'] or condition(live, 'Failed') or condition(live, 'FailureTarget'):
                raise ValueError('Recovered Job failed or changed; no automatic retry')
            if condition(live, 'Complete'):
                break
            if time.monotonic() > deadline:
                raise ValueError('Recovered Job did not complete within the bounded observation')
            time.sleep(10)
    fresh.verify_context(CONTEXT)
    record = {'passed': True, 'target': target, 'previous_uid': review['uid'],
              'current_uid': get(('deployment/' if target == 'ves' else 'job/')+TARGETS[target])['metadata']['uid'],
              'root_sha256': context['root_sha256'], 'completed_utc': datetime.now(timezone.utc).isoformat(),
              'certificate_fault_cases_started': False}
    private_write(directory/'result.json', (json.dumps(record, indent=2)+'\n').encode())
    return record


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=TARGETS, required=True)
    parser.add_argument('--expected-slice', required=True)
    parser.add_argument('--review-file', required=True)
    parser.add_argument('--ves-rehearsal')
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--audit', action='store_true'); modes.add_argument('--apply', action='store_true')
    args = parser.parse_args(); path = Path(args.review_file).resolve()
    try:
        with open('/local/setup/phase3-driver.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.audit:
                record = inspect(args.target, args.expected_slice, args.ves_rehearsal)[0]
                private_write(path, (json.dumps(record, indent=2)+'\n').encode())
            else:
                record = json.loads(path.read_text())
                if record['target'] != args.target or record['slice_urn'] != args.expected_slice:
                    raise ValueError('Review target/allocation mismatch')
                record = apply(record, path)
            print('ONAP '+args.target+' '+('audit' if args.audit else 'recovery')+' passed; private receipt: '+str(path))
    except (OSError, ValueError, RuntimeError, KeyError, StopIteration, subprocess.TimeoutExpired) as error:
        parser.exit(1, 'ONAP recovery refused/stopped: '+str(error)+'\n')
