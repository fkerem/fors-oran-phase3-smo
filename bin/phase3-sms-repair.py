#!/usr/bin/env python3
"""Audit/repair only SMS public chain and Service routing. Never replay preload."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
from urllib.parse import quote
import phase3_sms as sms
from phase3_lab_pki import private_write

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = Path('/local/setup/phase3-smo/fresh-start/context.json')
spec = importlib.util.spec_from_file_location('sms_fresh_repair', ROOT/'bin/phase3-fresh-start.py')
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
spec = importlib.util.spec_from_file_location('sms_existing_recovery', ROOT/'bin/phase3-onap-recovery.py')
recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def command(args, data=None, timeout=90):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if result.returncode: raise ValueError('SMS scoped command failed: '+args[0]+'; private output not printed')
    return result.stdout


def get(kind):
    return json.loads(command(['kubectl', '-n', 'onap', 'get', kind, '-o', 'json', '--request-timeout=30s']))


def protection():
    resources = get('statefulsets,pvc')['items']
    return {r['kind']+'/'+r['metadata']['name']: {'uid': r['metadata']['uid'],
        'spec_sha256': digest(r['spec'])} for r in resources}


def held_job():
    job = get('job/'+sms.JOB)
    if job['spec'].get('suspend') is not True or job.get('status', {}).get('active', 0):
        raise ValueError('SMS preload must remain suspended with no active execution')
    if any(any(o.get('uid') == job['metadata']['uid'] for o in p['metadata'].get('ownerReferences', [])) for p in get('pods')['items']):
        raise ValueError('SMS preload still has an owned Pod')
    if job.get('status', {}).get('succeeded', 0): raise ValueError('Completed preload requires a different review')
    return job


def inspect(slice_urn, rehearsal):
    context = fresh.verify_context(CONTEXT)
    if context['slice_urn'] != slice_urn or command(['hostname']).decode().strip().split('.')[0] != 'node-0':
        raise ValueError('SMS repair allocation mismatch')
    if any(Path('/local/setup', n).exists() for n in ('setup-driver-done', 'setup-oran-smo-done')):
        raise ValueError('Completed setup requires a different review')
    nodes = json.loads(command(['kubectl', 'get', 'nodes', '-o', 'json']))['items']
    if not all(any(c['type'] == 'Ready' and c['status'] == 'True' for c in n['status']['conditions']) for n in nodes):
        raise ValueError('Allocation Nodes are not all Ready')
    record = json.loads(Path(rehearsal).read_text())
    if (record.get('passed') is not True or record.get('image') != sms.IMAGE
            or record.get('preload_sha256') != sms.PRELOAD_SHA256
            or record.get('live_api_contacted') is not False
            or record.get('live_preload_authorized') is not False
            or record.get('chain_script_sha256') != hashlib.sha256((ROOT/'bin/phase3-sms-chain.sh').read_bytes()).hexdigest()
            or record.get('chain_controls') != {k: True for k in ('valid-stale-tail', 'wrong-root', 'wrong-hostname', 'expired-leaf')}):
        raise ValueError('Missing reviewed exact-image SMS rehearsal')
    job = held_job(); server = get('deployment/'+sms.NAME); service = get('service/'+sms.SERVICE)
    if any(r['metadata'].get('annotations', {}).get('meta.helm.sh/release-name') != 'onap-aaf' for r in (job, server, service)):
        raise ValueError('SMS Helm ownership differs from review')
    memory, gate = recovery.resume_gate.acceptance_record('/local/setup/phase3-smo/compatibility')
    operator = json.loads(command(['kubectl', '-n', 'strimzi-system', 'get', 'deployment/strimzi-cluster-operator', '-o', 'json']))
    operator_pods = json.loads(command(['kubectl', '-n', 'strimzi-system', 'get', 'pods', '-o', 'json']))['items']
    sample = recovery.resume_gate.compat.operator_sample(operator, operator_pods, memory)
    if sample is None or any(sample[k] != gate['observations'][-1][k] for k in sample):
        raise ValueError('Operator identity/restarts changed after its one-hour gate')
    dependencies = recovery.ready_pods(get('pods')['items'], ('aaf-locate', 'aaf-cm', 'aaf-service',
        'aaf-sms', 'aaf-sms-vault', 'aaf-sms-vault-backend', 'aaf-sms-quorumclient', 'dcae-ves-collector'), get('statefulsets')['items'])
    if (server['spec'].get('replicas') != 1 or server['status'].get('readyReplicas') != 1
            or server['status'].get('observedGeneration') != server['metadata']['generation']
            or server['spec'].get('strategy') != {'type': 'RollingUpdate', 'rollingUpdate': {'maxSurge': '25%', 'maxUnavailable': '25%'}}):
        raise ValueError('SMS needs the reviewed one-replica, old-Ready-preserving rollout')
    updated = sms.patch_deployment(server, context); narrowed = sms.patch_service(service)
    targets = {kind: {'uid': r['metadata']['uid'], 'resourceVersion': r['metadata']['resourceVersion'], 'spec_sha256': digest(r['spec'])}
        for kind, r in [('Deployment', server), ('Service', service), ('Job', job)]}
    review = {'schema': 1, 'operation': 'sms-public-chain-routing-only', 'slice_urn': slice_urn,
        'root_sha256': context['root_sha256'], 'targets': targets, 'protected': protection(),
        'context_sha256': hashlib.sha256(CONTEXT.read_bytes()).hexdigest(), 'operator': sample, 'dependencies': dependencies,
        'rehearsal': str(Path(rehearsal).resolve()), 'rehearsal_sha256': hashlib.sha256(Path(rehearsal).read_bytes()).hexdigest(),
        'helper_sha256': digest(sms.config(context)), 'new_template_sha256': digest(updated['spec']['template']),
        'new_selector': narrowed['spec']['selector'], 'preload_replay_authorized': False}
    return review, context, (server, service, job)


def tls_leaf(context, ip):
    tls = ssl.create_default_context(cafile=str(Path(context['pki_directory'])/'root.cer'))
    with socket.create_connection((ip, 10443), timeout=15) as transport:
        with tls.wrap_socket(transport, server_hostname='aaf-sms.onap') as session:
            return hashlib.sha256(session.getpeercert(binary_form=True)).hexdigest()


def expected_domains():
    config = get('configmap/'+sms.JOB)['data']
    if set(config) != {'has.json', 'osdf.json'}: raise ValueError('Unexpected preload input inventory')
    result = []
    for blob in config.values():
        domain = json.loads(blob)['domain']
        if not isinstance(domain['name'], str) or '$' in domain['name'] or '/' in domain['name']:
            raise ValueError('Unexpected preload domain')
        result.append(domain['name'])
    if len(set(result)) != 2: raise ValueError('Unexpected domain cardinality')
    return result


def partial_audit(context, service):
    """Read-only names only. HTTP 500/empty list NEVER proves an absent domain."""
    tls = ssl.create_default_context(cafile=str(Path(context['pki_directory'])/'root.cer'))
    observations = []
    for domain in expected_domains():
        connection = http.client.HTTPSConnection('aaf-sms.onap', 10443, timeout=15, context=tls)
        connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(
            (service['spec']['clusterIP'], 10443), timeout)
        try:
            connection.request('GET', '/v1/sms/domain/'+quote(domain, safe='')+'/secret')
            response = connection.getresponse(); blob = response.read(1024*1024)
            observation = {'http_status': response.status, 'absence_proved': False}
            if response.status == 200:
                names = json.loads(blob).get('secretnames')
                if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
                    raise ValueError('Unexpected SMS read-only metadata shape')
                observation.update({'secret_count': len(names), 'preexisting_objects_observed': bool(names)})
            observations.append(observation)
        finally: connection.close()
    return {'read_only': True, 'domain_count': len(observations), 'observations': observations,
        'no_partial_effects_proved': False, 'preload_replay_authorized': False,
        'decision': 'stop for review; do not infer absence from empty names or backend HTTP errors'}


def apply(review, context, objects, path):
    directory = path.parent/(path.stem+'-apply'); directory.mkdir(mode=0o700)
    files = {}
    def save(name, value):
        blob = value if isinstance(value, bytes) else (json.dumps(value, indent=2)+'\n').encode()
        private_write(directory/name, blob); files[name] = hashlib.sha256(blob).hexdigest()
    for name, obj in zip(('deployment-before.json', 'service-before.json', 'job-held-before.json'), objects): save(name, obj)
    for pod in get('pods')['items']:
        if any(c['name'] == 'aaf-sms' for c in pod['spec']['containers']):
            save('server-pod-before.json', pod)
            for c in pod['spec'].get('initContainers', [])+pod['spec']['containers']:
                save(c['name']+'.log', command(['kubectl', '-n', 'onap', 'logs', pod['metadata']['name'], '-c', c['name'], '--timestamps']))
    save('preservation.json', {'files_sha256': files.copy()})
    if not all(hashlib.sha256((directory/n).read_bytes()).hexdigest() == d for n, d in files.items()):
        raise ValueError('Private pre-change preservation failed')
    if inspect(review['slice_urn'], review['rehearsal'])[0] != review:
        raise ValueError('SMS audited state changed during preservation')
    cm = sms.config(context)
    existing = command(['kubectl', '-n', 'onap', 'get', 'configmap/'+cm['metadata']['name'], '--ignore-not-found', '-o', 'json']).strip()
    if existing:
        actual = json.loads(existing)
        if any(actual.get(k) != cm.get(k) for k in ('data', 'immutable')): raise ValueError('SMS immutable helper differs')
    else: command(['kubectl', 'create', '-f', '-'], json.dumps(cm).encode())
    server, service, old_job = objects
    updated = sms.patch_deployment(server, context)
    patch = [{'op': 'test', 'path': '/metadata/'+key, 'value': server['metadata'][key]} for key in ('uid', 'resourceVersion')]
    patch.append({'op': 'replace', 'path': '/spec/template', 'value': updated['spec']['template']})
    command(['kubectl', '-n', 'onap', 'patch', 'deployment/'+sms.NAME, '--type=json', '-p', json.dumps(patch)])
    command(['kubectl', '-n', 'onap', 'rollout', 'status', 'deployment/'+sms.NAME, '--timeout=15m'], timeout=930)
    current = get('deployment/'+sms.NAME)
    if current['metadata']['uid'] != server['metadata']['uid']: raise ValueError('SMS Deployment UID changed')
    sms.verify(current, context)
    deadline = time.monotonic()+180; stable_uid = None; stable_since = None; leaf = None
    while True:
        held = held_job()
        if held['metadata']['uid'] != old_job['metadata']['uid'] or held['spec'] != old_job['spec']:
            raise ValueError('Held preload changed during SMS repair')
        pods = [p for p in get('pods')['items'] if p['metadata'].get('labels', {}).get(sms.ROLE) == 'server' and not p['metadata'].get('deletionTimestamp')]
        if len(pods) != 1: raise ValueError('Expected exactly one repaired SMS server Pod')
        pod = pods[0]; sms.verify(pod, context)
        statuses = pod['status'].get('containerStatuses', [])
        if (len(statuses) != 1 or statuses[0].get('restartCount') != 0 or not statuses[0].get('ready')
                or not all(s['state'].get('terminated', {}).get('exitCode') == 0 for s in pod['status'].get('initContainerStatuses', []))):
            raise ValueError('SMS repaired Pod failed its no-restart/initializer gate')
        rs = get('replicaset/'+pod['metadata']['ownerReferences'][0]['name'])
        if not any(o.get('uid') == server['metadata']['uid'] and o.get('kind') == 'Deployment' for o in rs['metadata']['ownerReferences']):
            raise ValueError('SMS server owner chain differs')
        leaf = tls_leaf(context, pod['status']['podIP'])
        if stable_uid != pod['metadata']['uid']:
            stable_uid = pod['metadata']['uid']; stable_since = time.monotonic()
        if time.monotonic()-stable_since >= 120: break
        if time.monotonic() > deadline: raise ValueError('SMS stability window did not complete')
        time.sleep(5)
    # Old Service still serves a healthy server until the new role-labelled Pod is verified.
    current_service = get('service/'+sms.SERVICE)
    if current_service != service: raise ValueError('SMS Service drifted before narrowing')
    patch = [{'op': 'test', 'path': '/metadata/'+key, 'value': service['metadata'][key]} for key in ('uid', 'resourceVersion')]
    patch.append({'op': 'replace', 'path': '/spec/selector', 'value': sms.patch_service(service)['spec']['selector']})
    command(['kubectl', '-n', 'onap', 'patch', 'service/'+sms.SERVICE, '--type=json', '-p', json.dumps(patch)])
    deadline = time.monotonic()+60
    while True:
        endpoints = [ep for r in get('endpointslices')['items']
            if r['metadata'].get('labels', {}).get('kubernetes.io/service-name') == sms.SERVICE for ep in r.get('endpoints', [])]
        if (len(endpoints) == 1 and endpoints[0].get('targetRef', {}).get('uid') == stable_uid
                and endpoints[0].get('conditions', {}).get('ready') is True): break
        if time.monotonic() >= deadline: raise ValueError('SMS Service endpoints do not exclusively identify the repaired server')
        time.sleep(2)
    service = get('service/'+sms.SERVICE)
    service_leaf = tls_leaf(context, service['spec']['clusterIP'])
    if service_leaf != leaf: raise ValueError('SMS Service/Pod TLS identity differs')
    if protection() != review['protected']: raise ValueError('Protected storage/StatefulSet identity or specification changed')
    fresh.verify_context(CONTEXT)
    audit = partial_audit(context, service); save('partial-effects-audit.json', audit)
    held = held_job()
    if held['metadata']['uid'] != old_job['metadata']['uid'] or held['spec'] != old_job['spec']:
        raise ValueError('Preload state drifted at final acceptance')
    for name, obj in [('deployment-after.json', get('deployment/'+sms.NAME)), ('service-after.json', service), ('job-held-after.json', held), ('server-pod-after.json', pod)]: save(name, obj)
    result = {'schema': 1, 'passed': True, 'scope': 'SMS public chain and Service only',
        'utc': datetime.now(timezone.utc).isoformat(), 'slice_urn': context['slice_urn'],
        'deployment_uid': server['metadata']['uid'], 'server_pod_uid': stable_uid,
        'root_sha256': context['root_sha256'], 'server_leaf_sha256': leaf,
        'root_only_tls_hostname_verified': 'aaf-sms.onap', 'ready_window_seconds': 120,
        'exclusive_endpoint_uid': stable_uid, 'held_job_uid': held['metadata']['uid'],
        'protected_objects_unchanged': True, 'normal_aaf_leaf_retrieval_on_rollout': True,
        'ca_rotated': False, 'preload_replayed': False, 'dmaap_started': False,
        'partial_effects_audit': audit, 'private_archive': str(directory)}
    save('result.json', result); save('final-hashes.json', {'files_sha256': files.copy()})
    return result


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-slice', required=True); parser.add_argument('--rehearsal', required=True)
    parser.add_argument('--review-file', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--audit', action='store_true'); mode.add_argument('--apply', action='store_true')
    args = parser.parse_args(); path = Path(args.review_file).resolve()
    try:
        with open('/local/setup/phase3-driver.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            review, context, objects = inspect(args.expected_slice, args.rehearsal)
            if args.audit:
                private_write(path, (json.dumps({'created_utc': datetime.now(timezone.utc).isoformat(), 'review': review}, indent=2)+'\n').encode())
                print('SMS public-chain/routing audit passed; preload remains held')
            else:
                approved = json.loads(path.read_text())
                age = (datetime.now(timezone.utc)-datetime.fromisoformat(approved['created_utc'])).total_seconds()
                if not 0 <= age <= 1800 or approved['review'] != review: raise ValueError('SMS review expired or state changed')
                apply(review, context, objects, path)
                print('SMS public-chain/routing repair passed; preload remains held for write-safety review')
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as error:
        parser.exit(1, 'SMS scoped repair refused/stopped: '+str(error)+'\n')
