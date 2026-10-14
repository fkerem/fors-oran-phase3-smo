#!/usr/bin/env python3
"""Audit by default; pin and recreate only three exact stalled, unstarted Pods."""
import copy
import json
import time
from phase3_scoped_recovery import TARGETS, digest, execute, flow, normalized_pod_spec, one, owned, placement_patch, stalled_guard, stateful_template_spec


def replacement_ready(ss, pod, old, pinned_spec):
    if ss['spec'] != pinned_spec or ss['metadata']['uid'] != old['statefulset']['metadata']['uid']:
        raise ValueError('Pinned StatefulSet changed during rollout')
    if pod['metadata']['uid'] == old['pod']['metadata']['uid']:
        return False
    if pod['metadata'].get('deletionTimestamp'):
        raise ValueError('Replacement is terminating')
    if not pod['spec'].get('nodeName'):
        return False
    if pod['spec']['nodeName'] != old['proof']['node']:
        raise ValueError('Replacement is terminating or on a different storage node')
    if normalized_pod_spec(pod['spec']) != stateful_template_spec(ss, pod['metadata']['name']):
        raise ValueError('Replacement Pod application contract changed')
    if any(s.get('restartCount', 0) or s.get('lastState') or s.get('state', {}).get('terminated', {}).get('exitCode', 0)
           for s in pod.get('status', {}).get('initContainerStatuses', [])):
        raise ValueError('Replacement stock initializer failed/restarted')
    if pod['metadata'].get('labels', {}).get('controller-revision-hash') != ss.get('status', {}).get('updateRevision'):
        return False
    statuses = pod.get('status', {}).get('containerStatuses', [])
    expected = {c['name']: c['image'] for c in pinned_spec['template']['spec']['containers']}
    for s in statuses:
        if s.get('restartCount', 0) or s.get('lastState') or s.get('state', {}).get('terminated'):
            raise ValueError('Replacement main container failed/restarted')
        if s.get('imageID') and not s['imageID'].endswith(expected[s['name']].split('@')[1]):
            raise ValueError('Replacement resolved a different image digest')
    status = ss.get('status', {})
    return (status.get('observedGeneration', 0) >= ss['metadata']['generation']
            and status.get('readyReplicas') == status.get('updatedReplicas') == 1
            and status.get('currentRevision') == status.get('updateRevision')
            and len(statuses) == len(expected) and all(s.get('ready') and s.get('imageID') for s in statuses))


def live_controls(pod):
    name = pod['metadata']['name']
    main = pod['spec']['containers'][0]['name']
    if name.startswith(('onap-mariadb-galera-', 'onap-policy-mariadb-')):
        sql = flow.run(['kubectl', '-n', 'onap', 'exec', name, '-c', main, '--', 'bash', '-ec',
                        '/opt/bitnami/mariadb/bin/mysql -uroot -p"$MARIADB_ROOT_PASSWORD" -N -e "SELECT 1; SHOW STATUS WHERE Variable_name IN (\'wsrep_ready\',\'wsrep_cluster_status\',\'wsrep_cluster_size\');"'], timeout=30).decode()
        values = dict(line.split('\t', 1) for line in sql.splitlines() if '\t' in line)
        if sql.splitlines()[0] != '1' or values != {'wsrep_ready': 'ON', 'wsrep_cluster_status': 'Primary', 'wsrep_cluster_size': '1'}:
            raise ValueError('Read-only Galera positive control failed')
        metrics = flow.run(['kubectl', '-n', 'onap', 'exec', name, '-c', pod['spec']['containers'][1]['name'],
                            '--', 'sh', '-c', 'wget -qO- http://127.0.0.1:9104/metrics'], timeout=30).decode()
        if not any(line == 'mysql_up 1' for line in metrics.splitlines()):
            raise ValueError('Live exporter mysql_up is not 1')
        return {'select_1': True, 'galera_status': values, 'mysql_up': 1}
    version = flow.run(['kubectl', '-n', 'onap', 'exec', name, '-c', main, '--',
                        '/opt/bitnami/elasticsearch/bin/elasticsearch', '--version'], timeout=30).decode()
    if 'Version: 7.9.3' not in version:
        raise ValueError('Unexpected Elasticsearch application version')
    return {'version': '7.9.3', 'stock_readiness_passed': True, 'coordinator_not_accepted': True}


def apply(session, approved):
    nodes = flow.get('nodes', namespace=None)['items']
    for name in TARGETS:
        session.check()
        pods, workloads, jobs, states = session.inventory()
        if set(states.values()) != {'held'}:
            raise ValueError('A recovery Job was activated before rollout completed')
        ss, pod = one(workloads, name), one(pods, name + '-0')
        old = approved['targets'][name]
        proof = stalled_guard(ss, pod, session.baseline, nodes)
        if proof != old['proof'] or session.storage(name, pod) != old['storage']:
            raise ValueError('Rollout/storage proof changed since approval')
        pinned_spec = copy.deepcopy(ss['spec'])
        pinned_spec['template']['spec']['nodeSelector'] = {'kubernetes.io/hostname': proof['node']}
        if not proof['placement_already_pinned']:
            flow.run(['kubectl', '-n', 'onap', 'patch', 'statefulset', name, '--type=json', '-p', json.dumps(placement_patch(ss, proof['node']))])
        current = flow.get('statefulset', name)
        if current['metadata']['uid'] != proof['owner_uid'] or current['spec'] != pinned_spec:
            raise ValueError('Placement patch produced an unexpected contract')
        pod = flow.get('pod', name + '-0')
        if pod['metadata']['uid'] != proof['pod_uid']:
            raise ValueError('Controller already replaced the Pod; additional deletion refused')
        stalled_guard(current, pod, session.baseline, nodes)
        if session.storage(name, pod) != old['storage']:
            raise ValueError('Backing directory changed before deletion')
        body = {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                'preconditions': {'uid': pod['metadata']['uid'], 'resourceVersion': pod['metadata']['resourceVersion']}}
        path = session.work / (name + '-delete.json')
        flow.store(path, body)
        flow.run(['kubectl', 'delete', '--raw', '/api/v1/namespaces/onap/pods/' + name + '-0', '-f', str(path)])
        deadline, stable, new_uid = time.monotonic() + 1200, None, None
        while time.monotonic() < deadline:
            session.check()
            ss = flow.get('statefulset', name)
            matches = owned(flow.get('pods')['items'], proof['owner_uid'])
            if len(matches) > 1:
                raise ValueError('Unexpected additional StatefulSet Pod')
            if not matches:
                time.sleep(15)
                continue
            replacement = matches[0]
            if replacement['metadata']['uid'] != proof['pod_uid']:
                if new_uid and new_uid != replacement['metadata']['uid']:
                    raise ValueError('Replacement Pod was recreated unexpectedly')
                new_uid = replacement['metadata']['uid']
            ready = replacement_ready(ss, replacement, old, pinned_spec)
            stable = (stable or time.monotonic()) if ready else None
            if stable and time.monotonic() - stable >= 300:
                control = live_controls(replacement)
                record = {'name': name, 'old_pod_uid': proof['pod_uid'], 'new_pod_uid': new_uid,
                          'node': proof['node'], 'statefulset_uid': proof['owner_uid'], 'spec_sha256': digest(pinned_spec),
                          'ready_stability_seconds': time.monotonic() - stable, 'positive_control': control}
                flow.store(session.work / (name + '-accepted.json'), record)
                session.result['completed'].append(record)
                print('Accepted ' + name + '; retained node/PVC and five-minute readiness', flush=True)
                break
            time.sleep(15)
        else:
            raise ValueError('Replacement readiness timed out; no further Pod replacement')
    session.check()
    session.result['status'] = 'scoped-complete'


if __name__ == '__main__':
    raise SystemExit(execute('rollout', apply, __doc__))
