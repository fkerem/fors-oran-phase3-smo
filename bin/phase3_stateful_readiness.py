"""Read-only, strategy-aware StatefulSet readiness; never trigger a rollout."""
import argparse
import json
import subprocess
import time

NAMESPACES = ('onap', 'nonrtric', 'network')


def command(args, timeout=90):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError('StatefulSet readiness query or rollout-status check failed')
    return result.stdout


def get(kind):
    return json.loads(command(['kubectl', 'get', kind, '-A', '-o', 'json',
                               '--request-timeout=30s']))['items']


def ready(item):
    return any(c.get('type') == 'Ready' and c.get('status') == 'True'
               for c in item.get('status', {}).get('conditions', []))


def strategy(item):
    value = item.get('spec', {}).get('updateStrategy', {}).get('type', 'RollingUpdate')
    if value not in ('RollingUpdate', 'OnDelete'):
        raise ValueError('Unsupported StatefulSet update strategy')
    return value


def errors(sets, pods, kafkas, namespaces=NAMESPACES):
    problems = []
    for item in sets:
        if item.get('kind') != 'StatefulSet' or item['metadata'].get('namespace') not in namespaces:
            continue
        m, spec, status = item['metadata'], item.get('spec', {}), item.get('status', {})
        label = m['namespace']+'/'+m['name']
        try:
            kind = strategy(item)
            desired = spec.get('replicas', 1)
            if (status.get('readyReplicas', 0) != desired
                    or status.get('observedGeneration', 0) < m.get('generation', 1)):
                raise ValueError('replicas or observed generation not ready')
            if kind == 'RollingUpdate':
                partition = spec.get('updateStrategy', {}).get('rollingUpdate', {}).get('partition', 0)
                if status.get('updatedReplicas', 0) < max(0, desired-partition):
                    raise ValueError('rolling update incomplete')
                if not partition and desired and status.get('currentRevision') != status.get('updateRevision'):
                    raise ValueError('rolling revisions differ')
                continue
            # Strimzi Kafka references are deliberately controller:false in this pin.
            owners = [k for k in kafkas if k['metadata'].get('namespace') == m['namespace']
                      and any(o.get('apiVersion', '').startswith('kafka.strimzi.io/')
                              and o.get('kind') == 'Kafka' and o.get('name') == k['metadata']['name']
                              and o.get('uid') == k['metadata']['uid'] for o in m.get('ownerReferences', []))]
            if len(owners) != 1:
                raise ValueError('OnDelete ownership is not the one current Strimzi Kafka')
            kafka = owners[0]
            labels = m.get('labels', {})
            if (labels.get('strimzi.io/cluster') != kafka['metadata']['name']
                    or labels.get('strimzi.io/kind') != 'Kafka'
                    or m['name'] not in (kafka['metadata']['name']+'-kafka', kafka['metadata']['name']+'-zookeeper')
                    or not ready(kafka)
                    or kafka.get('status', {}).get('observedGeneration', 0) < kafka['metadata'].get('generation', 1)):
                raise ValueError('OnDelete Kafka binding is not reconciled and Ready')
            revision = status.get('updateRevision')
            if (desired < 1 or not revision or status.get('currentRevision') != revision
                    or any(status.get(key, 0) != desired for key in
                           ('replicas', 'readyReplicas', 'updatedReplicas', 'currentReplicas'))):
                raise ValueError('OnDelete replica/revision convergence is not established')
            selector = spec.get('selector', {})
            match = selector.get('matchLabels', {})
            if not match or selector.get('matchExpressions'):
                raise ValueError('Unreviewed OnDelete Pod selector')
            selected = [p for p in pods if p['metadata'].get('namespace') == m['namespace']
                        and all(p['metadata'].get('labels', {}).get(k) == v for k, v in match.items())]
            start = spec.get('ordinals', {}).get('start', 0)
            if (len(selected) != desired or {p['metadata']['name'] for p in selected}
                    != {m['name']+'-'+str(n) for n in range(start, start+desired)}):
                raise ValueError('OnDelete expected Pod membership differs')
            for pod in selected:
                pm = pod['metadata']
                if (not any(o.get('controller') is True and o.get('kind') == 'StatefulSet'
                            and o.get('uid') == m['uid'] for o in pm.get('ownerReferences', []))
                        or pm.get('deletionTimestamp') or pod.get('status', {}).get('phase') != 'Running'
                        or not ready(pod) or pm.get('labels', {}).get('controller-revision-hash') != revision):
                    raise ValueError('OnDelete Pod ownership/readiness/revision differs')
        except (ValueError, KeyError, TypeError) as error:
            problems.append('StatefulSet is not accepted: '+label+' ('+str(error)+')')
    return problems


def wait(namespaces=NAMESPACES, timeout=3600):
    if timeout <= 0 or timeout > 3600:
        raise ValueError('Readiness timeout must be within 1..3600 seconds')
    deadline = time.monotonic()+timeout
    sets = [x for x in get('statefulsets') if x['metadata'].get('namespace') in namespaces]
    bindings = {(x['metadata']['namespace'], x['metadata']['name']):
                (x['metadata']['uid'], x['metadata'].get('generation', 1), x['spec']) for x in sets}
    for item in sets:
        if strategy(item) == 'RollingUpdate':
            remaining = int(deadline-time.monotonic())
            if remaining < 1:
                raise ValueError('StatefulSet readiness deadline elapsed')
            command(['kubectl', '-n', item['metadata']['namespace'], 'rollout', 'status',
                     'statefulset/'+item['metadata']['name'], '--timeout='+str(remaining)+'s'], timeout=remaining+5)
    while True:
        current = [x for x in get('statefulsets') if x['metadata'].get('namespace') in namespaces]
        now_bindings = {(x['metadata']['namespace'], x['metadata']['name']):
                        (x['metadata']['uid'], x['metadata'].get('generation', 1), x['spec']) for x in current}
        if now_bindings != bindings:
            raise ValueError('StatefulSet inventory or desired identity changed during readiness')
        problems = errors(current, get('pods'), get('kafkas.kafka.strimzi.io'), namespaces)
        if not problems:
            return
        if time.monotonic() >= deadline:
            raise ValueError('StatefulSet readiness deadline elapsed; '+problems[0])
        time.sleep(min(5, max(0, deadline-time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace', action='append', choices=NAMESPACES)
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    try:
        wait(tuple(args.namespace or NAMESPACES), args.timeout)
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired):
        parser.exit(1, 'Strategy-aware StatefulSet readiness failed; no rollout was triggered\n')
    print('Strategy-aware StatefulSet readiness passed')


if __name__ == '__main__':
    main()
