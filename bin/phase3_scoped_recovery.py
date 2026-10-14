"""Private-receipt, fail-closed recovery for stalled Pods and already-held Jobs."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time

from phase3_images import LOCK_PATH, replacements
from phase3_recovery_guards import JOBS, PRESERVE_JOBS, executed

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ('onap-mariadb-galera', 'onap-policy-mariadb', 'onap-sdnrdb-master')
spec = importlib.util.spec_from_file_location('image_workflow', ROOT / 'bin/phase3-image-recovery.py')
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def complete(job):
    return any(c.get('type') == 'Complete' and c.get('status') == 'True'
               for c in job.get('status', {}).get('conditions', []))


def failed(job):
    return bool(job.get('status', {}).get('failed', 0) or any(
        c.get('type') in ('Failed', 'FailureTarget') and c.get('status') == 'True'
        for c in job.get('status', {}).get('conditions', [])))


def owned(pods, uid):
    return [p for p in pods if any(o.get('uid') == uid and o.get('controller') is True
                                 for o in p['metadata'].get('ownerReferences', []))]


def one(items, name):
    found = [x for x in items if x['metadata']['name'] == name]
    if len(found) != 1:
        raise ValueError('Missing/ambiguous resource: ' + name)
    return found[0]


def normalized_pod_spec(value):
    """Remove only controller/API-generated Pod fields, not application contracts."""
    result = copy.deepcopy(value)
    for key in ('nodeName', 'hostname', 'subdomain', 'priority', 'preemptionPolicy'):
        result.pop(key, None)
    for key, default in (('serviceAccountName', 'default'), ('serviceAccount', 'default'),
                         ('enableServiceLinks', True)):
        if result.get(key) == default:
            result.pop(key, None)
    result['tolerations'] = [t for t in result.get('tolerations', []) if not (
        t.get('key') in ('node.kubernetes.io/not-ready', 'node.kubernetes.io/unreachable')
        and t == {'key': t['key'], 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300})]
    if not result['tolerations']:
        result.pop('tolerations')
    automatic = {v['name'] for v in result.get('volumes', []) if v['name'].startswith('kube-api-access-')
                 and 'projected' in v}
    for container in result.get('containers', []) + result.get('initContainers', []):
        mounts = container.get('volumeMounts', [])
        for mount in mounts:
            if mount['name'] in automatic and (mount.get('mountPath') != '/var/run/secrets/kubernetes.io/serviceaccount'
                                               or mount.get('readOnly') is not True):
                raise ValueError('Unexpected automatic credential mount')
        mounts = [m for m in mounts if m['name'] not in automatic]
        if mounts:
            container['volumeMounts'] = mounts
        else:
            container.pop('volumeMounts', None)
    result['volumes'] = [v for v in result.get('volumes', []) if v['name'] not in automatic]
    return result


def stateful_template_spec(ss, pod_name):
    result = copy.deepcopy(ss['spec']['template']['spec'])
    claims = ss['spec'].get('volumeClaimTemplates', [])
    generated = [{'name': c['metadata']['name'], 'persistentVolumeClaim': {
        'claimName': c['metadata']['name'] + '-' + pod_name}} for c in claims]
    names = {v['name'] for v in generated}
    result['volumes'] = generated + [v for v in result.get('volumes', []) if v['name'] not in names]
    return normalized_pod_spec(result)


def init_contract(pod, name):
    ps = normalized_pod_spec(pod['spec'])
    init = ps.get('initContainers', [])
    if name in TARGETS[:2]:
        command = ('chown -R 10001:10001 /data\nchown -R 10001:10001 /bootstrap/\n'
                   'chown -R 10001:10001 /tmp/\ncp /config/my.cnf /actual/my.cnf\n'
                   'chown -R 10001:10001 /actual\n')
        if len(init) != 1 or init[0]['name'] != 'fix-permission' or init[0].get('command') != ['/bin/sh'] or init[0].get('args') != ['-c', command]:
            raise ValueError('Unreviewed Galera initializer')
        expected = {'/data': name, '/bootstrap': 'previous-boot', '/tmp': 'mariadb-tmp-folder',
                    '/config/my.cnf': 'mariadb-galera-starting-config', '/actual': 'mariadb-galera-actual-config'}
        if {m['mountPath']: m['name'] for m in init[0].get('volumeMounts', [])} != expected:
            raise ValueError('Unreviewed Galera initializer mounts')
        volumes = {v['name']: v for v in ps['volumes']}
        if any('emptyDir' not in volumes[n] for n in ('previous-boot', 'mariadb-tmp-folder', 'mariadb-galera-actual-config')) or 'configMap' not in volumes['mariadb-galera-starting-config']:
            raise ValueError('Permission initializer writes outside reviewed volumes')
        if init[0].get('securityContext', {}).get('runAsUser') != 0:
            raise ValueError('Unexpected stock permission initializer identity')
    else:
        expected = [('sysctl', ['/bin/sh', '-c', 'set -o errexit\nset -o pipefail\nset -o nounset\nsysctl -w vm.max_map_count=262144 && sysctl -w fs.file-max=65536\n']),
                    ('volume-permissions', ['/bin/sh', '-c', 'chown -R 1001:1001 //bitnami/elasticsearch/data\n'])]
        if [(i['name'], i.get('command')) for i in init] != expected or any(i.get('args') for i in init):
            raise ValueError('Unreviewed Elasticsearch initializer')
        if init[0].get('volumeMounts') or init[0].get('securityContext', {}).get('privileged') is not True:
            raise ValueError('Unexpected stock sysctl contract')
        if init[1].get('securityContext', {}).get('runAsUser') != 0 or init[1].get('volumeMounts') != [{'name': 'data', 'mountPath': '/bitnami/elasticsearch/data'}]:
            raise ValueError('Unreviewed Elasticsearch permission mounts')
    if any(i['image'] != 'docker.io/busybox:1.34.1' for i in init):
        raise ValueError('Initializer image changed')
    statuses = pod.get('status', {}).get('initContainerStatuses', [])
    if {s['name'] for s in statuses} != {i['name'] for i in init} or any(
            s.get('restartCount', 0) or s.get('lastState') or
            s.get('state', {}).get('terminated', {}).get('exitCode') != 0 for s in statuses):
        raise ValueError('Incomplete or failed stock initializer history')


def stalled_guard(ss, pod, baseline, nodes):
    name = ss['metadata']['name']
    old = baseline['targets'][name]['pod']
    if name not in TARGETS or ss['metadata']['uid'] != baseline['targets'][name]['owner_uid']:
        raise ValueError('StatefulSet identity changed')
    if (pod['metadata']['uid'] != old['metadata']['uid'] or pod['metadata'].get('deletionTimestamp')
            or pod['metadata']['name'] != name + '-0' or pod['spec'] != old['spec']):
        raise ValueError('Original stalled Pod changed')
    owner = pod['metadata'].get('ownerReferences', [])
    if len(owner) != 1 or owner[0].get('uid') != ss['metadata']['uid'] or owner[0].get('kind') != 'StatefulSet' or owner[0].get('controller') is not True:
        raise ValueError('Unexpected Pod ownership')
    if (ss['spec'].get('replicas') != 1 or ss['spec'].get('podManagementPolicy') != 'OrderedReady'
            or ss['spec'].get('updateStrategy') != {'type': 'RollingUpdate'}
            or ss['spec'].get('persistentVolumeClaimRetentionPolicy') != {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}):
        raise ValueError('Unexpected rollout or storage retention contract')
    statuses = pod.get('status', {}).get('containerStatuses', [])
    if {s['name'] for s in statuses} != {c['name'] for c in pod['spec']['containers']} or any(executed(s) for s in statuses):
        raise ValueError('Main execution exists or history is incomplete')
    if any(s.get('state', {}).get('waiting', {}).get('reason') not in ('ImagePullBackOff', 'ErrImagePull') for s in statuses):
        raise ValueError('Pod is not stalled solely on missing images')
    init_contract(pod, name)
    node = one(nodes, pod['spec']['nodeName'])
    if node['metadata']['uid'] != baseline['targets'][name]['node_uid'] or node['metadata']['labels'].get('kubernetes.io/hostname') != node['metadata']['name']:
        raise ValueError('Backing storage node identity changed')
    wanted = normalized_pod_spec(pod['spec'])
    for c in wanted['containers']:
        if c['image'] not in replacements():
            raise ValueError('Unreviewed stalled image')
        c['image'] = replacements()[c['image']]
    claims = ss['spec'].get('volumeClaimTemplates', [])
    pvc_names = [v['persistentVolumeClaim']['claimName'] for v in pod['spec']['volumes'] if 'persistentVolumeClaim' in v]
    if len(claims) != 1 or pvc_names != [claims[0]['metadata']['name'] + '-' + pod['metadata']['name']]:
        raise ValueError('Controller-generated PVC binding differs')
    actual_claim = copy.deepcopy(baseline['protections']['storage']['PersistentVolumeClaim/' + pvc_names[0]]['spec'])
    actual_claim.pop('volumeName', None)
    if actual_claim != claims[0]['spec']:
        raise ValueError('Claim template differs from retained PVC specification')
    live = stateful_template_spec(ss, pod['metadata']['name'])
    placement = live.pop('nodeSelector', None)
    if placement not in (None, {'kubernetes.io/hostname': node['metadata']['name']}):
        raise ValueError('Unreviewed placement override')
    if live != wanted:
        raise ValueError('Desired template differs beyond reviewed images/placement')
    return {'name': name, 'owner_uid': ss['metadata']['uid'], 'pod_uid': pod['metadata']['uid'],
            'node': node['metadata']['name'], 'node_uid': node['metadata']['uid'], 'pod_spec_sha256': digest(pod['spec']),
            'statefulset_spec_sha256': digest(ss['spec']), 'placement_already_pinned': placement is not None}


def held_guard(job, pods, expected):
    name = job['metadata']['name']
    if name not in JOBS or job['metadata'].get('namespace') != 'onap' or job['metadata']['uid'] != expected['uid']:
        raise ValueError('Unapproved held Job identity')
    if (job['metadata'].get('annotations', {}).get('meta.helm.sh/release-name') != JOBS[name]
            or 'helm.sh/hook' in job['metadata'].get('annotations', {})):
        raise ValueError('Unexpected Job ownership')
    expected_spec = copy.deepcopy(expected['spec'])
    expected_spec['suspend'] = job['spec'].get('suspend', False)
    if job['spec'] != expected_spec or job['spec'].get('backoffLimit') != 0 or job['spec']['template']['spec'].get('restartPolicy') != 'Never' or job['spec'].get('parallelism', 1) != 1 or job['spec'].get('completions', 1) != 1:
        raise ValueError('Held Job specification or retry controls changed')
    history = owned(pods, job['metadata']['uid'])
    if failed(job) or len(history) > 1:
        raise ValueError('Job failure or unexpected additional Pod execution')
    if complete(job):
        if len(history) != 1 or history[0].get('status', {}).get('phase') != 'Succeeded':
            raise ValueError('Incomplete completed Job execution evidence')
        return 'complete'
    if not job['spec'].get('suspend'):
        return 'active'
    if history or any(job.get('status', {}).get(k, 0) for k in ('active', 'failed', 'succeeded', 'terminating')) or job.get('status', {}).get('startTime'):
        raise ValueError('Held Job already has an execution history')
    return 'held'


def dependency_bindings(job, workloads, jobs):
    result = []
    for init in job['spec']['template']['spec'].get('initContainers', []):
        cmd = (init.get('command') or []) + (init.get('args') or [])
        if not cmd or cmd[0] != '/app/ready.py':
            continue
        if (len(cmd) - 1) % 2 or any(cmd[i] not in ('--container-name', '--job-name') for i in range(1, len(cmd), 2)):
            raise ValueError('Unreviewed readiness arguments')
        for i in range(1, len(cmd), 2):
            option, name = cmd[i:i+2]
            if option == '--job-name':
                resource = one(jobs, name)
                if name not in JOBS:
                    raise ValueError('Dependency is not a reviewed Job')
            else:
                matches = [w for w in workloads if any(c['name'] == name for c in w['spec']['template']['spec']['containers'])]
                if len(matches) != 1:
                    raise ValueError('Missing/ambiguous readiness controller')
                resource = matches[0]
            expected_spec = copy.deepcopy(resource['spec'])
            if resource['kind'] == 'Job':
                expected_spec['suspend'] = True
            result.append({'kind': resource['kind'], 'name': resource['metadata']['name'], 'uid': resource['metadata']['uid'],
                           'spec_sha256': digest(expected_spec), 'container': name if option == '--container-name' else None})
    if not result:
        raise ValueError('Missing reviewed readiness dependencies')
    return result


def dependencies_ready(bindings, workloads, jobs, pods):
    for binding in bindings:
        resource = one(jobs if binding['kind'] == 'Job' else workloads, binding['name'])
        spec_value = copy.deepcopy(resource['spec'])
        # The sole approved dependency Job change is unsuspension.
        if binding['kind'] == 'Job':
            spec_value['suspend'] = True
        if resource['metadata']['uid'] != binding['uid'] or digest(spec_value) != binding['spec_sha256']:
            raise ValueError('Dependency identity/specification changed')
        if binding['kind'] == 'Job':
            if not complete(resource):
                return False
            continue
        status = resource.get('status', {})
        replicas = resource['spec'].get('replicas', 1)
        if replicas < 1 or status.get('observedGeneration', 0) < resource['metadata']['generation'] or any(
                status.get(k, 0) != replicas for k in ('readyReplicas', 'updatedReplicas')):
            return False
        if resource['kind'] == 'StatefulSet':
            current = owned(pods, resource['metadata']['uid'])
            if status.get('currentRevision') != status.get('updateRevision'):
                return False
        else:
            selector = resource['spec']['selector'].get('matchLabels', {})
            if resource['spec']['selector'].get('matchExpressions'):
                raise ValueError('Unreviewed dependency selector')
            current = [p for p in pods if all(p['metadata'].get('labels', {}).get(k) == v for k, v in selector.items())]
        if len(current) != replicas or any(p['metadata'].get('deletionTimestamp') or not any(
                s['name'] == binding['container'] and s.get('ready') for s in p.get('status', {}).get('containerStatuses', [])) for p in current):
            return False
    return True


def placement_patch(ss, node):
    return [{'op': 'test', 'path': '/metadata/uid', 'value': ss['metadata']['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': ss['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/spec', 'value': ss['spec']},
            {'op': 'add', 'path': '/spec/template/spec/nodeSelector', 'value': {'kubernetes.io/hostname': node}}]


STORAGE_SCRIPT = '''import json,os,stat,subprocess,sys
from pathlib import Path
path=sys.argv[1];uid=int(sys.argv[2]);gid=int(sys.argv[3])
p=Path(path);s=p.lstat()
if str(p.resolve())!=path or not stat.S_ISDIR(s.st_mode) or list(p.iterdir()):raise ValueError('Backing directory is nonempty, linked or not a directory')
if (s.st_uid,s.st_gid)!=(uid,gid):raise ValueError('Backing directory ownership changed')
mount=json.loads(subprocess.check_output(['findmnt','-T',path,'-J','-o','TARGET,SOURCE,FSTYPE']))
if mount['filesystems']!=[{'target':'/storage','source':'/dev/mapper/emulab-k8s','fstype':'ext4'}]:raise ValueError('Backing filesystem changed')
print(json.dumps({'path':path,'realpath':str(p.resolve()),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'device':s.st_dev,'empty':True,'mount':mount,
 'sysctl':{k:Path('/proc/sys/'+k.replace('.','/')).read_text().strip() for k in ('vm.max_map_count','fs.file-max')}}))
'''


class Session:
    def __init__(self, args, mode):
        os.umask(0o077)
        self.args, self.mode = args, mode
        self.work = Path(args.work_dir)
        self.work.mkdir(mode=0o700, parents=False, exist_ok=False)
        flow.TRACE = self.work / 'trace'
        flow.TRACE.mkdir(mode=0o700)
        self.baseline_bytes = Path(args.baseline_state).read_bytes()
        self.baseline = json.loads(self.baseline_bytes)
        self.result = {'recorded_utc': datetime.now(timezone.utc).isoformat(), 'mode': mode, 'apply': args.apply,
                       'status': 'running', 'completed': [], 'blocked': [], 'full_smo_baseline_ready': False,
                       'certificate_cases_started': False, 'completion_markers_written': False}
        signal.signal(signal.SIGTERM, self.interrupted)
        signal.signal(signal.SIGINT, self.interrupted)

    def interrupted(self, number, frame):
        raise InterruptedError('Monitoring interrupted; workloads were not signaled')

    def check(self):
        flow.identity(self.args.expected_slice_urn, self.args.expected_commit)
        if self.baseline.get('schema') != 'phase3-scoped-v1' or self.baseline['slice_urn'] != self.args.expected_slice_urn or self.baseline['image_lock_sha256'] != hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest():
            raise ValueError('Baseline identity/image lock differs')
        if set(self.baseline['targets']) != set(TARGETS) or set(self.baseline['jobs']) != set(JOBS):
            raise ValueError('Incomplete scoped baseline')
        protected = flow.protections()
        if protected != self.baseline['protections']:
            raise ValueError('Storage, application Secret data or excluded Jobs changed')
        operator = flow.operator_gate()
        flow.store(self.work / ('health-%s.json' % time.time_ns()), operator)
        return operator

    def inventory(self):
        pods = flow.get('pods')['items']
        workloads = flow.get('deployments,statefulsets')['items']
        jobs = flow.get('jobs')['items']
        states = {n: held_guard(one(jobs, n), pods, self.baseline['jobs'][n]) for n in JOBS}
        return pods, workloads, jobs, states

    def storage(self, name, pod):
        values = self.baseline['targets'][name]
        claims = [v['persistentVolumeClaim']['claimName'] for v in pod['spec'].get('volumes', []) if 'persistentVolumeClaim' in v]
        if claims != [values['pvc']]:
            raise ValueError('Unexpected Pod PVC bindings')
        pvc = flow.get('pvc', values['pvc'])
        pv = flow.get('pv', pvc['spec']['volumeName'], namespace=None)
        if pvc['status'].get('phase') != 'Bound' or pv['status'].get('phase') != 'Bound' or pv['spec'].get('claimRef', {}).get('uid') != pvc['metadata']['uid'] or pv['spec'].get('hostPath', {}).get('path') != values['path'] or pv['spec'].get('persistentVolumeReclaimPolicy') != 'Retain':
            raise ValueError('Backing volume identity or binding changed')
        all_pods = flow.get('pods', namespace=None)['items']
        for p in all_pods:
            if p['metadata']['uid'] == pod['metadata']['uid']:
                continue
            for v in p['spec'].get('volumes', []):
                if p['metadata']['namespace'] == 'onap' and v.get('persistentVolumeClaim', {}).get('claimName') == values['pvc']:
                    raise ValueError('Another Pod uses the backing PVC')
                direct = v.get('hostPath', {}).get('path')
                if direct and (direct == values['path'] or values['path'].startswith(direct.rstrip('/') + '/') or direct.startswith(values['path'] + '/')):
                    raise ValueError('Another Pod has an overlapping application hostPath')
        uid = 1001 if name == TARGETS[2] else 10001
        command = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
                   pod['spec']['nodeName'], 'sudo -n python3 -c ' + shlex.quote(STORAGE_SCRIPT) + ' ' + shlex.quote(values['path']) + ' ' + str(uid) + ' ' + str(uid)]
        record = json.loads(flow.run(command, timeout=45))
        if name == TARGETS[2] and record['sysctl'] != {'vm.max_map_count': '262144', 'fs.file-max': '65536'}:
            raise ValueError('Stock sysctl replay would change the original node settings')
        return record

    def audit(self):
        self.check()
        pods, workloads, jobs, states = self.inventory()
        if any(s == 'active' for s in states.values()):
            raise ValueError('Unreviewed active recovery Job')
        if self.mode == 'rollout' and set(states.values()) != {'held'}:
            raise ValueError('Rollout requires all six Jobs still held')
        record = {'schema': 'phase3-scoped-audit-v1', 'recorded_utc': datetime.now(timezone.utc).isoformat(),
                  'mode': self.mode, 'slice_urn': self.args.expected_slice_urn, 'commit': self.args.expected_commit,
                  'baseline_sha256': hashlib.sha256(self.baseline_bytes).hexdigest(),
                  'image_lock_sha256': hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest(), 'job_states': states}
        if self.mode == 'rollout':
            nodes = flow.get('nodes', namespace=None)['items']
            record['targets'] = {}
            for name in TARGETS:
                ss, pod = one(workloads, name), one(pods, name + '-0')
                record['targets'][name] = {'proof': stalled_guard(ss, pod, self.baseline, nodes),
                                          'statefulset': ss, 'pod': pod, 'storage': self.storage(name, pod)}
        else:
            record['bindings'] = {n: dependency_bindings(one(jobs, n), workloads, jobs) for n in JOBS}
        flow.store(self.work / 'audit.json', record)
        return record

    def approved(self):
        blob = Path(self.args.approved_audit).read_bytes()
        if hashlib.sha256(blob).hexdigest() != self.args.approved_audit_sha256:
            raise ValueError('Approved audit hash differs')
        record = json.loads(blob)
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(record['recorded_utc'])).total_seconds()
        expected = {'schema': 'phase3-scoped-audit-v1', 'mode': self.mode, 'slice_urn': self.args.expected_slice_urn,
                    'commit': self.args.expected_commit, 'baseline_sha256': hashlib.sha256(self.baseline_bytes).hexdigest(),
                    'image_lock_sha256': hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()}
        if not 0 <= age <= 1800 or any(record.get(k) != v for k, v in expected.items()):
            raise ValueError('Stale/mismatched approved audit')
        flow.store(self.work / 'approved-audit.json', record)
        return record

    def save_result(self):
        self.result['finished_utc'] = datetime.now(timezone.utc).isoformat()
        flow.store(self.work / 'result.json', self.result)


def arguments(description):
    parser = argparse.ArgumentParser(description=description)
    for name in ('baseline-state', 'expected-slice-urn', 'expected-commit', 'work-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--approved-audit')
    parser.add_argument('--approved-audit-sha256')
    args = parser.parse_args()
    if args.apply and (not args.approved_audit or not args.approved_audit_sha256):
        parser.error('Apply requires the exact approved audit and SHA-256')
    return args


def execute(mode, action, description):
    session = None
    try:
        session = Session(arguments(description), mode)
        if session.args.apply:
            approved = session.approved()
            session.check()
            action(session, approved)
        else:
            session.audit()
            session.result['status'] = 'audit-passed'
        code = 2 if session.result['status'] == 'blocked' else 0
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        code = 1
        if session:
            session.result.update(status='failed', failure=str(error))
        else:
            print('Recovery refused before an attempt was opened')
    finally:
        if session:
            session.save_result()
            print(json.dumps(session.result, sort_keys=True), flush=True)
    return code
