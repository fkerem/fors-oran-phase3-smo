"""SMS public-chain/endpoint repair. Preload remains an explicit review gate."""
import copy
import hashlib
import json
from pathlib import Path
from phase3_lab_pki import CONFIG_IMAGE

ROOT = Path(__file__).resolve().parents[1]
NAME = 'onap-aaf-sms'
JOB = NAME+'-preload'
SERVICE = 'aaf-sms'
ROLE = 'phase3.onap.org/sms-role'
IMAGE_TAG = 'nexus3.onap.org:10001/onap/aaf/sms:4.0.2'
IMAGE = IMAGE_TAG.rsplit(':', 1)[0]+'@sha256:8bbed20427d11342eb96ebcf6c592f54cf9ee647aa8d3989e317f634f222e293'
PRELOAD_SHA256 = '5186a426361739479a0ce03e6d39997ea65721d5282dfa4fb7d3f236f5cf84ec'
INIT = NAME+'-add-intermediate-cert'
COMMAND = ['/bin/bash', '/phase3-sms/phase3-sms-chain.sh']
STOCK_ARGS = ['-c', 'cat /int-certs/intermediate_root_ca.pem >> /opt/app/osaaf/local/org.onap.aaf-sms.crt\n']
LABELS = {'app': 'aaf-sms', 'release': 'onap'}


def config(context):
    pki = Path(context['pki_directory'])
    data = {n: (pki/n).read_text() for n in ('root.cer', 'intermediate.cer')}
    data['phase3-sms-chain.sh'] = (ROOT/'bin/phase3-sms-chain.sh').read_text()
    digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
        'name': 'phase3-sms-'+digest[:16], 'namespace': 'onap',
        'annotations': {'phase3.onap.org/trust-root-sha256': context['root_sha256']}},
        'immutable': True, 'data': data}


def namespace_guard(r, kind, name):
    if r.get('kind') != kind or r['metadata']['name'] != name or r['metadata'].get('namespace', 'onap') != 'onap':
        raise ValueError('SMS patch target is outside the reviewed contract')


def patch_deployment(resource, context):
    namespace_guard(resource, 'Deployment', NAME)
    r = copy.deepcopy(resource)
    template = r['spec']['template']
    if template['metadata']['labels'] != LABELS or r['spec']['selector'] != {'matchLabels': {'app': 'aaf-sms'}}:
        raise ValueError('Unreviewed SMS labels or immutable Deployment selector')
    pod = template['spec']
    main = pod['containers']
    if (len(main) != 1 or main[0]['name'] != 'aaf-sms' or main[0]['image'] not in (IMAGE_TAG, IMAGE)
            or main[0].get('command') != ['/sms/bin/sms'] or main[0].get('args')):
        raise ValueError('Unreviewed SMS server image/entry point')
    matches = [c for c in pod.get('initContainers', []) if c['name'] == INIT]
    expected_mounts = [{'mountPath': '/opt/app/osaaf', 'name': NAME+'-aaf-config'},
                       {'mountPath': '/int-certs', 'name': NAME+'-int-certs', 'readOnly': True}]
    if (len(matches) != 1 or matches[0]['image'] != 'docker.io/busybox:1.34.1'
            or matches[0].get('command') != ['/bin/sh'] or matches[0].get('args') != STOCK_ARGS
            or matches[0].get('volumeMounts') != expected_mounts or matches[0].get('env')):
        raise ValueError('Unreviewed SMS intermediate appender')
    volumes = pod.setdefault('volumes', [])
    if [v for v in volumes if v['name'] == NAME+'-aaf-config'] != [
            {'name': NAME+'-aaf-config', 'emptyDir': {'medium': 'Memory'}}]:
        raise ValueError('SMS certificate output must remain Pod-local')
    if any(v['name'].startswith('phase3-sms') for v in volumes):
        raise ValueError('SMS public-trust volume collision')
    init = matches[0]
    init['image'] = CONFIG_IMAGE
    init['command'] = COMMAND.copy()
    init.pop('args')
    init['volumeMounts'] = [expected_mounts[0],
        {'name': 'phase3-sms', 'mountPath': '/phase3-sms', 'readOnly': True},
        {'name': 'phase3-sms-attempt', 'mountPath': '/phase3-sms-attempt'}]
    # No Secret or signing key is mounted into this crypto-only initializer.
    volumes.extend([
        {'name': 'phase3-sms', 'configMap': {'name': config(context)['metadata']['name'], 'defaultMode': 365}},
        {'name': 'phase3-sms-attempt', 'emptyDir': {'medium': 'Memory'}}])
    template['metadata']['labels'][ROLE] = 'server'
    main[0]['image'] = IMAGE
    return r


def crypto_initializer(container):
    # Admission adds this projected token mount to Pods, not controller
    # templates. Ignore only that exact standard read-only mount shape.
    mounts = []
    injected = 0
    for mount in container.get('volumeMounts', []):
        if (mount.get('mountPath') == '/var/run/secrets/kubernetes.io/serviceaccount'
                and mount.get('name', '').startswith('kube-api-access-')
                and mount.get('readOnly') is True and set(mount) == {'name', 'mountPath', 'readOnly'}):
            injected += 1
        else:
            mounts.append(mount)
    return (container.get('name') == INIT and container.get('image') == CONFIG_IMAGE
            and container.get('command') == COMMAND and not container.get('args')
            and injected <= 1 and mounts == [
                {'mountPath': '/opt/app/osaaf', 'name': NAME+'-aaf-config'},
                {'name': 'phase3-sms', 'mountPath': '/phase3-sms', 'readOnly': True},
                {'name': 'phase3-sms-attempt', 'mountPath': '/phase3-sms-attempt'}])


def patch_service(resource):
    namespace_guard(resource, 'Service', SERVICE)
    r = copy.deepcopy(resource)
    if r['spec'].get('selector') != LABELS or len(r['spec'].get('ports', [])) != 1:
        raise ValueError('Unreviewed SMS Service selector/ports')
    port = r['spec']['ports'][0]
    if port.get('port') != 10443 or port.get('targetPort') != 10443 or port.get('protocol', 'TCP') != 'TCP':
        raise ValueError('Unreviewed SMS Service listener')
    r['spec']['selector'][ROLE] = 'server'
    return r


def hold_preload(resource):
    """Do not silently deploy a log-based guard over a retrying writer."""
    namespace_guard(resource, 'Job', JOB)
    r = copy.deepcopy(resource)
    labels = r['spec']['template']['metadata']['labels']
    if any(labels.get(k) != v for k, v in LABELS.items()) or ROLE in labels:
        raise ValueError('Unreviewed preload labels')
    labels[ROLE] = 'preload'
    r['spec'].update({'suspend': True, 'backoffLimit': 0})
    r['spec']['template']['spec']['restartPolicy'] = 'Never'
    r['metadata'].setdefault('annotations', {})['phase3.onap.org/preload-gate'] = 'explicit-write-safety-review-required'
    return r


def verify(resource, context):
    pod = resource['spec'] if resource['kind'] == 'Pod' else resource['spec']['template']['spec']
    labels = resource['metadata']['labels'] if resource['kind'] == 'Pod' else resource['spec']['template']['metadata']['labels']
    init = [c for c in pod.get('initContainers', []) if c['name'] == INIT]
    if len(init) != 1 or not crypto_initializer(init[0]) or labels.get(ROLE) != 'server':
        raise ValueError('SMS did not use the reviewed chain/role contract')
    expected = config(context)
    if not any(v['name'] == 'phase3-sms' and v.get('configMap', {}).get('name') == expected['metadata']['name'] for v in pod['volumes']):
        raise ValueError('SMS public trust ConfigMap differs')
    main = next(c for c in pod['containers'] if c['name'] == 'aaf-sms')
    if main['image'] != IMAGE:
        raise ValueError('SMS runtime image differs')
    return expected
