"""Exact-image VES trust compatibility; public trust only, never a new issuer."""
import base64
import copy
import hashlib
import json
from pathlib import Path

IMAGE_TAG = 'nexus3.onap.org:10001/onap/org.onap.dcaegen2.deployments.tls-init-container:2.1.0'
IMAGE = IMAGE_TAG.rsplit(':', 1)[0] + '@sha256:36934e5002cfa55a9df08e0fd2f621c843e5ef9bea24e9963ce680beccfcc060'
NAME = 'onap-dcae-ves-collector'
ROOT = Path(__file__).resolve().parents[1]


def config(context):
    pki = Path(context['pki_directory'])
    data = {'phase3-ves-bootstrap.sh': (ROOT/'bin/phase3-ves-bootstrap.sh').read_text(),
            'root.cer': (pki/'root.cer').read_text()}
    binary = {'truststoreONAPall.jks': base64.b64encode((pki/'truststoreONAPall.jks').read_bytes()).decode()}
    digest = hashlib.sha256(json.dumps([data, binary], sort_keys=True).encode()).hexdigest()
    return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
        'name': 'phase3-ves-'+digest[:16], 'namespace': 'onap',
        'annotations': {'phase3.onap.org/trust-root-sha256': context['root_sha256']}},
        'immutable': True, 'data': data, 'binaryData': binary}


def patch_deployment(resource, context):
    result = copy.deepcopy(resource)
    if (result.get('kind') != 'Deployment' or result['metadata']['name'] != NAME
            or result['metadata'].get('namespace', 'onap') != 'onap'):
        raise ValueError('VES compatibility is limited to the reviewed Deployment')
    pod = result['spec']['template']['spec']
    matches = [c for c in pod.get('initContainers', []) if c['name'] == 'init-tls']
    if len(matches) != 1:
        raise ValueError('Expected exactly one VES TLS initializer')
    init = matches[0]
    if init['image'] not in (IMAGE_TAG, IMAGE) or init.get('command') or init.get('args'):
        raise ValueError('Unreviewed VES image or entry point')
    if init.get('volumeMounts') != [{'mountPath': '/opt/app/osaaf', 'name': 'tls-info'}]:
        raise ValueError('Unreviewed VES artifact mounts')
    volumes = pod.setdefault('volumes', [])
    if [v for v in volumes if v['name'] == 'tls-info'] != [{'name': 'tls-info', 'emptyDir': {}}]:
        raise ValueError('VES artifacts must be Pod-local emptyDir')
    if any(v['name'] in ('phase3-ves', 'phase3-ves-attempt') for v in volumes):
        raise ValueError('VES compatibility volume collision')
    init['image'] = IMAGE
    init['command'] = ['/bin/bash', '/phase3-ves/phase3-ves-bootstrap.sh']
    init['volumeMounts'] += [
        {'name': 'phase3-ves', 'mountPath': '/phase3-ves', 'readOnly': True},
        {'name': 'phase3-ves', 'mountPath': '/root/.aaf/truststoreONAPall.jks',
         'subPath': 'truststoreONAPall.jks', 'readOnly': True},
        {'name': 'phase3-ves-attempt', 'mountPath': '/phase3-ves-attempt'}]
    volumes += [{'name': 'phase3-ves', 'configMap': {'name': config(context)['metadata']['name'], 'defaultMode': 365}},
                {'name': 'phase3-ves-attempt', 'emptyDir': {'medium': 'Memory'}}]
    return result


def verify(resource, context):
    """Require the exact reviewed mount/wrapper contract after a successful init."""
    expected = config(context)
    pod = resource['spec'] if resource['kind'] == 'Pod' else resource['spec']['template']['spec']
    init = next(c for c in pod.get('initContainers', []) if c['name'] == 'init-tls')
    if init['image'] != IMAGE or init.get('command') != ['/bin/bash', '/phase3-ves/phase3-ves-bootstrap.sh']:
        raise ValueError('VES did not use the reviewed TLS initializer')
    required = [
        {'name': 'phase3-ves', 'mountPath': '/phase3-ves', 'readOnly': True},
        {'name': 'phase3-ves', 'mountPath': '/root/.aaf/truststoreONAPall.jks',
         'subPath': 'truststoreONAPall.jks', 'readOnly': True}]
    if not all(m in init.get('volumeMounts', []) for m in required):
        raise ValueError('VES public trust mount changed')
    if not any(v['name'] == 'phase3-ves' and v.get('configMap', {}).get('name') == expected['metadata']['name']
               for v in pod.get('volumes', [])):
        raise ValueError('VES trust ConfigMap changed')
    return expected
