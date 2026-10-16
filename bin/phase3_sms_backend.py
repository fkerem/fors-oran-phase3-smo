"""Fresh-only SMS backend contract; no recovery, reset, or preload operations."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

import phase3_sms as sms

QUORUM = 'onap-aaf-sms-quorumclient'
VAULT = 'onap-aaf-sms-vault'
QUORUM_TAG = 'nexus3.onap.org:10001/onap/aaf/smsquorumclient:4.0.2'
QUORUM_IMAGE = QUORUM_TAG.rsplit(':', 1)[0]+'@sha256:d016b90190c49cce566e56612d92ce8d6906480655a1e52056afa8006f8839a2'
VAULT_IMAGE = 'docker.io/library/vault@sha256:5b753351ad1d9fd67505590b6b09496b295e0ae2e2ef4362d9b4beeaff574018'
CONSUL_IMAGE = 'docker.io/library/consul@sha256:3e064c7f96231a95677a7d7af603ef99a8ca4d63d46a70e25de794c9fc392ea2'
IMAGES = {'sms': sms.IMAGE, 'quorum': QUORUM_IMAGE, 'vault': VAULT_IMAGE, 'consul': CONSUL_IMAGE}
STORAGE_PATHS = ['/storage/nfs/deployment-1/onap/sms/'+p for p in
                 ('auth', 'consul/data-0', 'quorum/data-0', 'quorum/data-1', 'quorum/data-2')]
CA_PATH = '/phase3-sms-backend/root.cer'
STOCK_CONFIG = {'url': 'https://aaf-sms.onap:10443', 'cafile': '/quorumclient/certs/aaf_root_ca.cer',
                'clientcert': 'client.cert', 'clientkey': 'client.key', 'timeout': '10s'}


def config(context):
    """Separate public CM: never change a retained PKI/helper identity."""
    settings = dict(STOCK_CONFIG, cafile=CA_PATH)
    data = {'root.cer': (Path(context['pki_directory'])/'root.cer').read_text(),
            'config.json': json.dumps(settings, sort_keys=True)}
    digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
        'name': 'phase3-sms-backend-'+digest[:16], 'namespace': 'onap',
        'annotations': {'phase3.onap.org/trust-root-sha256': context['root_sha256']}},
        'immutable': True, 'data': data}


def require_qualification(record):
    cases=record.get('cases',{})
    tls_cases=('wrong-ca','missing-ca','wrong-hostname','expired-server')
    expected={'fresh-and-restart','interrupted-before-custody','interrupted-before-auth',*tls_cases}
    positive=cases.get('fresh-and-restart',{})
    custody=positive.get('custody',{})
    if (record.get('schema')!=1 or record.get('passed') is not True or record.get('images')!=IMAGES
            or record.get('synthetic_material_only') is not True or record.get('live_api_contacted') is not False
            or record.get('application_domain_or_secret_posts')!=0 or set(cases)!=expected
            or any(positive.get(k) is not True for k in ('passed','normal_approle_bootstrap','scoped_role',
                'sms_and_quorum_restart','vault_restart_unsealed','two_shares_not_accepted','version_qualified_mount_catalog'))
            or positive.get('invalid_recovery_controls')!=5 or custody.get('sets')!=3
            or any(custody.get(k) is not True for k in ('nonempty','matching_key_pairs','distinct_valid_shares'))
            or any(cases.get(k,{}).get('blocked') is not True for k in ('interrupted-before-custody','interrupted-before-auth'))
            or any(cases[k].get('passed') is not True or cases[k].get('application_requests')!=0
                   or cases[k].get('exact_quorum_tls_refusal') is not True for k in tls_cases)):
        raise ValueError('Complete exact-image backend qualification is missing')
    return True


def patch(resource, context):
    r = copy.deepcopy(resource)
    if context.get('sms_backend_contract') != 1:
        return r
    kind, name = r.get('kind'), r.get('metadata', {}).get('name')
    if kind != 'StatefulSet' or name not in (QUORUM, VAULT):
        return r
    sms.namespace_guard(r, 'StatefulSet', name)
    pod = r['spec']['template']['spec']
    if name == QUORUM:
        if r['spec'].get('replicas') != 3 or len(pod['containers']) != 1:
            raise ValueError('Unreviewed SMS quorum inventory')
        c = pod['containers'][0]
        if (c['name'] != 'aaf-sms-quorumclient' or c['image'] != QUORUM_TAG
                or c.get('command') != ['/quorumclient/bin/quorumclient'] or c.get('args')
                or c.get('workingDir') != '/quorumclient/'):
            raise ValueError('Unreviewed SMS quorum runtime')
        volumes = pod['volumes']
        matches = [v for v in volumes if v['name'] == 'aaf-sms-quorumclient']
        if len(matches) != 1 or matches[0].get('configMap', {}).get('name') != QUORUM:
            raise ValueError('Unreviewed quorum configuration reference')
        mounts = c['volumeMounts']
        if [m for m in mounts if m['mountPath'] == '/quorumclient/config.json'] != [
                {'mountPath': '/quorumclient/config.json', 'name': 'aaf-sms-quorumclient', 'subPath': 'config.json'}]:
            raise ValueError('Unreviewed quorum configuration mount')
        if any(v['name'] == 'phase3-sms-backend' for v in volumes):
            raise ValueError('SMS backend volume collision')
        matches[0]['configMap']['name'] = config(context)['metadata']['name']
        volumes.append({'name': 'phase3-sms-backend', 'configMap': {
            'name': config(context)['metadata']['name'], 'defaultMode': 292}})
        mounts.append({'name': 'phase3-sms-backend', 'mountPath': '/phase3-sms-backend', 'readOnly': True})
        c['image'] = QUORUM_IMAGE
    else:
        if r['spec'].get('replicas') != 1 or len(pod['containers']) != 2:
            raise ValueError('Unreviewed SMS Vault inventory')
        for c in pod['containers']:
            expected = {'aaf-sms-vault': ('docker.io/library/vault:1.3.3', VAULT_IMAGE),
                        'aaf-sms-vault-backend': ('docker.io/library/consul:1.7.1', CONSUL_IMAGE)}.get(c['name'])
            if expected is None or c['image'] != expected[0]:
                raise ValueError('Unreviewed SMS Vault/Consul image')
            c['image'] = expected[1]
    return r


def check_stock_config(resource):
    if resource.get('kind') == 'ConfigMap' and resource.get('metadata', {}).get('name') == QUORUM:
        sms.namespace_guard(resource, 'ConfigMap', QUORUM)
        if json.loads(resource.get('data', {}).get('config.json', '{}')) != STOCK_CONFIG:
            raise ValueError('Unreviewed stock quorum TLS configuration')


def decrypt_shard(private_key, encrypted):
    """Validate in operator-private temporary storage; never return/log plaintext."""
    key = base64.b64decode(private_key, validate=True)
    ciphertext = base64.b64decode(encrypted, validate=True)
    with tempfile.TemporaryDirectory(prefix='phase3-quorum-gpg-') as directory:
        def gpg(args, data):
            p = subprocess.run(['gpg', '--batch', '--no-tty', '--homedir', directory]+args,
                               input=data, capture_output=True, timeout=30)
            if p.returncode:
                raise ValueError('Private quorum crypto validation failed; no material printed')
            return p.stdout
        gpg(['--import'], key)
        plain = gpg(['--decrypt'], ciphertext).strip()
        # Vault 1.3.3 encrypts the hex representation when PGP is requested.
        if not re.fullmatch(b'[a-fA-F0-9]{66}', plain):
            raise ValueError('Unexpected Vault share encoding')
        raw = bytes.fromhex(plain.decode('ascii'))
        # Vault Shamir shares include a one-byte share index.
        if len(raw) != 33:
            raise ValueError('Unexpected Vault share encoding')
        return hashlib.sha256(raw).hexdigest()


def recovery_checks(entries):
    if len(entries) != 3:
        raise ValueError('Three quorum recovery sets are required')
    ids, shares, bindings = [], [], []
    for entry in entries:
        values = entry['files']
        if set(values) != {'id', 'pbkey', 'prkey', 'shard'} or any(not v for v in values.values()):
            raise ValueError('Incomplete persisted quorum recovery set')
        identity = values['id'].decode().strip()
        if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', identity):
            raise ValueError('Invalid quorum identity')
        ids.append(identity)
        bindings.append(hashlib.sha256(values['id']+b'\0'+values['pbkey']+b'\0'+values['shard']).hexdigest())
        # Confirm the persisted public key matches the private key by importing
        # both and comparing their primary public-key fingerprints.
        with tempfile.TemporaryDirectory(prefix='phase3-quorum-pair-') as directory:
            fingerprints = []
            for key in ('pbkey', 'prkey'):
                p = subprocess.run(['gpg', '--batch', '--no-tty', '--homedir', directory,
                    '--with-colons', '--import-options', 'show-only', '--import'],
                    input=base64.b64decode(values[key], validate=True), capture_output=True, timeout=30)
                found = [line.split(b':')[9] for line in p.stdout.splitlines() if line.startswith(b'fpr:')]
                if p.returncode or not found:
                    raise ValueError('Invalid persisted quorum key pair')
                fingerprints.append(found[0])
            if fingerprints[0] != fingerprints[1]:
                raise ValueError('Persisted quorum public/private keys differ')
        shares.append(decrypt_shard(values['prkey'], values['shard']))
    if len(set(ids)) != 3 or len(set(shares)) != 3:
        raise ValueError('Quorum identities or decrypted shares are duplicated')
    return {'sets': 3, 'nonempty': True, 'matching_key_pairs': True, 'distinct_valid_shares': True,
            'encrypted_material_binding_sha256': hashlib.sha256(json.dumps(bindings).encode()).hexdigest()}


def vault_status(data):
    initialized = data.get('initialized') is True
    if (data.get('version') != '1.3.3' or
            (initialized and (data.get('n'),data.get('t')) != (3,3)) or
            (not initialized and (data.get('n'),data.get('t')) != (0,0))):
        raise ValueError('Unreviewed Vault version/quorum threshold')
    return {'initialized': data.get('initialized') is True, 'sealed': data.get('sealed') is not False,
            'version': data['version'], 'shares': data['n'], 'threshold': data['t']}
