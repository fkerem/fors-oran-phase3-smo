#!/usr/bin/env python3
"""Qualify guarded preload with synthetic data in exact, isolated images.

No kubectl, experiment endpoints, root credentials or stock preload invocation.
Only a completed exact-image run may produce a qualified receipt.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
READINESS_IMAGE = 'nexus3.onap.org:10001/onap/oom/readiness@sha256:317c8a361ae73750f4d4a1b682c42b73de39083f73228dede31fd68b16c089db'
FAULTS = ('domain-500', 'domain-conflict', 'secret-500', 'ambiguous-domain',
          'ambiguous-secret', 'malformed-domain', 'malformed-readback',
          'changed-readback', 'extra-value-key', 'extra-secret')
TLS_CASES = ('wrong-ca', 'missing-ca', 'wrong-hostname', 'expired-server')
JOURNAL_CASES = ('success', 'execute', 'stale-rv', 'replaced-read-uid', 'replaced-write-uid',
                 'read-403', 'read-redirect', 'write-500', 'write-redirect',
                 'malformed-read', 'oversized-read', 'ambiguous-commit')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def fixture_modules():
    import phase3_preload
    import Phase3PreloadFixture
    return phase3_preload, Phase3PreloadFixture


def synthetic_plan(preload):
    plan = preload.synthetic_inputs()
    if len(plan['domains']) != 2 or sum(len(d['secrets']) for d in plan['domains']) != 20:
        raise ValueError('Reviewed preload inventory changed')
    return plan


def run_faults(directory):
    """Execute the shared client against a separately implemented HTTPS server."""
    preload, fixture = fixture_modules()
    directory = Path(directory)
    plan = synthetic_plan(preload)
    binding = {'fixture': 'isolated-synthetic-preload'}
    results = {}
    for mode in ('success',) + FAULTS:
        state = fixture.State(mode)
        journal = fixture.Journal(binding)
        with fixture.Server(state, directory/'server.cer', directory/'server.key') as port:
            transport = preload.Transport(directory/'root.cer', '127.0.0.1', hostname='localhost', port=port)
            failed = False
            try:
                verified = preload.execute(plan, transport, journal, binding, 'fixture-pod')
                preload.verify_values(plan, transport)
            except Exception:
                if mode == 'success':
                    raise
                failed = True
        counts = state.counts()
        if mode == 'success':
            if failed or verified.get('state') != 'verified' or counts != {'domain_posts': 2, 'secret_posts': 20}:
                raise ValueError('Independent positive control failed')
        elif not failed:
            raise ValueError('Adversarial fixture was accepted: ' + mode)
        elif mode in ('domain-500', 'domain-conflict', 'ambiguous-domain', 'malformed-domain'):
            if counts != {'domain_posts': 1, 'secret_posts': 0}:
                raise ValueError('Client continued/retried uncertain domain write')
        elif mode in ('secret-500', 'ambiguous-secret'):
            if counts != {'domain_posts': 2, 'secret_posts': 1}:
                raise ValueError('Client continued/retried uncertain secret write')
        # Re-entering an uncertain attempt must never issue another write.
        if mode in ('ambiguous-domain', 'ambiguous-secret'):
            before = list(state.requests)
            try:
                preload.execute(plan, state, journal, binding, 'fixture-pod')
            except Exception:
                pass
            if state.requests != before:
                raise ValueError('Uncertain attempt contacted SMS on replay')
        results[mode] = dict(counts, passed=True, rejected=failed)
    for mode in TLS_CASES:
        state = fixture.State()
        certdir = directory/'tls'/mode
        with fixture.Server(state, certdir/'server.cer', certdir/'server.key') as port:
            failed = False
            try:
                ca = directory/'missing.cer' if mode == 'missing-ca' else directory/'root.cer'
                transport = preload.Transport(ca, '127.0.0.1', hostname='localhost', port=port)
                preload.execute(plan, transport, fixture.Journal(binding), binding, 'fixture-pod')
            except (OSError, ValueError, ssl.SSLError):
                failed = True
        if not failed or state.requests:
            raise ValueError('Invalid TLS reached the application: ' + mode)
        results[mode] = {'passed': True, 'rejected': True, 'application_requests': 0}
    return results


def run_journal(directory):
    """Exercise the staged production adapter over real verified HTTPS.

    Only projected-file locations are mapped to fixture files. Network calls,
    TLS verification, serialization, UID validation and CAS run unchanged.
    """
    preload, fixture = fixture_modules()
    directory = Path(directory)
    source = directory/'phase3-sms-preload-client.py'
    compile(source.read_bytes(), str(source), 'exec')
    client = load('isolated_preload_client_adapter', source)
    token = directory/'projected-token'
    descriptor = os.open(str(token), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write('isolated-fixture-token\n')
    real_path, real_ssl = client.Path, client.ssl
    saved_environment = {k: os.environ.get(k) for k in ('KUBERNETES_SERVICE_HOST', 'KUBERNETES_SERVICE_PORT_HTTPS')}

    def mapped_path(path):
        if path != '/phase3-api/token':
            raise ValueError('Adapter accessed an unexpected projected file')
        return real_path(token)

    def mapped_context(cafile=None):
        if cafile != '/phase3-api/ca.crt':
            raise ValueError('Adapter accessed an unexpected projected CA')
        # Real trust validation against the synthetic root; no insecure context.
        return real_ssl.create_default_context(cafile=str(directory/'root.cer'))

    client.Path = mapped_path
    client.ssl = SimpleNamespace(create_default_context=mapped_context, TLSVersion=real_ssl.TLSVersion)
    results = {}
    try:
        for mode in JOURNAL_CASES:
            state = fixture.KubeState(mode)
            with fixture.Server(state, directory/'server.cer', directory/'server.key') as port:
                os.environ['KUBERNETES_SERVICE_HOST'] = 'localhost'
                os.environ['KUBERNETES_SERVICE_PORT_HTTPS'] = str(port)
                journal = client.KubeJournal('fixture-journal-uid')
                failed = False
                try:
                    if mode == 'execute':
                        sms_state = fixture.State()
                        result = preload.execute(synthetic_plan(preload), sms_state, journal,
                                                 {'fixture': 'synthetic'}, 'fixture-pod')
                        if result.get('state') != 'verified' or sms_state.counts() != {'domain_posts': 2, 'secret_posts': 20}:
                            raise ValueError('Staged adapter did not support full execution')
                    else:
                        old = journal.read()
                        if old.get('_resourceVersion') != '1' or old.get('state') != 'prepared':
                            raise ValueError('Staged adapter did not read journal RV')
                        if mode == 'stale-rv':
                            state.version += 1
                        journal.cas(old, dict(old, state='claimed', _local='never-persist'))
                        if mode == 'success':
                            new = journal.read()
                            if new.get('_resourceVersion') != '2' or new.get('state') != 'claimed' or '_local' in new:
                                raise ValueError('Staged adapter CAS/readback differs')
                except Exception:
                    if mode in ('success', 'execute'):
                        raise
                    failed = True
            counts = {method: sum(m == method for m, p in state.requests) for method in ('GET', 'PUT')}
            if mode not in ('success', 'execute'):
                is_read_fault = mode in ('replaced-read-uid', 'read-403', 'read-redirect', 'malformed-read', 'oversized-read')
                if not failed or counts != {'GET': 1, 'PUT': 0 if is_read_fault else 1}:
                    raise ValueError('Staged adapter retried or accepted journal fault: ' + mode)
                if mode == 'ambiguous-commit' and state.record.get('state') != 'claimed':
                    raise ValueError('Journal ambiguity fixture failed to commit before connection loss')
            results[mode] = {'passed': True, 'rejected': failed, 'get_requests': counts['GET'], 'put_requests': counts['PUT']}
        return {'passed': True, 'adapter_compiled': True, 'real_https': True, 'cases': results}
    finally:
        client.Path, client.ssl = real_path, real_ssl
        for key, value in saved_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def run_real(directory):
    preload, fixture = fixture_modules()
    directory = Path(directory)
    if sys.version_info[:2] != (3, 8):
        raise ValueError('Exact readiness runtime must be Python 3.8')
    plan = synthetic_plan(preload)
    transport = fixture.Transport(10443, directory/'root.cer', directory/'preload'/'private-readback.jsonl',
        client=preload.Transport(directory/'root.cer', '127.0.0.1', hostname='localhost'))
    token = None

    def vault(method, path, data=None, authenticated=True):
        connection = http.client.HTTPConnection('127.0.0.1', 8200, timeout=10)
        headers = {'Content-Type': 'application/json'}
        if authenticated:
            headers['X-Vault-Token'] = token
        try:
            connection.request(method, path, fixture.encoded(data) if data is not None else None, headers)
            response = connection.getresponse()
            blob = response.read(1024 * 1024)
            if response.status not in (200, 204):
                raise ValueError('Exact scoped Vault fixture request refused')
            return json.loads(blob) if blob else {}
        finally:
            connection.close()

    def catalog():
        return vault('GET', '/v1/sys/internal/ui/mounts')

    def audit():
        result = preload.audit_catalog(vault('GET', '/v1/sys/internal/ui/resultant-acl'), catalog())
        if result != {'sms_mounts_absent': True, 'acl_complete': True}:
            raise ValueError('Exact scoped ACL/catalog proof differs')
        return result

    def mounts():
        return catalog()['data']['secret']

    def reject_nonempty():
        try:
            audit()
        except ValueError:
            return
        raise ValueError('Existing Vault SMS namespace accepted as empty')

    try:
        status = vault('GET', '/v1/sys/seal-status', authenticated=False)
        if status.get('version') != '1.3.3' or status.get('sealed') is not False:
            raise ValueError('Expected exact unsealed Vault 1.3.3')
        auth = {name: (directory/'sms/auth'/filename).read_text().strip()
                for name, filename in (('role_id', 'role'), ('secret_id', 'secret'))}
        login = vault('POST', '/v1/auth/approle/login', auth, authenticated=False)
        token = login['auth']['client_token']
        if set(login['auth']['policies']) != {'default', 'smsvaultpolicy'}:
            raise ValueError('Fixture AppRole policies differ')
        audit()  # Exact resultant ACL and version-specific visible-mount semantics.
        # Run the positive control against untouched fresh state. Removing the
        # internal UUID mount underneath a running SMS can invalidate its cached
        # bootstrap state, so destructive seed teardown follows all SMS writes.
        binding = {'fixture': 'exact-images-private-loopback'}
        journal = fixture.Journal(binding)
        verified = preload.execute(plan, transport, journal, binding, 'fixture-pod')
        preload.verify_values(plan, transport)
        if verified.get('state') != 'verified':
            raise ValueError('Exact preload did not produce verified journal')
        writes = [o for o in transport.observations if o[0] == 'POST']
        domain_writes = [o for o in writes if o[1] == '/v1/sms/domain']
        secret_writes = [o for o in writes if o[1] != '/v1/sms/domain']
        if (len(domain_writes) != 2 or len(secret_writes) != 20
                or any(o[2] != 201 or o[3] == 0 for o in domain_writes)
                or any(o[2] != 201 or o[3] != 0 for o in secret_writes)):
            raise ValueError('Exact SMS write-response contract changed')
        actual_mounts = {path for path in mounts() if path.startswith('sms')}
        if actual_mounts != {'sms/has/', 'sms/osdf/', 'sms/smsinternaldomain/'}:
            raise ValueError('Exact SMS postload mount inventory differs')
        for domain in ('has', 'osdf'):
            metadata = vault('GET', '/v1/sms/smsinternaldomain/' + domain)
            if metadata.get('data') != {'uuid': verified['domain_uuids'][domain]}:
                raise ValueError('Exact SMS internal UUID metadata path/shape differs')
        reject_nonempty()
        # Known empty domain: create it without any secret POST. Nil secret-list
        # handling is irrelevant; the version-qualified mount audit is the proof.
        before = set(mounts())
        status, body = transport.request('POST', '/v1/sms/domain', {'name': 'phase3-empty'})
        if status != 201 or not isinstance(json.loads(body), dict):
            raise ValueError('Exact SMS seed domain-create response differs from contract')
        if set(mounts()) - before != {'sms/phase3-empty/'}:
            raise ValueError('Fresh empty-domain mount was not visible to scoped metadata')
        # Remove only this disposable fixture's previously verified synthetic
        # mounts. No further SMS write is made after removing its internal mount.
        for path in sorted(actual_mounts):
            vault('DELETE', '/v1/sys/mounts/' + path)
        if {p for p in mounts() if p.startswith('sms')} != {'sms/phase3-empty/'}:
            raise ValueError('Empty-domain audit was not isolated from other SMS mounts')
        reject_nonempty()
        vault('DELETE', '/v1/sys/mounts/sms/phase3-empty/')
        audit()
        seeds = {}
        for mode in ('internal-mount', 'orphan-data'):
            path = 'sms/smsinternaldomain' if mode == 'internal-mount' else 'sms/phase3-orphan-data'
            vault('POST', '/v1/sys/mounts/' + path, {'type': 'kv', 'config': {'listing_visibility': 'hidden'}})
            try:
                if mode == 'orphan-data':
                    vault('POST', '/v1/' + path + '/unlisted-record', {'value': 'synthetic-orphan-only'})
                if path + '/' not in mounts():
                    raise ValueError('Scoped mount catalog hid an SMS prefix mount')
                reject_nonempty()
                seeds[mode] = {'blocked': True}
            finally:
                vault('DELETE', '/v1/sys/mounts/' + path)
            audit()
        return {'passed': True, 'python': '3.8', 'vault_version': '1.3.3',
                'normal_scoped_approle': True, 'exact_scoped_acl': True,
                'mount_metadata_semantics': True, 'empty-domain': {'blocked': True},
                **seeds, 'domains': 2, 'records': 20, 'full_private_readback': True,
                'domain_create': '201 JSON', 'secret_create': '201 empty',
                'internal_uuid_metadata_qualified': True,
                'internal_uuid_path': '/v1/sms/smsinternaldomain/{domain}',
                'postload_mount_inventory_qualified': True,
                'verified_journal': True, 'nonempty_after_preload_blocked': True}
    finally:
        if token is not None:
            vault('POST', '/v1/auth/token/revoke-self', {})


def source_paths():
    return {path.name: path for path in (Path(__file__), ROOT/'tools/Phase3PreloadFixture.py',
            ROOT/'bin/phase3_preload.py', ROOT/'bin/phase3-sms-preload-client.py')}


def capture_sources():
    return {name: path.read_bytes() for name, path in source_paths().items()}


def hashes(sources):
    return {name: hashlib.sha256(blob).hexdigest() for name, blob in sources.items()}


def require_unchanged_sources(sources):
    if capture_sources() != sources:
        raise ValueError('Preload source changed during qualification; no receipt issued')


def require_staged_sources(target, expected):
    if {name: hashlib.sha256((target/name).read_bytes()).hexdigest() for name in expected} != expected:
        raise ValueError('Staged preload source changed during qualification')


def stage(case, sources):
    """Copy code and synthetic TLS controls into the owned private bind mount."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone
    from phase3_lab_pki import certificate, name, private_write
    target = case/'preload'
    target.mkdir(mode=0o700)
    for filename, blob in sources.items():
        private_write(target/filename, blob)
    tested_hashes = {filename: hashlib.sha256((target/filename).read_bytes()).hexdigest() for filename in sources}
    if tested_hashes != hashes(sources):
        raise ValueError('Staged source does not match captured source')
    private_write(target/'source-hashes.json', json.dumps(tested_hashes, sort_keys=True).encode())
    # Negative servers have a separate root except the bad-host/expired controls,
    # which are signed by an independent root trusted only by the fault worker.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = certificate(name('preload synthetic root'), ca_key, name('preload synthetic root'), ca_key, 1, True, 0)
    private_write(target/'root.cer', ca.public_bytes(serialization.Encoding.PEM))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    good = certificate(name('localhost'), key, ca.subject, ca_key, 1, sans=['localhost'])
    key_blob = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption())
    private_write(target/'server.key', key_blob)
    private_write(target/'server.cer', good.public_bytes(serialization.Encoding.PEM))
    (target/'tls').mkdir(mode=0o700)
    for mode in TLS_CASES:
        folder = target/'tls'/mode
        folder.mkdir(mode=0o700)
        leaf = good
        if mode == 'wrong-ca':
            wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            wrong = name('untrusted synthetic root')
            leaf = certificate(name('localhost'), key, wrong, wrong_key, 1, sans=['localhost'])
        elif mode == 'wrong-hostname':
            leaf = certificate(name('wrong.invalid'), key, ca.subject, ca_key, 1, sans=['wrong.invalid'])
        elif mode == 'expired-server':
            now = datetime.now(timezone.utc)
            leaf = (x509.CertificateBuilder().subject_name(name('localhost')).issuer_name(ca.subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=2)).not_valid_after(now - timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
                    .sign(ca_key, crypto_hashes.SHA256()))
        private_write(folder/'server.cer', leaf.public_bytes(serialization.Encoding.PEM))
        private_write(folder/'server.key', key_blob)
    return target


def validate_observations(observations):
    if set(observations) != {'real', 'faults', 'journal'}:
        raise ValueError('Preload exact-image callback did not run')
    real, cases = observations['real'], observations['faults']
    expected = {'passed': True, 'python': '3.8', 'vault_version': '1.3.3',
                'normal_scoped_approle': True, 'exact_scoped_acl': True,
                'mount_metadata_semantics': True, 'domains': 2, 'records': 20,
                'full_private_readback': True, 'domain_create': '201 JSON',
                'secret_create': '201 empty', 'verified_journal': True,
                'internal_uuid_metadata_qualified': True,
                'internal_uuid_path': '/v1/sms/smsinternaldomain/{domain}',
                'postload_mount_inventory_qualified': True,
                'nonempty_after_preload_blocked': True}
    if (any(real.get(k) != v for k, v in expected.items())
            or any(real.get(k) != {'blocked': True} for k in ('empty-domain', 'internal-mount', 'orphan-data'))
            or set(cases) != {'success', *FAULTS, *TLS_CASES}
            or any(cases[k].get('passed') is not True for k in cases)
            or any(cases[k].get('rejected') is not True for k in (*FAULTS, *TLS_CASES))
            or cases['success'].get('domain_posts') != 2 or cases['success'].get('secret_posts') != 20
            or cases['success'].get('rejected') is not False
            or any(cases[k].get('application_requests') != 0 for k in TLS_CASES)):
        raise ValueError('Incomplete exact-image preload observations')
    adapter = observations['journal']
    if (any(adapter.get(k) is not True for k in ('passed', 'adapter_compiled', 'real_https'))
            or set(adapter.get('cases', {})) != set(JOURNAL_CASES)
            or any(adapter['cases'][k].get('passed') is not True for k in JOURNAL_CASES)
            or any(adapter['cases'][k].get('rejected') is not True for k in JOURNAL_CASES if k not in ('success', 'execute'))
            or any(adapter['cases'][k].get('rejected') is not False for k in ('success', 'execute'))):
        raise ValueError('Incomplete staged client adapter qualification')


def check(directory, docker):
    """Return a sanitized qualified receipt, or fail without writing one."""
    from phase3_lab_pki import private_write
    import phase3_sms_backend as backend
    root = Path(directory).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(root, 0o700)
    sources = capture_sources()
    observations = {}
    tested_hashes = {}

    def callback(case, names, command):
        target = stage(case, sources)
        tested_hashes.update(json.loads((target/'source-hashes.json').read_bytes()))
        require_staged_sources(target, tested_hashes)
        # Both workers execute in the already inspected --network none control.
        for worker in ('real', 'faults', 'journal'):
            command(['exec', names['control'], 'python3', '/fixture/preload/' + Path(__file__).name,
                     '--worker', worker], timeout=180)
            require_staged_sources(target, tested_hashes)
            observations[worker] = json.loads((target/(worker + '-result.json')).read_text())

    rehearsal = load('preload_backend_rehearsal', ROOT/'bin/phase3-sms-backend-rehearsal.py')
    backend_receipt = rehearsal.check(root/'backend', docker, callback=callback)
    backend.require_qualification(backend_receipt)
    require_unchanged_sources(sources)
    validate_observations(observations)
    result = {'schema': 1, 'passed': True, 'qualified': True,
              'images': dict(backend.IMAGES, readiness=READINESS_IMAGE),
              'runtime': observations['real'], 'cases': observations['faults'],
              'client_adapter': observations['journal'], 'client_adapter_https_qualified': True,
              'backend_qualified': True, 'synthetic_material_only': True,
              'live_api_contacted': False, 'live_preload_authorized': False,
              'network': 'none; containers share loopback only; no ports published',
              'contract': 1, 'client_image': READINESS_IMAGE,
              'real_sms_posts': 22, 'private_values_verified': 20,
              'real_sms_posts_scope': 'guarded client positive control only', 'seed_sms_posts': 1,
              'seed_sms_posts_scope': 'separate synthetic empty-domain seed',
              'acl_catalog_qualified': True, 'existing_mount_blocked': True,
              'internal_uuid_metadata_qualified': True,
              'client_source_sha256': tested_hashes['phase3-sms-preload-client.py'],
              'contract_source_sha256': tested_hashes['phase3_preload.py'],
              'tested_sources_sha256': tested_hashes,
              'full_smo_tested': False}
    import phase3_preload
    phase3_preload.require_qualification(result)
    private_write(root/'result.json', (json.dumps(result, indent=2) + '\n').encode())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory')
    parser.add_argument('--worker', choices=('real', 'faults', 'journal'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.worker:
        sys.path.insert(0, '/fixture/preload')
        target = Path('/fixture/preload')
        expected = json.loads((target/'source-hashes.json').read_bytes())
        require_staged_sources(target, expected)
        if sys.version_info[:2] != (3, 8):
            raise ValueError('Exact readiness runtime must be Python 3.8')
        workers = {'real': lambda: run_real('/fixture'), 'faults': lambda: run_faults(target),
                   'journal': lambda: run_journal(target)}
        result = workers[args.worker]()
        require_staged_sources(target, expected)
        path = Path('/fixture/preload')/(args.worker + '-result.json')
        with path.open('x') as stream:
            json.dump(result, stream, sort_keys=True)
    else:
        if not args.directory:
            parser.error('--directory is required')
        docker = (['sudo'] if os.geteuid() != 0 and sys.platform != 'darwin' else []) + ['docker']
        try:
            check(args.directory, docker)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            parser.exit(1, 'Preload isolated qualification stopped; private diagnostics retained\n')
        print('Exact-image isolated guarded preload qualification passed; no live API contacted')


if __name__ == '__main__':
    main()
