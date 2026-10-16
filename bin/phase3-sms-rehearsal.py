#!/usr/bin/env python3
"""Exact-image SMS safety characterization in a no-network loopback fixture."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from phase3_lab_pki import CONFIG_IMAGE, certificate, export_pkcs12, name, private_write
import phase3_sms as sms

ROOT = Path(__file__).resolve().parents[1]


def check(directory, run, docker):
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    root_key, int_key, leaf_key = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]
    root = certificate(name('SMS isolated fixture root'), root_key, name('SMS isolated fixture root'), root_key, 2, True, 1)
    intermediate = certificate(name('SMS isolated intermediate'), int_key, root.subject, root_key, 2, True, 0)
    leaf = certificate(name('localhost'), leaf_key, intermediate.subject, int_key, 1, sans=['localhost', 'aaf-sms.onap'])
    for n, c in [('root', root), ('intermediate', intermediate), ('leaf', leaf)]:
        private_write(directory/(n+'.cer'), c.public_bytes(serialization.Encoding.PEM))
    private_write(directory/'fixture-password', b'fixture-only')
    private_write(directory/'server.p12', export_pkcs12(b'fixture', leaf_key, leaf,
        [intermediate], b'fixture-only', directory/'fixture-password'))
    run(docker+['pull', sms.IMAGE], timeout=600, directory=directory)
    blob = run(docker+['run', '--rm', '--network', 'none', '--entrypoint', '/bin/cat', sms.IMAGE, '/sms/bin/preload'], directory=directory)
    if hashlib.sha256(blob).hexdigest() != sms.PRELOAD_SHA256:
        raise ValueError('Unreviewed SMS executable; no live preload permitted')
    # Rehearse the actual crypto helper in CONFIG_IMAGE, without an AAF API.
    chain_controls = {}
    for mode in ('valid-stale-tail', 'wrong-root', 'wrong-hostname', 'expired-leaf'):
        case = directory/mode; case.mkdir(mode=0o700)
        public = case/'public'; public.mkdir(mode=0o700)
        for n in ('root', 'intermediate'):
            private_write(public/(n+'.cer'), (directory/(n+'.cer')).read_bytes())
        case_leaf = leaf
        if mode == 'wrong-hostname':
            case_leaf = certificate(name('wrong.invalid'), leaf_key, intermediate.subject, int_key, 1, sans=['wrong.invalid'])
        elif mode == 'expired-leaf':
            now = datetime.now(timezone.utc)
            case_leaf = (x509.CertificateBuilder().subject_name(name('aaf-sms.onap'))
                .issuer_name(intermediate.subject).public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2))
                .not_valid_after(now-timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('aaf-sms.onap')]), False)
                .sign(int_key, hashes.SHA256()))
        if mode == 'wrong-root':
            other = certificate(name('wrong root'), root_key, name('wrong root'), root_key, 2, True, 1)
            (public/'root.cer').write_bytes(other.public_bytes(serialization.Encoding.PEM))
        target = case/'output'; target.mkdir(mode=0o700)
        # A wrong appended tail must be replaced, never carried forward.
        original = case_leaf.public_bytes(serialization.Encoding.PEM)+root.public_bytes(serialization.Encoding.PEM)
        private_write(target/'org.onap.aaf-sms.crt', original)
        state = case/'state'; state.mkdir(mode=0o700)
        command = docker+['run', '--rm', '--network', 'none',
            '--mount', 'type=bind,src='+str(public)+',dst=/phase3-sms,readonly',
            '--mount', 'type=bind,src='+str(target)+',dst=/opt/app/osaaf/local',
            '--mount', 'type=bind,src='+str(state)+',dst=/phase3-sms-attempt',
            '--mount', 'type=bind,src='+str(ROOT/'bin/phase3-sms-chain.sh')+',dst=/checks/chain.sh,readonly',
            '--entrypoint', '/bin/bash', CONFIG_IMAGE, '/checks/chain.sh']
        result = subprocess.run(command, capture_output=True, timeout=60)
        private_write(case/'initializer.stdout', result.stdout); private_write(case/'initializer.stderr', result.stderr)
        positive = mode == 'valid-stale-tail'
        if (result.returncode == 0) != positive:
            raise ValueError('Unexpected exact-image SMS chain control: '+mode)
        if positive:
            expected = leaf.public_bytes(serialization.Encoding.PEM)+intermediate.public_bytes(serialization.Encoding.PEM)
            if (target/'org.onap.aaf-sms.crt').read_bytes() != expected:
                raise ValueError('SMS public chain differs from deterministic fixture result')
            again = subprocess.run(command, capture_output=True, timeout=60)
            if again.returncode == 0: raise ValueError('SMS initializer latch failed')
        elif (target/'org.onap.aaf-sms.crt').read_bytes() != original:
            raise ValueError('Failed chain validation changed the issued certificate')
        chain_controls[mode] = True
    observations = {}
    for mode in ('positive', 'write-error', 'existing-domain', 'ambiguous', 'missing-ca'):
        case = directory/mode; case.mkdir(mode=0o700)
        for n in ('root.cer', 'server.p12'): private_write(case/n, (directory/n).read_bytes())
        inputs = case/'inputs'; inputs.mkdir(mode=0o700)
        private_write(inputs/'fixture.json', json.dumps({'domain': {'name': 'fixture', 'secrets': [
            {'name': 'fixture-secret', 'values': {'fixture': 'not-a-credential'}}]}}).encode())
        container = 'phase3-sms-fixture-'+str(os.getpid())+'-'+mode
        try:
            run(docker+['run', '-d', '--name', container, '--network', 'none',
                '--mount', 'type=bind,src='+str(case)+',dst=/fixture',
                '--mount', 'type=bind,src='+str(ROOT/'tools/Phase3SmsFixture.java')+',dst=/checks/Phase3SmsFixture.java,readonly',
                '--entrypoint', 'java', CONFIG_IMAGE, '/checks/Phase3SmsFixture.java', mode], directory=directory)
            deadline = time.monotonic()+45
            while not (case/'ready').exists():
                if time.monotonic() >= deadline: raise ValueError('Isolated SMS fixture did not start')
                time.sleep(.2)
            ca = '/fixture/root.cer' if mode != 'missing-ca' else '/fixture/missing.cer'
            command = docker+['run', '--rm', '--network', 'container:'+container,
                # Synthetic private files are owned by the rehearsal operator,
                # not the live image's UID 1000. No live-user equivalence claim.
                '--user', str(os.getuid())+':'+str(os.getgid()),
                '--mount', 'type=bind,src='+str(case)+',dst=/fixture,readonly',
                '--entrypoint', '/sms/bin/preload', sms.IMAGE,
                '-cacert', ca, '-serviceurl', 'https://localhost', '-serviceport', '10443', '-jsondir', '/fixture/inputs']
            result = subprocess.run(command, capture_output=True, timeout=90)
            private_write(case/'preload.stdout', result.stdout); private_write(case/'preload.stderr', result.stderr)
            requests = (case/'requests.txt').read_text().splitlines() if (case/'requests.txt').is_file() else []
            observation = {'exit_code': result.returncode,
                'domain_posts': requests.count('POST /v1/sms/domain'),
                'secret_posts': requests.count('POST /v1/sms/domain/fixture/secret'),
                'upload_marker_count': result.stdout.count(b'Uploading data...'),
                'insecure_fallback': b'Using Insecure Server Verification' in result.stdout,
                'retry_marker_count': result.stdout.count(b'Retrying...')}
            if observation['exit_code'] != 0: raise ValueError('Exact preload fixture behavior changed')
            if mode == 'positive' and (observation['domain_posts'], observation['secret_posts']) != (1, 1):
                raise ValueError('Missing exact-image positive write control')
            if mode in ('write-error', 'ambiguous') and observation['domain_posts'] != 5:
                raise ValueError('Exact-image retry characterization changed')
            if mode == 'existing-domain' and observation['secret_posts'] != 1:
                raise ValueError('Existing-domain continuation characterization changed')
            if mode == 'missing-ca' and not observation['insecure_fallback']:
                raise ValueError('Exact-image missing-CA characterization changed')
            observations[mode] = observation
        finally:
            # Only the explicitly created, uniquely named isolated fixture.
            subprocess.run(docker+['rm', '-f', container], capture_output=True, timeout=30)
    record = {'schema': 1, 'passed': True, 'image': sms.IMAGE, 'preload_sha256': sms.PRELOAD_SHA256,
        'chain_script_sha256': hashlib.sha256((ROOT/'bin/phase3-sms-chain.sh').read_bytes()).hexdigest(),
        'chain_controls': chain_controls, 'preload_characterization': observations,
        'network': 'none; two containers share loopback only; no published ports',
        'live_api_contacted': False, 'live_preload_authorized': False,
        'log_only_guard_accepted': False,
        'reason': 'Existing-domain response permits immediate secret writes; log supervision is not a request interlock.'}
    private_write(directory/'result.json', (json.dumps(record, indent=2)+'\n').encode())
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--directory', required=True)
    args = parser.parse_args(); os.umask(0o077)
    spec = importlib.util.spec_from_file_location('sms_fresh', ROOT/'bin/phase3-fresh-start.py')
    fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
    try:
        result = check(args.directory, fresh.run, fresh.docker_prefix())
        print('SMS chain controls passed; exact-image characterization requires preload to remain held')
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, 'SMS isolated rehearsal stopped: '+str(error)+'\n')
