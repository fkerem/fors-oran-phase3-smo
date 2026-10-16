#!/usr/bin/env python3
"""Rehearse exact VES-image TLS/conversion privately, without an AAF API call."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import phase3_ves
from phase3_lab_pki import CONFIG_IMAGE, private_write

ROOT = Path(__file__).resolve().parents[1]


def check(pki, directory, run, docker):
    pki = Path(pki).resolve()
    directory = Path(directory).resolve()
    run(docker+['pull', phase3_ves.IMAGE], timeout=600, directory=directory)
    expected = {'/opt/dcae/dcae-cert-setup.sh': '31aa68706dd52bcbdb30e243d76c370e60ca222ebf23fe7977de4be4c72b1b0c',
                '/opt/app/aaf_config/bin/agent.sh': '8d5ec5e08a57033449511f9ac66773c105d47b79dee620b4314e867c3f4d276d'}
    for filename, digest in expected.items():
        blob = run(docker+['run', '--rm', '--network', 'none', '--entrypoint', '/bin/cat', phase3_ves.IMAGE, filename], directory=directory)
        if hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError('Unreviewed VES image source')
    classes = directory/'ves-java8-classes'
    classes.mkdir(mode=0o700)
    run(docker+['run', '--rm', '--network', 'none', '--user', str(os.getuid())+':'+str(os.getgid()),
        '--mount', 'type=bind,src='+str(classes)+',dst=/classes',
        '--mount', 'type=bind,src='+str(ROOT/'tools/Phase3PkiTlsProbe.java')+',dst=/checks/Phase3PkiTlsProbe.java,readonly',
        # The pinned image contains the compiler module used by source launch,
        # but not a javac executable. Invoke that same compiler module directly.
        '--entrypoint', 'java', CONFIG_IMAGE, '-m', 'jdk.compiler/com.sun.tools.javac.Main',
        '--release', '8', '-d', '/classes', '/checks/Phase3PkiTlsProbe.java'], directory=directory)
    # All network activity during these controls is in-container loopback only.
    script = '''set -eu
java -cp /classes Phase3PkiTlsProbe /phase3-pki jks-only
mkdir /tmp/converted
openssl pkcs12 -in /phase3-pki/server.p12 -passin file:/phase3-pki/store-password -nodes -nokeys -out /tmp/converted/cert.pem
openssl pkcs12 -in /phase3-pki/server.p12 -passin file:/phase3-pki/store-password -nodes -nocerts -out /tmp/converted/key.pem
openssl verify -CAfile /phase3-pki/root.cer -untrusted /tmp/converted/cert.pem /tmp/converted/cert.pem
openssl x509 -in /tmp/converted/cert.pem -pubkey -noout >/tmp/converted/cert-public.pem
openssl pkey -in /tmp/converted/key.pem -pubout >/tmp/converted/key-public.pem
cmp /tmp/converted/cert-public.pem /tmp/converted/key-public.pem
'''
    run(docker+['run', '--rm', '--network', 'none',
        '--mount', 'type=bind,src='+str(classes)+',dst=/classes,readonly',
        '--mount', 'type=bind,src='+str(pki)+',dst=/phase3-pki,readonly',
        '--entrypoint', '/bin/bash', phase3_ves.IMAGE, '-c', script], timeout=120, directory=directory)
    return {'passed': True, 'image': phase3_ves.IMAGE, 'source_sha256': expected,
            'java8_tls_positive_and_negative_controls': True, 'openssl_conversion': True,
            'live_certificate_retrieval_tested': False, 'network': 'none; loopback fixture only'}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('fresh_start', ROOT/'bin/phase3-fresh-start.py')
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    try:
        fresh.offline_rehearsal(args.directory, 'isolated-ves-rehearsal')
        print('Isolated VES TLS/conversion rehearsal passed; no live AAF request sent')
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, 'VES rehearsal failed: '+str(error)+'\n')
