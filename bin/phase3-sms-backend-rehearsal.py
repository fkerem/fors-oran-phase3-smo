#!/usr/bin/env python3
"""Real SMS/Vault/Consul/quorum binaries, synthetic data, loopback-only network."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from phase3_lab_pki import certificate, name, private_write
import phase3_sms_backend as backend


def check(directory, docker):
    root = Path(directory).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    created = []
    names = {}
    def command(args, allow=False, data=None, timeout=90):
        p = subprocess.run(docker+args, input=data, capture_output=True, timeout=timeout)
        if p.returncode and not allow:
            private_write(root/('error-%d.stderr' % time.time_ns()), p.stderr)
            raise ValueError('Isolated backend command failed; private diagnostics retained')
        return p
    def start(role, image, args, case, environment=()):
        cname = 'phase3-backend-%d-%s-%s' % (os.getpid(), case.name, role)
        argv = ['run', '-d', '--name', cname, '--network',
                'none' if role == 'control' else 'container:'+names['control'],
                '--user', str(os.getuid())+':'+str(os.getgid()),
                '--mount', 'type=bind,src='+str(case)+',dst=/fixture']
        for key, value in environment:
            argv += ['-e', key+'='+value]
        argv += ['--workdir', '/fixture/'+role, '--entrypoint', args[0], image]+args[1:]
        command(argv); created.append(cname); names[role] = cname
        actual=json.loads(command(['inspect',cname]).stdout)[0]
        network=actual['HostConfig']['NetworkMode']
        if ((role=='control' and network!='none') or
                (role!='control' and not network.startswith('container:')) or actual['HostConfig'].get('PortBindings')):
            raise ValueError('Isolated fixture network/port contract changed')
        return cname
    def probe(kind, *arguments):
        # Values used here are synthetic fixture-only. The live gate has its own
        # private credential flow and never prints authentication responses.
        source = r'''import json,sys,ssl,urllib.request,urllib.error
kind=sys.argv[1]
if kind=='status':
 print(urllib.request.urlopen('http://127.0.0.1:8200/v1/sys/seal-status',timeout=5).read().decode())
elif kind=='sms':
 ctx=ssl.create_default_context(cafile='/fixture/root.cer')
 try:
  r=urllib.request.urlopen('https://localhost:10443/v1/sms/domain/fixture/secret',context=ctx,timeout=5)
  print(r.status)
 except urllib.error.HTTPError as e:print(e.code)
elif kind=='seal':
 role=open('/fixture/sms/auth/role').read();secret=open('/fixture/sms/auth/secret').read()
 body=json.dumps({'role_id':role,'secret_id':secret}).encode()
 r=json.load(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8200/v1/auth/approle/login',data=body),timeout=5))
 token=r['auth']['client_token']
 def api(method,path,data=None):
  body=json.dumps(data).encode() if data is not None else None
  return json.load(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8200'+path,
   data=body,method=method,headers={'X-Vault-Token':token}),timeout=5))
 caps=api('POST','/v1/sys/capabilities-self',{'path':'sms/phase3-metadata-probe'})['capabilities']
 if not {'read','list'}.issubset(caps) or 'sudo' in caps:raise SystemExit('Unexpected metadata capabilities')
 mounts=api('GET','/v1/sys/internal/ui/mounts')['data']['secret']
 if not isinstance(mounts,dict):raise SystemExit('No mount catalog')
 # The ordinary SMS role deliberately cannot seal Vault. This branch only
 # verifies the backend role remains scoped, never escalates it.
 try:
  urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8200/v1/sys/seal',data=b'{}',headers={'X-Vault-Token':token}),timeout=5)
  raise SystemExit('Unexpected seal privilege')
 except urllib.error.HTTPError as e:
  if e.code!=403:raise
 urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8200/v1/auth/token/revoke-self',data=b'{}',headers={'X-Vault-Token':token}),timeout=5)
 print('scoped')
'''
        p = command(['exec', names['control'], 'python3', '-c', source, kind, *arguments], allow=True)
        return p.returncode, p.stdout
    def status():
        rc, output = probe('status')
        if rc: return None
        return json.loads(output)
    def wait(predicate, description, seconds=90):
        deadline = time.monotonic()+seconds
        while not predicate():
            if time.monotonic() >= deadline:
                raise ValueError('Isolated backend timed out: '+description)
            time.sleep(.5)
    def cleanup():
        for cname in reversed(created):
            for stream in ('stdout', 'stderr'):
                p = command(['logs', cname], allow=True)
                private_write(root/(cname+'.'+stream), getattr(p, stream))
            command(['rm', '-f', cname], allow=True)
        created.clear(); names.clear()
    images = dict(backend.IMAGES)
    images['control'] = 'nexus3.onap.org:10001/onap/oom/readiness@sha256:317c8a361ae73750f4d4a1b682c42b73de39083f73228dede31fd68b16c089db'
    results = {}
    try:
        for image in images.values(): command(['pull', image], timeout=600)
        for mode in ('fresh-and-restart', 'interrupted-before-custody', 'interrupted-before-auth',
                     'wrong-ca', 'missing-ca', 'wrong-hostname', 'expired-server'):
            case = root/mode; case.mkdir(mode=0o700)
            for role in ('control', 'consul', 'vault', 'sms', 'quorum-0', 'quorum-1', 'quorum-2'):
                (case/role).mkdir(mode=0o700)
            (case/'sms/auth').mkdir(mode=0o700)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ca = certificate(name('isolated backend root'), ca_key, name('isolated backend root'), ca_key, 2, True, 0)
            leaf = certificate(name('localhost'), key, ca.subject, ca_key, 1, sans=['localhost','aaf-sms.onap'])
            if mode == 'wrong-hostname':
                leaf = certificate(name('wrong.invalid'),key,ca.subject,ca_key,1,sans=['wrong.invalid'])
            elif mode == 'expired-server':
                now = datetime.now(timezone.utc)
                leaf = (x509.CertificateBuilder().subject_name(name('localhost')).issuer_name(ca.subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now-timedelta(days=2)).not_valid_after(now-timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False)
                    .sign(ca_key,hashes.SHA256()))
            for filename, blob in [('root.cer', ca.public_bytes(serialization.Encoding.PEM)),
                    ('server.cer', leaf.public_bytes(serialization.Encoding.PEM)),
                    ('server.key', key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                     serialization.NoEncryption()))]:
                private_write(case/filename, blob)
            private_write(case/'vault.json', json.dumps({'disable_mlock': True,
                'listener': {'tcp': {'address': '127.0.0.1:8200', 'tls_disable': True}},
                'storage': {'consul': {'address': '127.0.0.1:8500', 'path': 'vault/'}}}).encode())
            private_write(case/'sms/smsconfig.json', json.dumps({'cafile': '/fixture/root.cer',
                'servercert': '/fixture/server.cer', 'serverkey': '/fixture/server.key',
                'password': '', 'smsdbaddress': 'http://127.0.0.1:8200'}).encode())
            negative_tls = mode in ('wrong-ca','missing-ca','wrong-hostname','expired-server')
            if negative_tls:
                private_write(case/'tls-fixture.py',(Path(__file__).resolve().parents[1]/'tools/Phase3QuorumTlsFixture.py').read_bytes())
                start('control',images['control'],['python3','/fixture/tls-fixture.py'],case)
                wait(lambda:(case/'tls-ready').exists(),'synthetic TLS listener')
                settings = dict(backend.STOCK_CONFIG,url='https://localhost:10443',cafile='/fixture/root.cer',timeout='1s')
                if mode == 'wrong-ca':
                    other_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
                    other=certificate(name('wrong root'),other_key,name('wrong root'),other_key,1,True,0)
                    private_write(case/'wrong.cer',other.public_bytes(serialization.Encoding.PEM))
                    settings['cafile']='/fixture/wrong.cer'
                elif mode == 'missing-ca': settings['cafile']='/fixture/missing.cer'
                private_write(case/'quorum-0/config.json',json.dumps(settings).encode())
                start('quorum-0',images['quorum'],['/quorumclient/bin/quorumclient'],case,[('HOSTNAME','quorum-0')])
                expected = {'wrong-ca':b'unknown authority','missing-ca':b'Error while reading CA file',
                    'wrong-hostname':b'certificate is valid for','expired-server':b'certificate has expired'}[mode]
                wait(lambda:expected in (command(['logs',names['quorum-0']],allow=True).stdout+
                    command(['logs',names['quorum-0']],allow=True).stderr),'exact quorum TLS refusal: '+mode,45)
                if (case/'requests.jsonl').exists() and (case/'requests.jsonl').stat().st_size:
                    raise ValueError('Quorum accepted invalid TLS')
                results[mode]={'passed':True,'application_requests':0,'exact_quorum_tls_refusal':True}
                cleanup(); continue
            start('control', images['control'], ['python3','-c','import time;time.sleep(1800)'], case)
            start('consul', images['consul'], ['consul','agent','-server','-bootstrap-expect=1',
                  '-bind=127.0.0.1','-client=127.0.0.1','-data-dir=/fixture/consul/data'], case)
            start('vault', images['vault'], ['vault','server','-config=/fixture/vault.json'], case)
            wait(lambda: status() is not None, 'Vault listener')
            if status()['initialized']: raise ValueError('Isolated fixture was not empty')
            start('sms', images['sms'], ['/sms/bin/sms'], case)
            wait(lambda: bool(status() and status()['initialized']), 'stock SMS initializes empty Vault')
            if mode == 'interrupted-before-custody':
                command(['restart', names['sms']])
                wait(lambda: probe('sms')[0] == 0, 'restarted SMS TLS')
                if not status()['sealed'] or any((case/'sms/auth'/n).exists() for n in ('role','secret')):
                    raise ValueError('Unexpected interrupted-bootstrap recovery')
                results[mode] = {'blocked': True, 'sealed': True, 'backend_credentials_absent': True,
                                 'no_reinitialization': True}
                cleanup(); continue
            for i in range(3):
                role = 'quorum-'+str(i)
                settings = dict(backend.STOCK_CONFIG, url='https://localhost:10443', cafile='/fixture/root.cer', timeout='1s')
                private_write(case/role/'config.json', json.dumps(settings).encode())
                start(role, images['quorum'], ['/quorumclient/bin/quorumclient'], case, [('HOSTNAME',role)])
                if i == 1:
                    wait(lambda:bool(status() and status()['sealed'] and status().get('progress')==2),
                         'two shares are insufficient',60)
            wait(lambda: bool(status() and not status()['sealed']), 'three stock quorum clients unseal Vault', 120)
            if mode == 'interrupted-before-auth':
                if any((case/'sms/auth'/n).exists() for n in ('role','secret')):
                    raise ValueError('Unreviewed automatic AppRole initialization')
                command(['restart',names['sms']])
                wait(lambda:probe('sms')[0]==0,'restarted SMS without initial root authority')
                if any((case/'sms/auth'/n).exists() for n in ('role','secret')):
                    raise ValueError('Unexpected recovery of missing bootstrap authority')
                results[mode]={'blocked':True,'unsealed':True,'backend_credentials_absent':True,
                              'no_authority_regeneration':True}
                cleanup(); continue
            # This normal SMS read triggers its first-use AppRole initialization;
            # its 500 for an absent domain is NOT an absence/acceptance proof.
            wait(lambda: probe('sms')[0] == 0, 'SMS normal first-use bootstrap')
            wait(lambda: all((case/'sms/auth'/n).is_file() and (case/'sms/auth'/n).stat().st_size
                             for n in ('role','secret')), 'persisted AppRole')
            entries = []
            for i in range(3):
                folder = case/('quorum-'+str(i))/'auth'/('quorum-'+str(i))
                entries.append({'files': {n:(folder/n).read_bytes() for n in ('id','pbkey','prkey','shard')}})
            custody = backend.recovery_checks(entries)
            if probe('seal') != (0, b'scoped\n'): raise ValueError('Backend role exceeded expected privileges')
            # Restart the same isolated server/quorum processes with their exact
            # existing directories. Restart Vault to reseal, not a root API token.
            for role in ('sms','quorum-0','quorum-1','quorum-2','vault'):
                command(['restart', names[role]])
            wait(lambda: bool(status() and not status()['sealed']), 'unseal after isolated restarts', 120)
            wait(lambda: probe('sms')[0] == 0, 'SMS role reload after restart')
            for i, entry in enumerate(entries):
                folder = case/('quorum-'+str(i))/'auth'/('quorum-'+str(i))
                if any((folder/n).read_bytes() != value for n,value in entry['files'].items()):
                    raise ValueError('Restart changed persisted recovery material')
            # Exercise real crypto failure predicates, without changing a live file.
            import copy
            for bad in ('missing-shard','empty-shard','invalid-key','duplicate-identity','duplicate-share'):
                invalid = copy.deepcopy(entries)
                if bad == 'missing-shard': invalid[0]['files'].pop('shard')
                elif bad == 'empty-shard': invalid[0]['files']['shard'] = b''
                elif bad == 'invalid-key': invalid[0]['files']['prkey'] = b'not-base64'
                elif bad == 'duplicate-identity': invalid[1]['files']['id'] = invalid[0]['files']['id']
                else: invalid[1] = copy.deepcopy(invalid[0]); invalid[1]['files']['id'] = entries[1]['files']['id']
                try: backend.recovery_checks(invalid)
                except (ValueError, KeyError): pass
                else: raise ValueError('Invalid recovery material accepted: '+bad)
            results[mode] = {'passed': True, 'custody': custody, 'normal_approle_bootstrap': True,
                            'scoped_role': True, 'sms_and_quorum_restart': True, 'vault_restart_unsealed': True,
                            'invalid_recovery_controls': 5,'two_shares_not_accepted':True,
                            'version_qualified_mount_catalog':True}
            cleanup()
        result = {'schema': 1, 'passed': True, 'images': backend.IMAGES, 'cases': results,
                  'network': 'none; containers share loopback only; no ports published',
                  'synthetic_material_only': True, 'live_api_contacted': False,
                  'fixture_user': 'operator UID; not a live filesystem-permissions equivalence claim',
                  'application_domain_or_secret_posts': 0, 'full_smo_tested': False}
        backend.require_qualification(result)
        private_write(root/'result.json', (json.dumps(result, indent=2)+'\n').encode())
        return result
    finally:
        cleanup()
