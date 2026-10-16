#!/usr/bin/env python3
"""Exact-image qualification, synthetic PostgreSQL/AAF/MR, no live endpoints.

Receipt is issued only after the production writer completes against the real
DMAAP server with independent API and downstream observations. Legacy PKCS12
is fixture packaging only; no live certificate/authentication configuration is
changed. PostgreSQL is a fresh disposable database with no host storage.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import phase3_dmaap as dmaap

ROOT=Path(__file__).resolve().parents[1]
PG_IMAGE='docker.io/crunchydata/crunchy-postgres@sha256:b08f87fa2c422ba90a62fcfee725a7468697ce259975465cfd19249eccac23cf'
SOURCES=('bin/phase3_dmaap.py','bin/phase3-dmaap-client.py','bin/phase3-dmaap-rehearsal.py',
         'bin/phase3_preload.py','tools/Phase3DmaapFixture.py','tools/Phase3DmaapDownstreamFixture.py','tools/Phase3PreloadFixture.py')


def private_write(path,blob):
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as output:output.write(blob)


def run_adapter(directory):
    import ssl
    sys.path.insert(0,str(directory))
    import Phase3DmaapFixture as fixture
    from Phase3PreloadFixture import Server
    spec=importlib.util.spec_from_file_location('dmaap_client_adapter',directory/'phase3-dmaap-client.py')
    client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
    original_path,original_ssl=client.Path,client.ssl
    token=directory/'projected-token';private_write(token,b'synthetic-fixture-token')
    def mapped_path(path):
        if path!='/phase3-api/token':raise ValueError('Unexpected projected fixture access')
        return original_path(token)
    def mapped_context(cafile):
        if cafile!='/phase3-api/ca.crt':raise ValueError('Unexpected projected fixture trust')
        return original_ssl.create_default_context(cafile=str(directory/'root.cer'))
    client.Path=mapped_path
    client.ssl=SimpleNamespace(create_default_context=mapped_context,TLSVersion=ssl.TLSVersion)
    saved={k:os.environ.get(k) for k in ('KUBERNETES_SERVICE_HOST','KUBERNETES_SERVICE_PORT_HTTPS')}
    results={}
    try:
        for mode in ('success','execute','read-403','read-redirect','malformed','oversized','read-uid',
                     'write-500','write-redirect','write-uid','stale-rv','lost-commit'):
            state=fixture.KubeState(mode)
            with Server(state,directory/'server.cer',directory/'server.key') as port:
                os.environ['KUBERNETES_SERVICE_HOST']='localhost'
                os.environ['KUBERNETES_SERVICE_PORT_HTTPS']=str(port)
                journal=client.KubeJournal('fixture-journal');failed=False
                try:
                    if mode=='execute':
                        dmaap.execute(fixture.plan(),fixture.State(),journal,{'fixture':'exact-images'},'fixture-pod')
                    else:
                        old=journal.read()
                        if mode=='stale-rv':state.version+=1
                        journal.cas(old,dict(old,state='claimed'))
                        if mode=='success' and journal.read().get('state')!='claimed':raise ValueError('CAS readback differs')
                except Exception:
                    if mode in ('success','execute'):raise
                    failed=True
            counts={m:sum(x==m for x,p in state.requests) for m in ('GET','PUT')}
            if mode not in ('success','execute'):
                expected={'GET':1,'PUT':0 if mode in ('read-403','read-redirect','malformed','oversized','read-uid') else 1}
                if not failed or counts!=expected:raise ValueError('Journal fault accepted or retried')
            results[mode]={'passed':True,'rejected':failed,**counts}
        private_write(directory/'adapter.json',dmaap.canonical(results))
        return True
    finally:
        client.Path,client.ssl=original_path,original_ssl
        for k,v in saved.items():
            if v is None:os.environ.pop(k,None)
            else:os.environ[k]=v


def run_writer(directory):
    sys.path.insert(0,str(directory))
    import Phase3DmaapFixture as fixture
    run_adapter(directory)
    transport=dmaap.Transport(directory/'root.cer','127.0.0.1','fixture:synthetic-only',hostname='localhost')
    journal=fixture.Journal({'fixture':'exact-images'})
    # Retry only read-only startup probes; not a single application write is
    # retried. Any positive-control failure produces no qualification receipt.
    deadline=time.monotonic()+120
    while True:
        try:
            dmaap.audit_catalog(transport);break
        except (OSError,ValueError):
            if time.monotonic()>deadline:raise
            time.sleep(1)
    observations=[]
    real=transport.request
    def observed(method,path,data=None):
        code,body=real(method,path,data)
        observations.append({'method':method,'path':path,'code':code,'bytes':len(body)})
        fd=os.open(str(directory/'private-wire.jsonl'),os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
        with os.fdopen(fd,'a') as stream:
            stream.write(json.dumps({'method':method,'path':path,'code':code,'body':body.decode()},sort_keys=True)+'\n')
        return code,body
    transport.request=observed
    value=dmaap.execute(fixture.plan(),transport,journal,{'fixture':'exact-images'},'fixture-pod')
    dmaap.verify_values(fixture.plan(),transport)
    private_write(directory/'api-observations.json',json.dumps(observations,indent=2).encode())
    private_write(directory/'journal.json',dmaap.canonical(journal.record))
    if value.get('state')!='verified' or len([o for o in observations if o['method']=='POST'])!=6:
        raise ValueError('Exact DMAAP positive control did not qualify')
    downstream=[json.loads(l) for l in (directory/'downstream.jsonl').read_text().splitlines()]
    if (not downstream or not any(d['port']==18443 for d in downstream)
            or not any(d['port']==18080 for d in downstream)
            or any(not d['authorization_present'] for d in downstream)):
        raise ValueError('Exact downstream effects were not independently observed')
    result={'passed':True,'posts':6,'private_fields_and_relationships_verified':True,
            'clients_verified':len(dmaap.read(transport,'mr_clients')),
            'downstream_requests':len(downstream),'aaf_requests':sum(d['port']==18443 for d in downstream),
            'mr_requests':sum(d['port']==18080 for d in downstream)}
    private_write(directory/'runtime.json',dmaap.canonical(result))


def check(directory,docker):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from phase3_lab_pki import certificate, export_pkcs12, name
    root=Path(directory).resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False)
    created=[];names={};sequence=0
    def command(args,allow=False,timeout=90,data=None):
        nonlocal sequence
        sequence+=1
        p=subprocess.run(docker+args,input=data,capture_output=True,timeout=timeout)
        if p.returncode:
            private_write(root/('command-%04d.stderr'%sequence),p.stderr)
            if not allow:raise ValueError('Isolated DMAAP command failed; private diagnostics retained')
        return p
    def start(role,image,entry,args,extra=()):
        cname='phase3-dmaap-%d-%s'%(os.getpid(),role)
        network='none' if role=='control' else 'container:'+names['control']
        argv=['run','-d','--name',cname,'--network',network,*extra,'--entrypoint',entry,image,*args]
        command(argv);created.append(cname);names[role]=cname
        actual=json.loads(command(['inspect',cname]).stdout)[0]
        mode=actual['HostConfig']['NetworkMode']
        if ((role=='control' and mode!='none') or (role!='control' and not mode.startswith('container:'))
                or actual['HostConfig'].get('PortBindings') or actual['HostConfig'].get('Privileged')):
            raise ValueError('Isolated DMAAP network/privilege contract changed')
    try:
        for image in (dmaap.IMAGE,dmaap.STOCK_IMAGE,dmaap.SERVER_IMAGE,PG_IMAGE):
            command(['pull',image],timeout=600)
        for relative in SOURCES:
            private_write(root/Path(relative).name,(ROOT/relative).read_bytes())
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cakey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        ca=certificate(name('isolated DMAAP root'),cakey,name('isolated DMAAP root'),cakey,2,True,0)
        leaf=certificate(name('localhost'),key,ca.subject,cakey,1,sans=['localhost','dmaap-bc.onap'])
        private_write(root/'root.cer',ca.public_bytes(serialization.Encoding.PEM))
        private_write(root/'server.cer',leaf.public_bytes(serialization.Encoding.PEM))
        private_write(root/'server.key',key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
        private_write(root/'store-password',b'isolated-fixture-only')
        private_write(root/'server.p12',export_pkcs12(b'fixture',key,leaf,[ca],b'isolated-fixture-only',root/'store-password'))
        # Synthetic-only DB trust is confined to an unconnected loopback
        # namespace. There are no live credentials or retained data directories.
        properties='''HttpAllowed: false
IntHttpsPort: 8443
CertificateManagement: legacy
KeyStoreFile: /fixture/server.p12
KeyStoreType: PKCS12
KeyStorePassword: isolated-fixture-only
TrustStoreFile: /fixture/server.p12
TrustStoreType: PKCS12
TrustStorePassword: isolated-fixture-only
UsePGSQL: true
DB.host: 127.0.0.1
DB.name: fixture
DB.user: fixture
DB.cred: synthetic-only
DB.schema: public
UseAAF: true
aaf.URL: https://localhost:18443/proxy/
aaf.AdminUser: fixture
aaf.AdminPassword: synthetic-only
aaf.TopicMgrUser: fixture
aaf.TopicMgrPassword: synthetic-only
AafDecryption.Class: org.onap.dmaap.dbcapi.aaf.ClearDecrypt
ApiPermission.Class: org.onap.dmaap.dbcapi.authentication.AllowAll
MR.multisite: false
MR.topicStyle: FQTN_LEGACY_FORMAT
MR.CentralCname: localhost
MR.authentication: basicAuth
UnitTest: No
'''
        private_write(root/'dmaapbc.properties',properties.encode())
        private_write(root/'logback.xml',b'<configuration><appender name="out" class="ch.qos.logback.core.ConsoleAppender"><encoder><pattern>%msg%n</pattern></encoder></appender><root level="INFO"><appender-ref ref="out"/></root></configuration>')
        mount=['--user',str(os.getuid())+':'+str(os.getgid()),'--mount','type=bind,src='+str(root)+',dst=/fixture']
        start('control',dmaap.IMAGE,'python3',['/fixture/Phase3DmaapDownstreamFixture.py'],mount)
        deadline=time.monotonic()+30
        while not (root/'downstream-ready').exists():
            if time.monotonic()>deadline:raise ValueError('Synthetic downstream listener failed')
            time.sleep(.5)
        start('postgres',PG_IMAGE,'/bin/sh',['-c',
            '/usr/pgsql-13/bin/initdb -D /fixturedb -A trust -U fixture >/dev/null && exec /usr/pgsql-13/bin/postgres -D /fixturedb -c listen_addresses=127.0.0.1'],
            ['--user','26:26','--tmpfs','/fixturedb:rw,uid=26,gid=26,mode=0700'])
        deadline=time.monotonic()+60
        while command(['exec',names['postgres'],'/usr/pgsql-13/bin/pg_isready','-h','127.0.0.1','-U','fixture'],allow=True).returncode:
            if time.monotonic()>deadline:raise ValueError('Synthetic PostgreSQL did not start')
            time.sleep(1)
        command(['exec',names['postgres'],'/usr/pgsql-13/bin/createdb','-h','127.0.0.1','-U','fixture','fixture'])
        start('server',dmaap.SERVER_IMAGE,'java',['-DConfigFile=/fixture/dmaapbc.properties',
            '-Dlogback.configurationFile=/fixture/logback.xml','-jar','/opt/app/dmaapbc/lib/dmaap-bc.jar.jar'],mount)
        # Inspect the real stock script without running its unbounded writer.
        stock=command(['run','--rm','--network','none','--entrypoint','cat',dmaap.STOCK_IMAGE,
                       '/opt/app/dbc-client/bin/dbc-client']).stdout
        if hashlib.sha256(stock).hexdigest()!=dmaap.STOCK_SCRIPT_SHA256:
            raise ValueError('Exact stock client script changed')
        private_write(root/'stock-client-script',stock)
        p=command(['exec',names['control'],'python3','/fixture/phase3-dmaap-rehearsal.py','--worker','/fixture'],allow=True,timeout=240)
        private_write(root/'writer.stdout',p.stdout)
        if p.returncode:raise ValueError('Exact DMAAP qualification failed; no live change authorized')
        result={'schema':1,'passed':True,'contract':1,'synthetic_material_only':True,'live_api_contacted':False,
            'images':{'server':dmaap.SERVER_IMAGE,'stock_client':dmaap.STOCK_IMAGE,'client':dmaap.IMAGE,'postgres':PG_IMAGE},
            'network':'none; shared loopback only; no published ports',
            'fixture_differences':['synthetic AAF/MR','legacy PKCS12 server packaging','fresh loopback-only PostgreSQL trust'],
            'runtime':json.loads((root/'runtime.json').read_text()),
            'client_adapter_https_qualified':(root/'adapter.json').is_file(),
            'tested_sources_sha256':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in SOURCES}}
        private_write(root/'result.json',dmaap.canonical(result))
        return result
    finally:
        for cname in reversed(created):
            p=command(['logs',cname],allow=True)
            private_write(root/(cname+'.stdout'),p.stdout);private_write(root/(cname+'.stderr'),p.stderr)
            command(['rm','-f',cname],allow=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path)
    parser.add_argument('--worker',type=Path)
    args=parser.parse_args();os.umask(0o077)
    try:
        if args.worker:
            run_writer(args.worker)
        elif args.directory:
            check(args.directory,(['sudo'] if os.geteuid()!=0 else [])+['docker'])
            print('Isolated exact-image DMAAP qualification passed; no live API contacted')
        else:parser.error('--directory is required')
    except Exception:
        if args.worker:
            import traceback
            private_write(args.worker/'worker-error.txt',traceback.format_exc().encode())
        parser.exit(1,'DMAAP qualification stopped; private diagnostics retained; no live change authorized\n')
