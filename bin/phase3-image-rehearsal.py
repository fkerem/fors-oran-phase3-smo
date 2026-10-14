#!/usr/bin/env python3
"""Isolated Docker rehearsal; synthetic credentials, owned temporary storage, no published ports."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid
import yaml
from phase3_images import load_lock, replacements

LABEL = "phase3.image-rehearsal"
TRACE=None
TRACE_COUNT=0
TRACE_REDACT=None

def call(args, env=None, timeout=120):
    global TRACE_COUNT
    result = subprocess.run(["sudo", "-E", "docker"] + args, env=env, text=True, capture_output=True, timeout=timeout)
    if TRACE is not None:
        TRACE_COUNT+=1
        prefix=TRACE/('docker-%04d'%TRACE_COUNT)
        prefix.with_suffix('.json').write_text(json.dumps({'argv':args,'returncode':result.returncode},indent=2)+'\n')
        # Contains no production credentials; synthetic env values are redacted even from inspect output.
        for suffix,body in (('.stdout',result.stdout),('.stderr',result.stderr)):
            if TRACE_REDACT:body=body.replace(TRACE_REDACT,'[synthetic credential redacted]')
            prefix.with_suffix(suffix).write_text(body)
    if result.returncode:
        raise RuntimeError("Isolated Docker operation failed: " + args[0])
    return result.stdout + result.stderr

def exporter_contract(documents):
    contracts=[]
    refs={"docker.io/bitnami/mysqld-exporter:0.12.1-debian-10-r264",replacements()["docker.io/bitnami/mysqld-exporter:0.12.1-debian-10-r264"]}
    for resource in documents:
        if not resource or resource.get('kind') not in ('StatefulSet','Deployment'):continue
        spec=resource['spec']['template']['spec']
        for container in spec.get('containers',[]):
            if container.get('image') not in refs:continue
            if spec.get('securityContext') != {'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001}:
                raise ValueError('Exporter Pod security contract differs from review')
            expected={'readOnlyRootFilesystem':True,'privileged':False,'allowPrivilegeEscalation':False}
            if container.get('securityContext') != expected:
                raise ValueError('Exporter container security contract differs from review')
            command=container.get('command',[])
            if len(command)!=3 or command[:2]!=['sh','-c'] or '/bin/mysqld_exporter' not in command[2] or 'DATA_SOURCE_NAME=' not in command[2]:
                raise ValueError('Unexpected exporter command')
            flags=[e for e in container.get('env',[]) if e['name']=='MARIADB_METRICS_EXTRA_FLAGS']
            if len(flags)!=1 or 'value' not in flags[0]:raise ValueError('Metrics flags require further review')
            for probe in ('livenessProbe','readinessProbe'):
                if container.get(probe,{}).get('httpGet',{}).get('path')!='/metrics':raise ValueError('Metrics probes changed')
            contracts.append({'command':command,'flags':flags[0]['value'],'security_context':expected,'uid':10001})
    if not contracts or any(c!=contracts[0] for c in contracts):raise ValueError('No unique retained exporter contract')
    return contracts[0]

def rehearsal(manifest, output):
    global TRACE,TRACE_REDACT,TRACE_COUNT
    os.umask(0o077)
    target=Path(output)
    if target.exists():raise ValueError('Refusing to overwrite rehearsal evidence')
    TRACE=target.parent/(target.stem+'-trace')
    TRACE.mkdir(mode=0o700)
    lock=load_lock(); contract=exporter_contract(list(yaml.safe_load_all(Path(manifest).read_text())))
    nonce=uuid.uuid4().hex[:12]; prefix='phase3-rehearsal-'+nonce
    environment=dict(os.environ,MARIADB_ROOT_PASSWORD=secrets.token_hex(24),MARIADB_ROOT_USER='root',MARIADB_METRICS_EXTRA_FLAGS=contract['flags'])
    TRACE_REDACT=environment['MARIADB_ROOT_PASSWORD'];TRACE_COUNT=0
    record={'started_utc':datetime.now(timezone.utc).isoformat(),'lock_sha256':hashlib.sha256((Path(__file__).resolve().parents[1]/'image-availability-lock.json').read_bytes()).hexdigest(),
            'manifest_sha256':hashlib.sha256(Path(manifest).read_bytes()).hexdigest(),'owner':nonce,'network':prefix,
            'containers':[],'volumes':[],'versions':[],'ready':False,'exporter_contract':contract,
            'production_secrets_or_volumes_used':False,'ports_published':False,'galera_cluster_bootstrap_validated':False}
    refs=replacements(lock)
    try:
        call(['network','create','--internal','--label',LABEL+'='+nonce,prefix])
        for i,item in enumerate(lock['images']):
            name=prefix+'-version-'+str(i);record['containers'].append(name)
            option='-v' if item['application_version']=='1.21.4' else '--version'
            command=item['binary_path']+' '+option
            if item.get('binary_sha256'):command+='; sha256sum '+item['binary_path']
            command+='; test "$(id -u)" -eq 10001'
            args=['run','--name',name,'--label',LABEL+'='+nonce,'--network','none','--read-only','--user','10001:10001',
                  '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--cpus','1',
                  '--tmpfs','/tmp:rw,size=64m,uid=10001,gid=10001','--entrypoint','/bin/sh']
            if item['application_version']=='7.9.3':
                args+=['--env','ES_JAVA_OPTS=-Xms16m -Xmx64m','--tmpfs','/opt/bitnami/elasticsearch/logs:rw,size=16m,uid=10001,gid=10001',
                       '--tmpfs','/opt/bitnami/elasticsearch/tmp:rw,size=64m,uid=10001,gid=10001']
            result=call(args+[refs[item['original']],'-ec',command])
            if item['application_version'] not in result:raise ValueError('Application version probe mismatch')
            if item.get('binary_sha256') and item['binary_sha256'] not in result:raise ValueError('Exporter binary hash mismatch')
            record['versions'].append({'original':item['original'],'image':refs[item['original']],'version':item['application_version'],
                                       'uid':10001,'stdout_sha256':hashlib.sha256(result.encode()).hexdigest()})
        database=prefix+'-database'; exporter=prefix+'-exporter'
        for suffix in ('data','conf','tmp','logs'):
            volume=prefix+'-'+suffix;call(['volume','create','--label',LABEL+'='+nonce,volume]);record['volumes'].append(volume)
        args=['create','--name',database,'--label',LABEL+'='+nonce,'--network',prefix,'--user','10001:10001','--memory','1g','--cpus','1',
              '--security-opt','no-new-privileges','--env','MARIADB_ROOT_PASSWORD','--env','MARIADB_ROOT_USER',
              '--mount','type=volume,source='+prefix+'-data,target=/bitnami/mariadb',
              '--mount','type=volume,source='+prefix+'-conf,target=/opt/bitnami/mariadb/conf',
              '--mount','type=volume,source='+prefix+'-tmp,target=/opt/bitnami/mariadb/tmp',
              '--mount','type=volume,source='+prefix+'-logs,target=/opt/bitnami/mariadb/logs',
              refs['docker.io/bitnami/mariadb:10.5.8']]
        call(args,environment);record['containers'].append(database)
        for volume in record['volumes']:
            info=json.loads(call(['volume','inspect',volume]))[0]
            expected='/var/lib/docker/volumes/'+volume+'/_data'
            if info.get('Labels',{}).get(LABEL)!=nonce or info['Mountpoint']!=expected:raise ValueError('Temporary volume identity mismatch')
            # Only brand-new, exact owned rehearsal volume paths; never a workspace/storage root.
            subprocess.run(['sudo','chown','-hR','10001:10001',expected],check=True,capture_output=True,timeout=30)
        call(['start',database])
        deadline=time.monotonic()+240
        while True:
            try:
                result=call(['exec',database,'bash','-ec','/opt/bitnami/mariadb/bin/mysql -uroot -p"$MARIADB_ROOT_PASSWORD" -N -e "SELECT 1"'],timeout=15)
                if not re.search(r'^1$',result,re.M):raise ValueError('Temporary database positive control failed')
                break
            except RuntimeError:
                if time.monotonic()>=deadline:raise ValueError('Temporary database did not become authenticated and Ready')
                time.sleep(3)
        record['containers'].append(exporter)
        call(['run','-d','--name',exporter,'--label',LABEL+'='+nonce,'--network','container:'+database,'--user','10001:10001',
              '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--cpus','1',
              '--env','MARIADB_ROOT_USER','--env','MARIADB_ROOT_PASSWORD','--env','MARIADB_METRICS_EXTRA_FLAGS',
              '--entrypoint',contract['command'][0],refs['docker.io/bitnami/mysqld-exporter:0.12.1-debian-10-r264']]+contract['command'][1:],environment)
        deadline=time.monotonic()+60
        while True:
            try:
                metrics=call(['exec',exporter,'sh','-c','wget -qO- http://127.0.0.1:9104/metrics'],timeout=15)
                if not re.search(r'^mysql_up 1$',metrics,re.M):raise RuntimeError('Authenticated scrape not yet healthy')
                break
            except RuntimeError:
                if time.monotonic()>=deadline:raise ValueError('Exporter /metrics and mysql_up=1 were not established')
                time.sleep(3)
        record.update(ready=True,metrics_sha256=hashlib.sha256(metrics.encode()).hexdigest(),mysql_up=1,
                      database_user=10001,exporter_user=10001,completed_utc=datetime.now(timezone.utc).isoformat())
        for name in record['containers']:
            info=json.loads(call(['inspect',name]))[0]
            if info.get('Config',{}).get('Labels',{}).get(LABEL)!=nonce or info.get('HostConfig',{}).get('PortBindings'):
                raise ValueError('Rehearsal resource ownership/port contract mismatch')
        # Remove only resources created by this successful rehearsal; failures retain diagnostics.
        for name in record['containers']:
            info=json.loads(call(['inspect',name]))[0]
            if info['State']['Running']:call(['stop','--time','15',name],timeout=30)
            call(['rm',name])
        for volume in record['volumes']:call(['volume','rm',volume])
        call(['network','rm',prefix]);record['owned_resources_cleaned']=True
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        record['ready']=False;record['failure']=str(error);record['owned_resources_cleaned']=False
        for name in record['containers']:
            try:call(['logs','--tail','100',name],environment,timeout=15)
            except (RuntimeError,subprocess.SubprocessError):pass
    finally:
        target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(record,indent=2)+'\n')
    return record

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    result=rehearsal(args.manifest,args.output)
    print('Isolated image/exporter rehearsal '+('passed' if result['ready'] else 'failed')+'; private record: '+args.output)
    raise SystemExit(0 if result['ready'] else 1)
