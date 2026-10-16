#!/usr/bin/env python3
"""Execute the pinned stock readiness functions against synthetic API responses."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType,SimpleNamespace as Object
from unittest.mock import patch
import phase3_oru_readiness as policy

IMAGE=policy.IMAGE


def qualify(blob):
    if hashlib.sha256(blob).hexdigest()!=policy.SOURCE_SHA256:raise ValueError('Unknown readiness source')
    wrapper_path=Path(__file__).resolve().parents[1]/'bin/phase3-readiness-wrapper.py'
    spec=importlib.util.spec_from_file_location('qualified_wrapper',wrapper_path)
    wrapper=importlib.util.module_from_spec(spec);spec.loader.exec_module(wrapper)
    calls=[];denied=[False]
    class ApiException(Exception):pass
    class Core:
        def list_namespaced_pod(self,namespace,watch):
            calls.append(('list','pods',namespace,None))
            if denied[0]:raise ApiException('synthetic 403 Forbidden')
            return Object(items=[Object(status=Object(container_statuses=[Object(name='aaf-locate')]),
                metadata=Object(owner_references=[Object(kind='ReplicaSet',name='synthetic-rs')]))])
    class Apps:
        def read_namespaced_replica_set_status(self,name,namespace):
            calls.append(('get','replicasets/status',namespace,name))
            return Object(metadata=Object(owner_references=[Object(name='onap-aaf-locate')]))
        def read_namespaced_deployment(self,name,namespace):
            calls.append(('get','deployments',namespace,name))
            return Object(metadata=Object(generation=1),spec=Object(replicas=1),status=Object(
                unavailable_replicas=None,updated_replicas=1,replicas=1,ready_replicas=1,observed_generation=1))
    kubernetes=ModuleType('kubernetes');client=ModuleType('kubernetes.client');rest=ModuleType('kubernetes.client.rest')
    client.Configuration=lambda:Object();client.ApiClient=lambda value:value
    client.CoreV1Api=lambda value:Core();client.AppsV1Api=lambda value:Apps();client.BatchV1Api=lambda value:Object()
    client.rest=rest;rest.ApiException=ApiException;kubernetes.client=client
    with tempfile.TemporaryDirectory(prefix='oru-synthetic-') as directory:
        token=Path(directory)/'token';token.write_text('synthetic-credential-not-live')
        env={}
        for node in ast.walk(ast.parse(blob)):
            if isinstance(node,ast.Subscript) and isinstance(node.value,ast.Attribute) and node.value.attr=='environ':
                key=node.slice
                if isinstance(key,ast.Constant) and isinstance(key.value,str):env[key.value]=str(token)
        env.update(NAMESPACE='onap',TOKEN=str(token))
        with patch.dict(sys.modules,{'kubernetes':kubernetes,'kubernetes.client':client,'kubernetes.client.rest':rest}),patch.dict(os.environ,env):
            scope={'__name__':'qualified_import'}
            exec(compile(wrapper.patched_source(blob),'/app/ready.py','exec'),scope)
            assert scope['is_ready']('aaf-locate') is True
            positive=list(calls);calls.clear();denied[0]=True
            assert scope['is_ready']('aaf-locate') is False
            assert calls==[('list','pods','onap',None)]
    assert positive==[('list','pods','onap',None),('get','replicasets/status','onap','synthetic-rs'),
                      ('get','deployments','onap','onap-aaf-locate')]
    return {'schema':1,'passed':True,'source_sha256':policy.SOURCE_SHA256,'positive_api_calls':positive,
        'denied_read_control':True,'live_api_contacted':False,'synthetic_material_only':True,
        'fixture_difference':'Synthetic Kubernetes client responses; exact pinned helper functions and existing wrapper.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077)
    prefix=(['sudo'] if os.geteuid()!=0 else [])+['docker']
    source=subprocess.check_output(prefix+['run','--rm','--network','none','--entrypoint','cat',IMAGE,'/app/ready.py'])
    record=qualify(source)
    fd=os.open(str(args.output),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as output:json.dump(record,output,sort_keys=True)
    print('Pinned O-RU readiness synthetic positive/403 controls passed; no live API contacted')


if __name__=='__main__':main()
