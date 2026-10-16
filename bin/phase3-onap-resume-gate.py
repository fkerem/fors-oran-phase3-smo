#!/usr/bin/env python3
"""Read-only ONAP/one-hour-operator gate before the explicit post-ONAP continuation."""
import argparse
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
from phase3_images import run
from phase3_recovery_guards import onap_ready

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('memory_compat',ROOT/'strimzi-version-compat.py')
compat=importlib.util.module_from_spec(spec);spec.loader.exec_module(compat)

def acceptance_record(directory):
    records=[]
    for path in Path(directory).glob('*/version-override.json'):
        record=json.loads(path.read_text())
        records.append((datetime.fromisoformat(record['recorded_utc']),path,record))
    if not records:raise ValueError('No operator compatibility record')
    _,path,record=max(records,key=lambda row:row[0])
    gate=path.parent/'operator-gate.json'
    data=json.loads(gate.read_text()) if gate.exists() else {}
    if record.get('operator_memory')!=compat.MEMORY or not data.get('ready') or data.get('stability_seconds',0)<3600:
        raise ValueError('Latest operator record has not passed the one-hour memory gate')
    return record,data

def check(directory='/local/setup/phase3-smo/compatibility', context_path='/local/setup/phase3-smo/fresh-start/context.json'):
    def get(kind,namespace=None):
        args=['kubectl']+(['-n',namespace] if namespace else [])+['get',kind,'-o','json','--request-timeout=30s']
        return json.loads(run(args))
    record,gate=acceptance_record(directory)
    deployment=get('deployment/strimzi-cluster-operator','strimzi-system')
    pods=get('pods','strimzi-system')['items']
    sample=compat.operator_sample(deployment,pods,record)
    baseline=gate['observations'][-1]
    if sample is None or any(sample[k]!=baseline[k] for k in sample):raise ValueError('Operator changed or lost readiness after acceptance')
    runtime=compat.runtime_sample(sample['pod']);compat.kafka_sample()
    resources=get('deployments,statefulsets,jobs,pvc','onap')['items']
    releases=json.loads(run(['helm','list','--all','-n','onap','-o','json']))
    preload_spec=importlib.util.spec_from_file_location('resume_sms_preload',ROOT/'phase3-sms-preload.py')
    preload_gate=importlib.util.module_from_spec(preload_spec);preload_spec.loader.exec_module(preload_gate)
    preload_verified=preload_gate.verify_acceptance(context_path) is not None
    dmaap_spec=importlib.util.spec_from_file_location('resume_dmaap',ROOT/'phase3-dmaap-recovery.py')
    dmaap_gate=importlib.util.module_from_spec(dmaap_spec);dmaap_spec.loader.exec_module(dmaap_gate)
    dmaap_acceptance=dmaap_gate.verify_acceptance(context_path)
    fresh_spec=importlib.util.spec_from_file_location('resume_fresh',ROOT/'phase3-fresh-start.py')
    fresh=importlib.util.module_from_spec(fresh_spec);fresh_spec.loader.exec_module(fresh)
    errors=fresh.onap_errors(resources, preload_verified=preload_verified,dmaap_acceptance=dmaap_acceptance)
    if errors:raise ValueError('ONAP continuation refused: '+errors[0])
    def items(kind):return [r for r in resources if r['kind']==kind]
    onap_ready(get('nodes')['items'],items('Deployment'),items('StatefulSet'),items('Job'),items('PersistentVolumeClaim'),get('kafkas.kafka.strimzi.io','onap')['items'],releases)
    backend_spec=importlib.util.spec_from_file_location('resume_sms_backend',ROOT/'phase3-sms-backend.py')
    backend_gate=importlib.util.module_from_spec(backend_spec);backend_spec.loader.exec_module(backend_gate)
    backend_gate.verify_acceptance(context_path)
    return {'ready':True,'operator':sample,'runtime':runtime,'operator_stability_seconds':gate['stability_seconds']}

if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True);args=parser.parse_args();output=Path(args.output)
    if output.exists():parser.error('Refusing to overwrite readiness evidence')
    try:record=check()
    except (OSError,ValueError,RuntimeError,KeyError) as error:record={'ready':False,'failure':str(error)}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(record,indent=2)+'\n')
    print('Post-ONAP continuation gate '+('passed' if record['ready'] else 'failed')+'; private record: '+args.output)
    raise SystemExit(0 if record['ready'] else 1)
