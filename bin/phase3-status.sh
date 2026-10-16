#!/bin/bash
set -eo pipefail
SRC=$(cd -- "$(dirname -- "$0")/.." && pwd)
kubectl get nodes
kubectl get pods -A
kubectl get pvc -A
helm list --all --all-namespaces
python3 - "$SRC" <<'PY'
import importlib.util,json,sys
from pathlib import Path
root=Path('/local/setup/phase3-smo/fresh-start')
for name in ('rehearsal.json','sms-backend-acceptance.json','sms-preload-acceptance.json','dmaap-acceptance.json','onap-acceptance.json'):
    path=root/name
    if path.is_file():
        record=json.loads(path.read_text())
        print('Fresh-start stored receipt %s: passed=%s; current bindings checked separately' % (name,record.get('passed')))
    else:
        print('Fresh-start %s: NOT ESTABLISHED' % name)
if (root/'sms-backend-acceptance.json').is_file():
    sys.path.insert(0,str(Path(sys.argv[1])/'bin'))
    spec=importlib.util.spec_from_file_location('status_sms_backend',Path(sys.argv[1])/'bin/phase3-sms-backend.py')
    gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
    try:
        if gate.verify_acceptance(root/'context.json') is None:
            raise ValueError('Receipt is not a qualified fresh context')
    except (ValueError,OSError,RuntimeError,KeyError):
        raise SystemExit('SMS backend current bindings: NOT ESTABLISHED; no readiness claim')
    print('SMS backend current bindings: VERIFIED; preload remains separate')
if (root/'context.json').is_file() and 'sms_preload_contract' in json.loads((root/'context.json').read_text()):
    sys.path.insert(0,str(Path(sys.argv[1])/'bin'))
    spec=importlib.util.spec_from_file_location('status_sms_preload',Path(sys.argv[1])/'bin/phase3-sms-preload.py')
    gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
    try:
        if gate.verify_acceptance(root/'context.json') is None:
            raise ValueError('Receipt is not a qualified fresh context')
    except (ValueError,OSError,RuntimeError,KeyError):
        raise SystemExit('SMS preload current verification: NOT ESTABLISHED; no readiness claim')
    print('SMS preload current verification: VERIFIED')
else:
    print('SMS preload: retained safety hold; no automatic preload authorization')
if (root/'context.json').is_file() and ('dmaap_contract' in json.loads((root/'context.json').read_text()) or (root/'dmaap-transition.json').exists()):
    sys.path.insert(0,str(Path(sys.argv[1])/'bin'))
    spec=importlib.util.spec_from_file_location('status_dmaap',Path(sys.argv[1])/'bin/phase3-dmaap-recovery.py')
    gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
    try:
        accepted=gate.verify_acceptance(root/'context.json')
        if accepted is None:raise ValueError('DMAAP receipt not accepted')
    except (ValueError,OSError,RuntimeError,KeyError):
        raise SystemExit('DMAAP current verification: NOT ESTABLISHED; no readiness claim')
    if accepted.get('acceptance_kind')=='completed-comparator-verification':
        print('DMAAP post-execution verification: VERIFIED; Job held, journal uncertain, no replay')
    else:
        print('DMAAP current verification: VERIFIED')
print('Application acceptance does not establish full SMO/certificate-test readiness')
PY
python3 "$SRC/bin/collect-phase3-provenance.py" --require-ready
