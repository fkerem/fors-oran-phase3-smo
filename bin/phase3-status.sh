#!/bin/bash
set -eo pipefail
SRC=$(cd -- "$(dirname -- "$0")/.." && pwd)
kubectl get nodes
kubectl get pods -A
kubectl get pvc -A
helm list --all --all-namespaces
python3 - <<'PY'
import json
from pathlib import Path
root=Path('/local/setup/phase3-smo/fresh-start')
for name in ('rehearsal.json','onap-acceptance.json'):
    path=root/name
    if path.is_file():
        record=json.loads(path.read_text())
        print('Fresh-start %s: passed=%s; full SMO acceptance is separate' % (name,record.get('passed')))
    else:
        print('Fresh-start %s: NOT ESTABLISHED' % name)
PY
python3 "$SRC/bin/collect-phase3-provenance.py" --require-ready
