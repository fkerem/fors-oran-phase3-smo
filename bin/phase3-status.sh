#!/bin/bash
set -eo pipefail
SRC=$(cd -- "$(dirname -- "$0")/.." && pwd)
kubectl get nodes
kubectl get pods -A
kubectl get pvc -A
helm list --all --all-namespaces
python3 "$SRC/bin/collect-phase3-provenance.py" --require-ready
