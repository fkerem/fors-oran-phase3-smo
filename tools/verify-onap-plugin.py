#!/usr/bin/env python3
"""Rehearse failure handling in the actual pinned plugin with a fake Helm."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

PLUGIN = "kubernetes/helm/plugins/deploy/deploy.sh"

def run_function(script, directory):
    start = script.index("deploy_subchart() {")
    end = script.index("\n}\n", start) + 3
    function = script[start:end]
    settings = "\n".join([
        'SUBCHART_RELEASE=""', 'RELEASE="onap"', 'subchart="sdnc"',
        'LOG_DIR="'+directory+'"', 'CACHE_SUBCHART_DIR="'+directory+'"',
        'DEPLOY_FLAGS=""', 'GLOBAL_OVERRIDES=""', 'SUBCHART_OVERRIDES=""',
        'VERBOSE="false"', 'SET_LAST_APPLIED="false"', 'DELAY="false"',
        'helm() { return 7; }',
    ])
    return subprocess.run(["bash", "-c", settings + "\n" + function + "\ndeploy_subchart\n"], capture_output=True, text=True).returncode

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True)
    args = parser.parse_args()
    checkout = Path(args.checkout)
    original = subprocess.check_output(["git", "-C", str(checkout), "show", "HEAD:"+PLUGIN], text=True)
    patched = (checkout / PLUGIN).read_text()
    with tempfile.TemporaryDirectory() as directory:
        before = run_function(original, directory)
        after = run_function(patched, directory)
    if before != 0 or after != 7 or "set -o pipefail" not in patched:
        raise SystemExit("Pinned plugin failure rehearsal did not match expected behavior")
    print(json.dumps({"source_commit": subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip(),
                      "helm_failure_exit": 7, "original_plugin_exit": before, "patched_plugin_exit": after,
                      "live_helm_used": False}))
