#!/usr/bin/env python3
"""Read-only current operator/Job guard. Does not upgrade releases or delete Jobs."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from phase3_images import run
from phase3_recovery_guards import JOBS, PRESERVE_JOBS, job_guard, operator_health

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    path = Path(args.output)
    if path.exists():
        parser.error("Refusing to overwrite a guard record")
    def get(namespace, kind, name=None):
        argv = ["kubectl", "-n", namespace, "get", kind]
        if name:
            argv.append(name)
        return json.loads(run(argv + ["-o", "json", "--request-timeout=30s"]))
    record = {"recorded_utc": datetime.now(timezone.utc).isoformat(), "read_only": True,
              "ready_for_mutation": False, "failures": [], "jobs": []}
    deployment = get("strimzi-system", "deployment", "strimzi-cluster-operator")
    pods = get("strimzi-system", "pods")["items"]
    try:
        record["operator"] = operator_health(deployment, pods)
    except ValueError as error:
        record["failures"].append(str(error))
    jobs = get("onap", "jobs")["items"]
    pods = get("onap", "pods")["items"]
    for name in JOBS:
        selected = [j for j in jobs if j["metadata"]["name"] == name]
        try:
            if len(selected) != 1:
                raise ValueError("Expected Job is absent: " + name)
            record["jobs"].append(job_guard(selected[0], pods))
        except ValueError as error:
            record["failures"].append(name + ": " + str(error))
    record["excluded_jobs_preserved"] = sorted(j["metadata"]["name"] for j in jobs if j["metadata"]["name"] in PRESERVE_JOBS)
    extra_failed = [j["metadata"]["name"] for j in jobs if j["metadata"]["name"] not in set(JOBS) | PRESERVE_JOBS and
                    any(c["type"] == "Failed" and c["status"] == "True" for c in j.get("status", {}).get("conditions", []))]
    if extra_failed:
        record["failures"].append("Additional failed Jobs require review: " + ", ".join(sorted(extra_failed)))
    # This snapshot is not an authorization/receipt for an apply operation.
    record["current_prerequisites_pass"] = not record["failures"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n")
    print("Recovery guard %s; private record: %s" % ("passed" if not record["failures"] else "failed", path))
    raise SystemExit(1 if record["failures"] else 0)

if __name__ == "__main__":
    main()
