#!/usr/bin/env python3
"""Collect metadata and readiness without reading Kubernetes Secret contents."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SMO_NAMESPACES = {"onap", "nonrtric", "network", "strimzi-system"}
REQUIRED_RELEASES = {"onap", "onap-sdnc", "oran-nonrtric", "oran-simulator", "strimzi-kafka-operator"}

def command(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError("Command failed (%d): %s" % (result.returncode, " ".join(args)))
    return result.stdout

def assess(nodes, workloads, pods, pvcs, releases, services, kafkas=(), jobs=None):
    errors = []
    if len(nodes) != 3 or not all(n["ready"] for n in nodes):
        errors.append("Expected three Ready Kubernetes nodes")
    present = {w["namespace"] for w in workloads}
    if not SMO_NAMESPACES <= present:
        errors.append("Missing SMO/operator workload namespace")
    for workload in workloads:
        if workload["namespace"] in SMO_NAMESPACES and not workload["ready"]:
            errors.append("Workload is not ready: %s/%s" % (workload["namespace"], workload["name"]))
    for pod in pods:
        if pod["namespace"] in SMO_NAMESPACES and pod["phase"] != "Succeeded" and not pod["ready"]:
            errors.append("Pod is not ready: %s/%s" % (pod["namespace"], pod["name"]))
    live_namespaces = {p["namespace"] for p in pods if p["phase"] == "Running" and p["ready"]}
    for namespace in sorted(SMO_NAMESPACES - live_namespaces):
        errors.append("No Ready running pod in " + namespace)
    for pvc in pvcs:
        if pvc["namespace"] in SMO_NAMESPACES and pvc["phase"] != "Bound":
            errors.append("PVC is not Bound: %s/%s" % (pvc["namespace"], pvc["name"]))
    names = {r["name"] for r in releases if r.get("status") == "deployed"}
    for name in sorted(REQUIRED_RELEASES - names):
        errors.append("Required Helm release is not deployed: " + name)
    for release in releases:
        if release.get("namespace") in SMO_NAMESPACES and release.get("status") != "deployed":
            errors.append("Helm release is not deployed: " + release["name"])
    service_names = {(s["namespace"], s["name"]) for s in services}
    for name in ["sdnc-oam", "sdnc-web-service"]:
        if ("onap", name) not in service_names:
            errors.append("Required SDNC service is missing: " + name)
    expected_kafkas = [k for k in kafkas if k["namespace"] == "onap"]
    if not expected_kafkas:
        errors.append("Required ONAP Kafka resource is missing")
    for kafka in expected_kafkas:
        if not kafka["ready"] or kafka["observed_generation"] < kafka["generation"]:
            errors.append("Kafka is not reconciled and Ready: %s/%s" % (kafka["namespace"], kafka["name"]))
    if jobs is not None:
        if not any(j['namespace']=='onap' for j in jobs):errors.append('Required ONAP initialization Jobs are missing')
        for job in jobs:
            if job['namespace'] in SMO_NAMESPACES and not job['complete']:
                errors.append('Job is not Complete: %s/%s' % (job['namespace'],job['name']))
    return errors

def collect():
    raw_nodes = json.loads(command(["kubectl", "get", "nodes", "-o", "json"]))["items"]
    nodes = [{"name": n["metadata"]["name"],
              "ready": any(c["type"] == "Ready" and c["status"] == "True" for c in n.get("status", {}).get("conditions", [])),
              "versions": n.get("status", {}).get("nodeInfo", {})} for n in raw_nodes]
    raw_workloads = json.loads(command(["kubectl", "get", "deployments,statefulsets", "-A", "-o", "json"]))["items"]
    workloads = []
    for w in raw_workloads:
        desired = w.get("spec", {}).get("replicas", 1)
        status = w.get("status", {})
        workloads.append({"name": w["metadata"]["name"], "namespace": w["metadata"]["namespace"],
                          "kind": w["kind"], "desired": desired, "ready_replicas": status.get("readyReplicas", 0),
                          "ready": status.get("readyReplicas", 0) == desired and status.get("observedGeneration", 0) >= w["metadata"].get("generation", 1)})
    raw_pods = json.loads(command(["kubectl", "get", "pods", "-A", "-o", "json"]))["items"]
    pods = []
    for p in raw_pods:
        statuses = p.get("status", {}).get("containerStatuses", [])
        pods.append({"name": p["metadata"]["name"], "namespace": p["metadata"]["namespace"],
                     "phase": p.get("status", {}).get("phase"),
                     "ready": any(c["type"] == "Ready" and c["status"] == "True" for c in p.get("status", {}).get("conditions", [])),
                     "images": [{"name": c["name"], "reference": c.get("image"), "resolved_id": c.get("imageID"), "restarts": c.get("restartCount", 0)} for c in statuses]})
    raw_pvcs = json.loads(command(["kubectl", "get", "pvc", "-A", "-o", "json"]))["items"]
    pvcs = [{"name": p["metadata"]["name"], "namespace": p["metadata"]["namespace"],
             "phase": p.get("status", {}).get("phase"), "storage_class": p.get("spec", {}).get("storageClassName")} for p in raw_pvcs]
    raw_services = json.loads(command(["kubectl", "get", "services", "-A", "-o", "json"]))["items"]
    services = [{"name": s["metadata"]["name"], "namespace": s["metadata"]["namespace"],
                 "type": s["spec"]["type"], "ports": s["spec"].get("ports", [])} for s in raw_services]
    releases = json.loads(command(["helm", "list", "--all", "--all-namespaces", "-o", "json"]))
    raw_kafkas = json.loads(command(["kubectl", "get", "kafkas.kafka.strimzi.io", "-A", "-o", "json"]))["items"]
    raw_jobs=json.loads(command(['kubectl','get','jobs','-A','-o','json']))['items']
    jobs=[{'name':j['metadata']['name'],'namespace':j['metadata']['namespace'],'uid':j['metadata']['uid'],
           'complete':any(c['type']=='Complete' and c['status']=='True' for c in j.get('status',{}).get('conditions',[])),
           'failed':j.get('status',{}).get('failed',0),'suspended':j.get('spec',{}).get('suspend',False)} for j in raw_jobs]
    kafkas = [{"name": k["metadata"]["name"], "namespace": k["metadata"]["namespace"],
               "generation": k["metadata"].get("generation", 1),
               "observed_generation": k.get("status", {}).get("observedGeneration", 0),
               "ready": any(c["type"] == "Ready" and c["status"] == "True" for c in k.get("status", {}).get("conditions", [])),
               "kafka_version": k.get("spec", {}).get("kafka", {}).get("version")} for k in raw_kafkas]
    dependencies = {}
    for name, directory in {"it-dep": "/local/setup/phase3-smo/dep", "onap-oom": "/local/setup/phase3-smo/oom", "kubespray": "/local/setup/kubespray"}.items():
        if (Path(directory) / ".git").exists():
            dependencies[name] = {"commit": command(["git", "-C", directory, "rev-parse", "HEAD"]).strip(),
                                  "modified_paths": command(["git", "-C", directory, "diff", "--name-only"]).splitlines()}
    compatibility = {}
    for record in Path("/local/setup/phase3-smo/prepared").glob("*-changes.json"):
        compatibility[record.name] = json.loads(record.read_text())
    operator_compatibility = []
    for record in sorted(Path("/local/setup/phase3-smo/compatibility").glob("strimzi-*/version-override.json")):
        entry = json.loads(record.read_text())
        gate = record.parent / "operator-gate.json"
        entry["gate"] = json.loads(gate.read_text()) if gate.exists() else {"ready": False}
        operator_compatibility.append(entry)
    return {"collected_utc": datetime.now(timezone.utc).isoformat(),
            "profile_commit": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip(),
            "kubernetes": json.loads(command(["kubectl", "version", "-o", "json"])),
            "helm_version": command(["helm", "version", "--short"]).strip(),
            "nodes": nodes, "workloads": workloads, "pods": pods, "pvcs": pvcs,
            "helm_releases": releases, "services": services,
            "kafkas": kafkas, "jobs": jobs, "operator_compatibility": operator_compatibility,
            "source_dependencies": dependencies, "chart_compatibility": compatibility,
            "readiness_errors": assess(nodes, workloads, pods, pvcs, releases, services, kafkas, jobs)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="/local/setup/phase3-smo/provenance.json")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    try:
        data = collect()
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, "Provenance collection failed: %s\n" % error)
    print("Provenance: " + args.output)
    for error in data["readiness_errors"]:
        print(error)
    if args.require_ready and data["readiness_errors"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
