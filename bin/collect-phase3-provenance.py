#!/usr/bin/env python3
"""Collect readiness metadata and verify current preload acceptance privately."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from phase3_stateful_readiness import errors as stateful_errors

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

def collect(context_path='/local/setup/phase3-smo/fresh-start/context.json'):
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
    errors = assess(nodes, workloads, pods, pvcs, releases, services, kafkas, jobs)
    stateful_readiness_errors = stateful_errors(raw_workloads, raw_pods, raw_kafkas)
    errors.extend(stateful_readiness_errors)
    oru_current=None
    if Path(context_path).is_file() and json.loads(Path(context_path).read_text()).get('oru_readiness_contract')==1:
        result=subprocess.run(['python3',str(ROOT/'tools/phase3-oru-readiness.py'),'verify-fresh',
            '--context',str(context_path),'--expected-slice',json.loads(Path(context_path).read_text())['slice_urn']],
            capture_output=True,timeout=180)
        oru_current={'verified':result.returncode==0}
        if result.returncode:errors.append('O-RU readiness current identity/RBAC verification is not established')
    kong_proxy_current = None
    try:
        if Path(context_path).is_file():
            context = json.loads(Path(context_path).read_text())
            if 'kong_proxy_contract' in context:
                if type(context['kong_proxy_contract']) is not int or context['kong_proxy_contract'] != 1:
                    raise ValueError('Unreviewed Kong proxy contract')
                result = subprocess.run(['python3', str(ROOT/'tools/phase3-kong-proxy.py'), 'verify-fresh',
                    '--context', str(context_path), '--expected-slice', context['slice_urn']],
                    capture_output=True, timeout=180)
                if result.returncode:
                    raise ValueError('Kong proxy verification failed')
                kong_proxy_current = {'verified': True}
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired):
        kong_proxy_current = {'verified': False}
        errors.append('Kong proxy current verification is not established')
    preload_verified = False
    preload_current = None
    dmaap_acceptance = None
    dmaap_current = None
    try:
        if Path(context_path).is_file():
            context = json.loads(Path(context_path).read_text())
            if 'sms_preload_contract' in context:
                spec = importlib.util.spec_from_file_location('provenance_sms_preload', ROOT/'bin/phase3-sms-preload.py')
                gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
                if gate.verify_acceptance(context_path) is None:
                    raise ValueError('Qualified fresh preload acceptance missing')
                preload_verified = True
                preload_current = {'verified': True}
    except (OSError, ValueError, RuntimeError, KeyError):
        preload_current = {'verified': False}
        errors.append('SMS preload current verification is not established')
    try:
        if Path(context_path).is_file():
            context=json.loads(Path(context_path).read_text())
            if context.get('dmaap_contract')==1 or (Path(context_path).parent/'dmaap-transition.json').exists():
                spec=importlib.util.spec_from_file_location('provenance_dmaap',ROOT/'bin/phase3-dmaap-recovery.py')
                gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
                dmaap_acceptance=gate.verify_acceptance(context_path)
                if dmaap_acceptance is None:raise ValueError('DMAAP acceptance missing')
                dmaap_current={'verified':True,**dmaap_acceptance}
    except (OSError,ValueError,RuntimeError,KeyError):
        dmaap_current={'verified':False};errors.append('DMAAP current verification is not established')
    onap = [r for r in raw_workloads+raw_jobs if r['metadata'].get('namespace') == 'onap']
    if any(r['kind'] == 'Job' and r['metadata']['name'] == 'onap-aaf-sms-preload' for r in onap):
        spec = importlib.util.spec_from_file_location('provenance_fresh', ROOT/'bin/phase3-fresh-start.py')
        fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
        try:
            errors.extend(fresh.onap_errors(onap, preload_verified=preload_verified,dmaap_acceptance=dmaap_acceptance))
        except (ValueError, RuntimeError, KeyError):
            errors.append('SMS preload/ONAP Job acceptance is not established')
    return {"collected_utc": datetime.now(timezone.utc).isoformat(),
            "profile_commit": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip(),
            "kubernetes": json.loads(command(["kubectl", "version", "-o", "json"])),
            "helm_version": command(["helm", "version", "--short"]).strip(),
            "nodes": nodes, "workloads": workloads, "pods": pods, "pvcs": pvcs,
            "helm_releases": releases, "services": services,
            "kafkas": kafkas, "jobs": jobs, "operator_compatibility": operator_compatibility,
            "sms_preload_current": preload_current,
            "dmaap_current":dmaap_current,
            "oru_readiness_current":oru_current,
            "kong_proxy_current": kong_proxy_current,
            "source_dependencies": dependencies, "chart_compatibility": compatibility,
            "statefulset_readiness": {"verified": not stateful_readiness_errors},
            "readiness_errors": errors}

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
