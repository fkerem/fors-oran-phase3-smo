#!/usr/bin/env python3
"""Use Strimzi's built-in version override without falsifying the server version."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("major", "minor", "gitVersion", "gitCommit", "gitTreeState",
          "buildDate", "goVersion", "compiler", "platform")
IMAGE_TAG = "quay.io/strimzi/operator:0.29.0"
IMAGE = json.loads((ROOT / "runtime-image-pins.json").read_text())[IMAGE_TAG]
METHOD = "strimzi-0.29.0-built-in-version-override"
MEMORY = {"java_opts": "-Xms256m -Xmx512m", "initial_heap_bytes": 268435456,
          "maximum_heap_bytes": 536870912, "container_memory": "1Gi",
          "container_limit_bytes": 1073741824, "required_stability_seconds": 3600}
CONFLICTING_ENV = {"JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"}


def utc():
    return datetime.now(timezone.utc).isoformat()


def unique_mapping(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field: " + key)
        result[key] = value
    return result


def version_fields(response, expected):
    selected = expected.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", selected):
        raise ValueError("Invalid selected Kubernetes version")
    if not isinstance(response, dict):
        raise ValueError("Server version must be a JSON object")
    fields = {}
    for key in FIELDS:
        value = response.get(key)
        if not isinstance(value, str) or not value or re.search(r"[\s,=]", value):
            raise ValueError("Missing or malformed server version field: " + key)
        fields[key] = value
    major, minor = selected.split(".")[:2]
    if fields["major"] != major or fields["minor"] != minor or fields["gitVersion"] != "v" + selected:
        raise ValueError("Server version differs from the selected Kubernetes release")
    for name, key in (("emulationMajor", "major"), ("emulationMinor", "minor")):
        if name in response and response[name] != fields[key]:
            raise ValueError("Server emulation version differs from its actual version")
    return fields


def merge_env(existing, override):
    if not isinstance(existing, list) or any(not isinstance(e, dict) or not isinstance(e.get("name"), str) for e in existing):
        raise ValueError("Malformed extraEnvs")
    names = [e["name"] for e in existing]
    if len(names) != len(set(names)) or CONFLICTING_ENV & set(names):
        raise ValueError("Duplicate or conflicting JVM environment setting")
    for env in existing:
        if env["name"] == "JAVA_OPTS" and env.get("value") != MEMORY["java_opts"]:
            raise ValueError("Existing JAVA_OPTS differs from the reviewed heap-only setting")
        if env["name"] == "STRIMZI_KUBERNETES_VERSION" and env.get("value") != override:
            raise ValueError("Existing version override differs from the actual server")
    result = copy.deepcopy([e for e in existing if e["name"] not in {"JAVA_OPTS", "STRIMZI_KUBERNETES_VERSION"}])
    return result + [{"name": "STRIMZI_KUBERNETES_VERSION", "value": override},
                     {"name": "JAVA_OPTS", "value": MEMORY["java_opts"]}]


def prepare(source, expected, values_output, record_output, existing_values=None):
    raw = Path(source).read_bytes()
    response = json.loads(raw, object_pairs_hook=unique_mapping)
    fields = version_fields(response, expected)
    override = "\n".join(key + "=" + fields[key] for key in FIELDS)
    existing = yaml.safe_load(Path(existing_values).read_text()) if existing_values else {}
    if not isinstance(existing, dict):
        raise ValueError("Existing Helm values are not a mapping")
    values = {"extraEnvs": merge_env(existing.get("extraEnvs", []), override)}
    rendered = yaml.safe_dump(values, sort_keys=False).encode()
    record = {"method": METHOD, "recorded_utc": utc(), "expected_version": "v" + expected.removeprefix("v"),
              "server_version_sha256": hashlib.sha256(raw).hexdigest(),
              "values_sha256": hashlib.sha256(rendered).hexdigest(),
              "reported_version": response, "override_fields": fields,
              "additional_fields_not_forwarded": sorted(set(response) - set(FIELDS)),
              "operator_image": IMAGE, "operator_memory": MEMORY,
              "existing_values_sha256": hashlib.sha256(Path(existing_values).read_bytes()).hexdigest() if existing_values else None}
    outputs = ((values_output, rendered), (record_output, (json.dumps(record, indent=2) + "\n").encode()))
    if Path(values_output).resolve() == Path(record_output).resolve() or any(Path(p).exists() for p, _ in outputs):
        raise ValueError("Refusing to overwrite a compatibility record")
    for destination, content in outputs:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o600)
    return record


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError("Command failed (%d): %s" % (result.returncode, " ".join(args)))
    return result.stdout


def operator_sample(deployment, pods, record):
    containers = deployment["spec"]["template"]["spec"]["containers"]
    if len(containers) != 1 or containers[0]["image"] != record["operator_image"]:
        raise ValueError("Operator image or container layout differs from the reviewed pin")
    expected_env = "\n".join(key + "=" + record["override_fields"][key] for key in FIELDS)
    env = [e for e in containers[0].get("env", []) if e["name"] == "STRIMZI_KUBERNETES_VERSION"]
    if len(env) != 1 or env[0].get("value") != expected_env:
        raise ValueError("Operator version override differs from the captured server version")
    if "operator_memory" in record:
        if record["operator_memory"] != MEMORY:
            raise ValueError("Unreviewed operator memory configuration")
        names = [e["name"] for e in containers[0].get("env", [])]
        opts = [e for e in containers[0].get("env", []) if e["name"] == "JAVA_OPTS"]
        if len(names) != len(set(names)) or CONFLICTING_ENV & set(names) or len(opts) != 1 or opts[0].get("value") != MEMORY["java_opts"]:
            raise ValueError("Operator JVM environment differs from the reviewed heap cap")
        resources = containers[0].get("resources", {})
        if any(resources.get(k, {}).get("memory") != MEMORY["container_memory"] for k in ("requests", "limits")):
            raise ValueError("Operator memory resources changed from the retained 1Gi baseline")
    status = deployment.get("status", {})
    if status.get("observedGeneration", 0) < deployment["metadata"]["generation"] or any(
            status.get(key, 0) != 1 for key in ("readyReplicas", "updatedReplicas", "availableReplicas")):
        return None
    live = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
    if len(live) != 1:
        return None
    pod = live[0]
    if pod.get("status", {}).get("phase") != "Running" or not any(
            c["type"] == "Ready" and c["status"] == "True" for c in pod["status"].get("conditions", [])):
        return None
    pod_containers = pod["spec"]["containers"]
    if len(pod_containers) != 1 or pod_containers[0] != containers[0]:
        # API defaulting can add unrelated pod container fields. Compare only the relevant fields.
        if len(pod_containers) != 1 or any(pod_containers[0].get(k) != containers[0].get(k) for k in ("name", "image", "env")):
            raise ValueError("Ready operator pod does not match the reviewed deployment")
    statuses = [c for c in pod["status"].get("containerStatuses", []) if c["name"] == containers[0]["name"]]
    if len(statuses) != 1 or not statuses[0].get("ready"):
        return None
    container = statuses[0]
    if "operator_memory" in record and container.get("lastState", {}).get("terminated", {}).get("reason") == "OOMKilled":
        raise ValueError("Operator was OOMKilled during heap-only recovery")
    if not container.get("imageID", "").endswith("@" + record["operator_image"].split("@", 1)[1]):
        raise ValueError("Running operator digest differs from the recorded stock image")
    return {"pod": pod["metadata"]["name"], "uid": pod["metadata"]["uid"],
            "restarts": container.get("restartCount", 0), "image_id": container["imageID"]}


def verify_log(log, record):
    if any(message in log for message in ("UnrecognizedPropertyException", "Failed to gather environment facts",
                                         "Detection of Kubernetes version failed")):
        raise ValueError("Operator logs still contain an environment-discovery failure")
    if "operator_memory" in record and any(message in log for message in ("OutOfMemoryError", "Java heap space", "GC overhead limit exceeded")):
        raise ValueError("Operator logs contain a JVM memory failure")
    fields = record["override_fields"]
    version = fields["major"] + "." + fields["minor"]
    if not re.search(r"Environment facts gathered:.*KubernetesVersion=" + re.escape(version) + r"[,)]", log):
        raise ValueError("Operator has not reported the actual Kubernetes environment version")


def parse_runtime(raw):
    argv, tail = raw.split("\nLIMIT\n", 1)
    limit, tail = tail.split("\nCURRENT\n", 1)
    current, events = tail.split("\nEVENTS\n", 1)
    args = argv.split("\0")
    if args.count("-Xms256m") != 1 or args.count("-Xmx512m") != 1:
        raise ValueError("Running JVM does not have the reviewed heap bounds")
    if any(a.startswith(("-Xms", "-Xmx", "-XX:MaxHeapSize", "-XX:InitialHeapSize")) and
           a not in ("-Xms256m", "-Xmx512m") for a in args):
        raise ValueError("Running JVM contains conflicting heap bounds")
    if args.count("io.strimzi.operator.cluster.Main") != 1:
        raise ValueError("Runtime probe did not inspect the Cluster Operator JVM")
    event_counts = {k: int(v) for k, v in (line.split() for line in events.strip().splitlines())}
    if int(limit.strip()) != MEMORY["container_limit_bytes"]:
        raise ValueError("Runtime cgroup memory limit differs from the retained 1Gi baseline")
    if event_counts.get("oom", 0) or event_counts.get("oom_kill", 0):
        raise ValueError("Operator cgroup reports an OOM event")
    return {"memory_current_bytes": int(current.strip()), "memory_limit_bytes": int(limit.strip()),
            "memory_events": event_counts, "jvm_argv_sha256": hashlib.sha256(argv.encode()).hexdigest(),
            "verified_heap_initial_bytes": MEMORY["initial_heap_bytes"],
            "verified_heap_maximum_bytes": MEMORY["maximum_heap_bytes"]}


def runtime_sample(pod):
    script = r'''set -e
count=0
for entry in /proc/[0-9]*/comm; do
    read -r name < "$entry" || continue
    if [ "$name" = java ]; then
        count=$((count + 1)); pid=${entry#/proc/}; pid=${pid%/comm}
        cat "/proc/$pid/cmdline"
    fi
done
[ "$count" -eq 1 ]
printf '\nLIMIT\n'; cat /sys/fs/cgroup/memory.max
printf '\nCURRENT\n'; cat /sys/fs/cgroup/memory.current
printf '\nEVENTS\n'; cat /sys/fs/cgroup/memory.events
'''
    return parse_runtime(command(["kubectl", "-n", "strimzi-system", "exec", pod, "--", "bash", "-c", script]))


def kafka_sample():
    items = json.loads(command(["kubectl", "-n", "onap", "get", "kafkas.kafka.strimzi.io", "-o", "json", "--request-timeout=30s"]))["items"]
    if not items or any(k.get("status", {}).get("observedGeneration", 0) < k["metadata"].get("generation", 1) or not any(
            c["type"] == "Ready" and c["status"] == "True" for c in k.get("status", {}).get("conditions", [])) for k in items):
        raise ValueError("ONAP Kafka is not reconciled and Ready during operator recovery")
    return [{"name": k["metadata"]["name"], "uid": k["metadata"]["uid"], "generation": k["metadata"].get("generation", 1)} for k in items]


def wait_operator(record, timeout=600, stability=240, poll=15, require_kafka=False, observe=None):
    if record.get("method") != METHOD or record.get("operator_image") != IMAGE:
        raise ValueError("Compatibility record does not match the reviewed method/image")
    if version_fields(record["reported_version"], record["expected_version"]) != record["override_fields"]:
        raise ValueError("Compatibility record version fields are inconsistent")
    if "operator_memory" in record and (record["operator_memory"] != MEMORY or stability < MEMORY["required_stability_seconds"]):
        raise ValueError("Heap-only recovery requires its full one-hour stability gate")
    started = time.monotonic()
    stable_since = None
    baseline = None
    observations = []
    pressure_samples = 0
    kafka_baseline = None
    while time.monotonic() - started <= timeout:
        deployment = json.loads(command(["kubectl", "-n", "strimzi-system", "get", "deployment",
                                         "strimzi-cluster-operator", "-o", "json", "--request-timeout=30s"]))
        pods = json.loads(command(["kubectl", "-n", "strimzi-system", "get", "pods", "-l",
                                  "name=strimzi-cluster-operator", "-o", "json", "--request-timeout=30s"]))["items"]
        sample = operator_sample(deployment, pods, record)
        if sample is not None:
            log = command(["kubectl", "-n", "strimzi-system", "logs", sample["pod"], "--timestamps"])
            verify_log(log, record)
            if baseline is None:
                baseline, stable_since = sample, time.monotonic()
            elif sample != baseline:
                raise ValueError("Operator restarted or changed identity during its stability gate")
            runtime = runtime_sample(sample["pod"]) if "operator_memory" in record else {}
            pressure_samples = pressure_samples + 1 if runtime.get("memory_current_bytes", 0) >= MEMORY["container_limit_bytes"] * 0.9 else 0
            if pressure_samples >= 3:
                raise ValueError("Operator memory exceeded 90 percent for three consecutive samples")
            kafka = kafka_sample() if require_kafka else []
            if require_kafka:
                if kafka_baseline is None: kafka_baseline = kafka
                elif kafka != kafka_baseline: raise ValueError("Kafka identity/generation changed during stability gate")
            observations.append(dict(sample, collected_utc=utc(), log_sha256=hashlib.sha256(log.encode()).hexdigest(), **runtime, kafkas=kafka))
            if observe is not None: observe(observations[-1])
            if len(observations) % 4 == 0:
                print("Operator stable for %d seconds; memory %d MiB" % (time.monotonic() - stable_since,
                      runtime.get("memory_current_bytes", 0) // 1048576), flush=True)
            if time.monotonic() - stable_since >= stability:
                return {"ready": True, "method": METHOD, "stability_seconds": stability,
                        "completed_utc": utc(), "observations": observations}
        elif baseline is not None:
            raise ValueError("Operator lost readiness during its stability gate")
        time.sleep(poll)
    raise ValueError("Operator did not pass its bounded readiness/stability gate")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    generate = actions.add_parser("prepare")
    generate.add_argument("--server-version-json", required=True)
    generate.add_argument("--expected-version", required=True)
    generate.add_argument("--values-output", required=True)
    generate.add_argument("--record-output", required=True)
    generate.add_argument("--existing-values", help="Retained Helm values; unrelated extraEnvs are preserved")
    wait = actions.add_parser("wait")
    wait.add_argument("--record", required=True)
    wait.add_argument("--output", required=True)
    wait.add_argument("--require-onap-kafka", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare(args.server_version_json, args.expected_version, args.values_output, args.record_output, args.existing_values)
            print("Prepared Strimzi override from the actual server version")
        else:
            output = Path(args.output)
            if output.exists():
                raise ValueError("Refusing to overwrite an operator gate record")
            record = json.loads(Path(args.record).read_text())
            if record.get("operator_memory") != MEMORY:
                raise ValueError("Current acceptance requires a reviewed memory record, not a historical four-minute receipt")
            samples = output.with_suffix(".samples.jsonl")
            if samples.exists(): raise ValueError("Refusing to overwrite operator samples")
            def observe(sample):
                with samples.open("a") as stream:
                    stream.write(json.dumps(sample) + "\n")
            try:
                data = wait_operator(record, timeout=4500, stability=3600, require_kafka=args.require_onap_kafka, observe=observe)
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                output.write_text(json.dumps({"ready": False, "failed_utc": utc(), "error": str(error)}, indent=2) + "\n")
                output.chmod(0o600)
                raise
            output.write_text(json.dumps(data, indent=2) + "\n")
            output.chmod(0o600)
            print("Strimzi passed actual-version, stock-image, heap-cap and one-hour stability checks")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, yaml.YAMLError) as error:
        parser.exit(1, "Strimzi compatibility check failed: %s\n" % error)


if __name__ == "__main__":
    main()
