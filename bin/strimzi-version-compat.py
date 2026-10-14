#!/usr/bin/env python3
"""Use Strimzi's built-in version override without falsifying the server version."""
import argparse
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


def prepare(source, expected, values_output, record_output):
    raw = Path(source).read_bytes()
    response = json.loads(raw, object_pairs_hook=unique_mapping)
    fields = version_fields(response, expected)
    override = "\n".join(key + "=" + fields[key] for key in FIELDS)
    values = {"extraEnvs": [{"name": "STRIMZI_KUBERNETES_VERSION", "value": override}]}
    rendered = yaml.safe_dump(values, sort_keys=False).encode()
    record = {"method": METHOD, "recorded_utc": utc(), "expected_version": "v" + expected.removeprefix("v"),
              "server_version_sha256": hashlib.sha256(raw).hexdigest(),
              "values_sha256": hashlib.sha256(rendered).hexdigest(),
              "reported_version": response, "override_fields": fields,
              "additional_fields_not_forwarded": sorted(set(response) - set(FIELDS)),
              "operator_image": IMAGE}
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
    if not container.get("imageID", "").endswith("@" + record["operator_image"].split("@", 1)[1]):
        raise ValueError("Running operator digest differs from the recorded stock image")
    return {"pod": pod["metadata"]["name"], "uid": pod["metadata"]["uid"],
            "restarts": container.get("restartCount", 0), "image_id": container["imageID"]}


def verify_log(log, record):
    if any(message in log for message in ("UnrecognizedPropertyException", "Failed to gather environment facts",
                                         "Detection of Kubernetes version failed")):
        raise ValueError("Operator logs still contain an environment-discovery failure")
    fields = record["override_fields"]
    version = fields["major"] + "." + fields["minor"]
    if not re.search(r"Environment facts gathered:.*KubernetesVersion=" + re.escape(version) + r"[,)]", log):
        raise ValueError("Operator has not reported the actual Kubernetes environment version")


def wait_operator(record, timeout=600, stability=240, poll=15):
    if record.get("method") != METHOD or record.get("operator_image") != IMAGE:
        raise ValueError("Compatibility record does not match the reviewed method/image")
    if version_fields(record["reported_version"], record["expected_version"]) != record["override_fields"]:
        raise ValueError("Compatibility record version fields are inconsistent")
    started = time.monotonic()
    stable_since = None
    baseline = None
    observations = []
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
            observations.append(dict(sample, collected_utc=utc(), log_sha256=hashlib.sha256(log.encode()).hexdigest()))
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
    wait = actions.add_parser("wait")
    wait.add_argument("--record", required=True)
    wait.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare(args.server_version_json, args.expected_version, args.values_output, args.record_output)
            print("Prepared Strimzi override from the actual server version")
        else:
            output = Path(args.output)
            if output.exists():
                raise ValueError("Refusing to overwrite an operator gate record")
            data = wait_operator(json.loads(Path(args.record).read_text()))
            output.write_text(json.dumps(data, indent=2) + "\n")
            output.chmod(0o600)
            print("Strimzi passed actual-version, image and four-minute stability checks")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, yaml.YAMLError) as error:
        parser.exit(1, "Strimzi compatibility check failed: %s\n" % error)


if __name__ == "__main__":
    main()
