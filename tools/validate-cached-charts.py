#!/usr/bin/env python3
"""Offline integration check using the downloaded pins and dependency checkouts."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "bin" / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

cache = module("cache", "smo-chart-preflight.py")
prepare = module("prepare", "prepare-cached-chart.py")
values = module("values", "prepare-smo-values.py")
compat = module("compat", "helm-api-compat.py")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--dep-g", required=True)
    parser.add_argument("--dep-f", required=True)
    parser.add_argument("--helm", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    pins = json.loads((ROOT / "smo-chart-pins.json").read_text())
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for release, dependency in [("g-release", args.dep_g), ("f-release", args.dep_f)]:
        overrides = output / release / "values"
        values.prepare(Path(dependency) / "smo-install/helm-override/default", overrides, release)
        for name, pin in pins["releases"][release]["charts"].items():
            path = Path(args.artifacts) / (release + "-" + name + "-" + pin["version"] + ".tgz")
            blob = path.read_bytes()
            cache.verify_archive(blob, pin, name)
            prepared, changes = prepare.prepare_archive(blob)
            target = output / release / (name + ".tgz")
            target.write_bytes(prepared)
            extra = {"onap": ["onap-override.yaml"], "nonrtric": ["oran-override.yaml"],
                     "ru-du-simulators": ["network-simulators-override.yaml", "network-simulators-topology-override.yaml"]}[name]
            command = [args.helm, "template", "phase3-"+name, str(target), "--namespace", "phase3-preview", "--kube-version", "v1.34.3"]
            for file in extra:
                command.extend(["-f", str(overrides / file)])
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            docs = list(yaml.safe_load_all(result.stdout))
            normalized = compat.normalize(docs)
            if not normalized:
                raise ValueError("No resources rendered for " + name)
            (output / release / (name+".yaml")).write_text(yaml.safe_dump_all(normalized, sort_keys=False))
            results.append({"release": release, "chart": name, "original_sha256": pin["sha256"],
                            "prepared_sha256": hashlib.sha256(prepared).hexdigest(), "changes": changes,
                            "resources": len(normalized), "apis": dict(Counter(d["apiVersion"] for d in normalized))})
    pin = pins["strimzi"]
    archive = Path(args.artifacts) / "strimzi-0.29.0.tgz"
    cache.verify_archive(archive.read_bytes(), pin, "strimzi-kafka-operator")
    result = subprocess.run([args.helm, "template", "strimzi-kafka-operator", str(archive), "--namespace", "strimzi-system",
                             "--kube-version", "v1.34.3", "--include-crds"], capture_output=True, text=True, check=True)
    normalized = compat.normalize(yaml.safe_load_all(result.stdout))
    results.append({"release": "shared", "chart": "strimzi-kafka-operator", "original_sha256": pin["sha256"],
                    "resources": len(normalized), "apis": dict(Counter(d["apiVersion"] for d in normalized))})
    report = {"helm_version": subprocess.check_output([args.helm, "version", "--short"], text=True).strip(),
              "kubernetes_target": "v1.34.3", "chart_results": results, "live_cluster_tested": False}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
