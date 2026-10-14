#!/usr/bin/env python3
"""Helm post-renderer for narrowly scoped Kubernetes API compatibility."""
import sys
import json
from pathlib import Path
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parent))
from phase3_images import replacements

IMAGE_PINS = json.loads((Path(__file__).resolve().parents[1] / "runtime-image-pins.json").read_text())
IMAGE_PINS.update(replacements())

def pin_images(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "image" and isinstance(item, str):
                if item in IMAGE_PINS:
                    value[key] = IMAGE_PINS[item]
                elif item.endswith(":latest") or ("@" not in item and ":" not in item.rsplit("/", 1)[-1]):
                    raise ValueError("Unreviewed mutable image reference: " + item)
            else:
                pin_images(item)
    elif isinstance(value, list):
        for item in value:
            pin_images(item)

REMOVED_APIS = {
    "extensions/v1beta1", "apps/v1beta1", "apps/v1beta2", "policy/v1beta1",
    "batch/v1beta1", "apiextensions.k8s.io/v1beta1", "networking.k8s.io/v1beta1",
    "rbac.authorization.k8s.io/v1beta1", "admissionregistration.k8s.io/v1beta1",
    "autoscaling/v2beta1", "autoscaling/v2beta2",
}

def normalize(resources):
    result = []
    for resource in resources:
        if resource is None:
            continue
        if not isinstance(resource, dict):
            raise ValueError("Chart output contains a non-resource YAML document")
        api = resource.get("apiVersion")
        kind = resource.get("kind")
        if api == "policy/v1beta1" and kind == "PodDisruptionBudget":
            if not resource.get("spec", {}).get("selector"):
                raise ValueError("Cannot convert a PDB with an empty selector: v1 changes its meaning")
            resource["apiVersion"] = "policy/v1"
        elif api == "batch/v1beta1" and kind == "CronJob":
            resource["apiVersion"] = "batch/v1"
        elif api in REMOVED_APIS:
            raise ValueError("Unsupported removed API: %s %s" % (api, kind))
        pin_images(resource)
        result.append(resource)
    return result

if __name__ == "__main__":
    try:
        yaml.safe_dump_all(normalize(yaml.safe_load_all(sys.stdin)), sys.stdout, sort_keys=False)
    except (ValueError, yaml.YAMLError) as error:
        sys.exit("Chart API check failed: %s" % error)
