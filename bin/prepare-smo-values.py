#!/usr/bin/env python3
"""Apply the profile's SMO overrides without discarding persistence values."""
import argparse
import copy
from pathlib import Path
import yaml

def merge(base, extra):
    result = copy.deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result

def fragments(release):
    if release not in ("g-release", "f-release"):
        raise ValueError("Unsupported SMO release")
    persistence = {"mountPath": "/storage/nfs/deployment-1"}
    onap = {"global": {"persistence": persistence}, "strimzi": {"enabled": True, "storageClassName": ""},
            "dmaap": {"message-router": {"message-router-zookeeper": {"persistence": persistence},
                                          "message-router-kafka": {"persistence": persistence}}}}
    nonrtric = {"global": {"persistence": persistence}, "nonrtric": {"persistence": persistence},
                "a1policymanagement": {"enabled": False, "rics": []}}
    if release == "g-release":
        nonrtric.update({"odu-app": {"image": {"repository": "nexus3.o-ran-sc.org:10002/o-ran-sc/nonrtric-rapp-ransliceassurance"}},
                        "odu-app-ics-version": {"image": {"repository": "nexus3.o-ran-sc.org:10002/o-ran-sc/nonrtric-rapp-ransliceassurance-icsversion"}}})
    simulators = {name: {"image": {"repository": "nexus3.o-ran-sc.org:10002/o-ran-sc", "name": image,
                                   "tag": "1.5.0", "pullPolicy": "IfNotPresent"}} for name, image in [
        ("ru-simulator", "nts-ng-o-ran-ru-fh"), ("du-simulator", "nts-ng-o-ran-du"),
        ("topology-server", "smo-nts-ng-topology-server")]}
    return {"onap-override.yaml": onap, "oran-override.yaml": nonrtric, "network-simulators-override.yaml": simulators}

def prepare(defaults, output, release):
    source = Path(defaults)
    target = Path(output)
    target.mkdir(parents=True, exist_ok=True)
    overrides = fragments(release)
    for name in ["onap-override.yaml", "oran-override.yaml", "network-simulators-override.yaml", "network-simulators-topology-override.yaml"]:
        data = yaml.safe_load((source / name).read_text())
        if not isinstance(data, dict):
            raise ValueError("Invalid override mapping: " + name)
        (target / name).write_text(yaml.safe_dump(merge(data, overrides.get(name, {})), sort_keys=False))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--defaults-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--release", required=True, choices=["g-release", "f-release"])
    args = parser.parse_args()
    try:
        prepare(args.defaults_dir, args.output_dir, args.release)
    except (OSError, ValueError, yaml.YAMLError) as error:
        parser.exit(1, "Override preparation failed: %s\n" % error)
