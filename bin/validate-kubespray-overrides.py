#!/usr/bin/env python3
"""Check the generated adapter output before the real Kubespray assertions."""
import argparse
from pathlib import Path
import yaml


def validate(text, selected):
    node = yaml.compose(text)
    if not isinstance(node, yaml.MappingNode):
        raise ValueError("Expected a YAML mapping of generated overrides")
    keys = [key.value for key, _ in node.value]
    if len(set(keys)) != len(keys):
        raise ValueError("Duplicate generated override keys")
    values = yaml.safe_load(text)
    if not selected:
        if "kube_version" in values:
            raise ValueError("Empty selection must omit kube_version")
        return None
    expected = selected[1:] if selected.startswith("v") else selected
    actual = values.get("kube_version")
    if not isinstance(actual, str) or actual != expected:
        raise ValueError("Generated kube_version differs from the normalized selected release")
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("overrides", type=Path)
    parser.add_argument("selected_version")
    args = parser.parse_args()
    try:
        version = validate(args.overrides.read_text(), args.selected_version)
        if version is not None:
            from ansible.plugins.test.core import version_compare
            # Test numeric parsing, not the supported-release minimum; Kubespray
            # retains its own unmodified minimum/checksum assertions below.
            if not version_compare(version, "0.0.0", ">="):
                raise ValueError("Ansible did not accept the normalized version format")
            print("Verified Kubespray kube_version format: " + version)
        else:
            print("No kube_version override; retaining the Kubespray default")
    except (OSError, ValueError, ImportError) as error:
        parser.exit(1, "Kubespray adapter validation failed: %s\n" % error)


if __name__ == "__main__":
    main()
