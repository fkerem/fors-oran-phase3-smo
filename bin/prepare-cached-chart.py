#!/usr/bin/env python3
"""Remove identical duplicate dependency rows from a reviewed cached chart."""
import argparse
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import yaml

def deduplicate_dependencies(chart):
    seen = {}
    dependencies = []
    removed = []
    for dependency in chart.get("dependencies", []):
        key = dependency.get("alias", dependency["name"])
        if key in seen:
            if seen[key] != dependency:
                raise ValueError("Conflicting duplicate dependency: " + key)
            removed.append(key)
        else:
            seen[key] = dependency
            dependencies.append(dependency)
    if removed:
        chart["dependencies"] = dependencies
    return chart, removed

def prepare_archive(blob, prefix=""):
    changes = []
    members = []
    changed_directories = set()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or member.isdev():
                raise ValueError("Unsafe chart archive member")
            content = archive.extractfile(member).read() if member.isfile() else None
            if member.isfile() and member.name.endswith("/Chart.yaml"):
                chart, removed = deduplicate_dependencies(yaml.safe_load(content))
                if removed:
                    content = yaml.safe_dump(chart, sort_keys=False).encode()
                    changed_directories.add(str(path.parent))
                    changes.append({"path": prefix+member.name, "removed_identical_dependencies": removed})
            elif member.isfile() and member.name.endswith(".tgz"):
                content, nested = prepare_archive(content, prefix+member.name+"!")
                changes.extend(nested)
            members.append((copy.copy(member), content))
    if not changes:
        return blob, []
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as archive:
            for member, content in members:
                path = PurePosixPath(member.name)
                if path.name == "Chart.lock" and str(path.parent) in changed_directories:
                    changes.append({"path": prefix+member.name, "removed_stale_lock": True})
                    continue
                if content is not None:
                    member.size = len(content)
                archive.addfile(member, io.BytesIO(content) if content is not None else None)
    return output.getvalue(), changes

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--record", required=True)
    args = parser.parse_args()
    try:
        blob = Path(args.archive).read_bytes()
        original_sha = hashlib.sha256(blob).hexdigest()
        if original_sha != args.sha256:
            raise ValueError("Input archive SHA256 differs from reviewed pin")
        prepared, changes = prepare_archive(blob)
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(prepared)
        record = {"original_sha256": original_sha, "prepared_sha256": hashlib.sha256(prepared).hexdigest(), "changes": changes}
        Path(args.record).write_text(json.dumps(record, indent=2) + "\n")
    except (OSError, ValueError, tarfile.TarError, yaml.YAMLError) as error:
        parser.exit(1, "Chart preparation failed: %s\n" % error)
    print("Prepared chart; compatibility changes: %d" % len(changes))

if __name__ == "__main__":
    main()
