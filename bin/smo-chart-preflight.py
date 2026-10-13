#!/usr/bin/env python3
"""Fetch only reviewed release archives; write a runtime provenance lock."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.parse
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHARTS = ("onap", "nonrtric", "ru-du-simulators")

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def select_charts(index, release_pin):
    selected = {}
    for name in CHARTS:
        pin = release_pin["charts"][name]
        entries = index.get("entries", {}).get(name, [])
        matches = [e for e in entries if str(e.get("version")) == pin["version"]]
        if len(matches) != 1:
            raise ValueError("Missing or ambiguous cached chart: %s %s" % (name, pin["version"]))
        entry = matches[0]
        urls = [urllib.parse.urljoin(release_pin["index_url"], u) for u in entry.get("urls", [])]
        if pin["url"] not in urls:
            raise ValueError("Cached chart URL changed: " + name)
        if entry.get("digest") and entry["digest"] != pin["sha256"]:
            raise ValueError("Index digest differs from reviewed pin: " + name)
        selected[name] = pin
    return selected

def verify_archive(blob, pin, name):
    if sha256(blob) != pin["sha256"]:
        raise ValueError("Archive SHA256 mismatch: " + name)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or member.isdev():
                raise ValueError("Unsafe archive member in " + name)

def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "POWDER-Phase3-Profile"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()

def prepare(release, cache_dir, output, pins_path=ROOT / "smo-chart-pins.json"):
    pins = json.loads(Path(pins_path).read_text())
    if release not in pins["releases"]:
        raise ValueError("Unsupported SMO release")
    release_pin = pins["releases"][release]
    index_blob = fetch(release_pin["index_url"])
    index = yaml.safe_load(index_blob)
    if not isinstance(index, dict):
        raise ValueError("Cached chart index is not a mapping")
    selected = select_charts(index, release_pin)
    selected["strimzi-kafka-operator"] = pins["strimzi"]
    directory = Path(cache_dir) / release
    directory.mkdir(parents=True, exist_ok=True)
    locked = {}
    for name, pin in selected.items():
        path = directory / (name + "-" + pin["version"] + ".tgz")
        blob = path.read_bytes() if path.exists() else fetch(pin["url"])
        verify_archive(blob, pin, name)
        if not path.exists():
            path.write_bytes(blob)
        locked[name] = dict(pin, path=str(path.resolve()))
    lock = {"release": release, "index_url": release_pin["index_url"],
            "index_sha256": sha256(index_blob), "dep_commit": release_pin["dep_commit"],
            "onap_plugin_commit": pins["onap_plugin_commit"], "charts": locked}
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(lock, indent=2) + "\n")
    return lock

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, choices=["g-release", "f-release"])
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        lock = prepare(args.release, args.cache_dir, args.output)
    except (OSError, ValueError, tarfile.TarError, yaml.YAMLError) as error:
        parser.exit(1, "SMO preflight failed: %s\n" % error)
    print("Verified %s cached SMO archives; lock: %s" % (lock["release"], args.output))

if __name__ == "__main__":
    main()
