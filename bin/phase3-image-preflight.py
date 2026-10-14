#!/usr/bin/env python3
"""Audit images by default; --cache explicitly copies the five reviewed artifacts."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import yaml
from phase3_images import audit, cache, images_in
import phase3_images

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="append", required=True, help="Rendered YAML or live Kubernetes JSON")
    parser.add_argument("--output", required=True)
    parser.add_argument("--cache", action="store_true")
    args = parser.parse_args()
    destination = Path(args.output)
    if destination.exists():
        parser.error("Refusing to overwrite an audit/cache record")
    if args.cache:
        trace=destination.parent/(destination.stem+'-trace')
        trace.mkdir(mode=0o700)
        phase3_images.TRACE_DIRECTORY=trace
    images = set()
    for path in args.manifest:
        images.update(images_in(list(yaml.safe_load_all(Path(path).read_text()))))
    record = audit(images)
    record["recorded_utc"] = datetime.now(timezone.utc).isoformat()
    try:
        if not record["ready"]:
            raise ValueError("Image inventory has unavailable/ambiguous artifacts; no cache or deployment attempted")
        if args.cache:
            record["cache_receipts"] = cache()
    except (OSError, ValueError, RuntimeError) as error:
        record["ready"] = False
        record["failure"] = str(error)
    finally:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(record, indent=2) + "\n")
    print("Image audit %s; private record: %s" % ("passed" if record["ready"] else "failed", destination))
    raise SystemExit(0 if record["ready"] else 1)

if __name__ == "__main__":
    main()
