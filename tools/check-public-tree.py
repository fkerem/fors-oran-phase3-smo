#!/usr/bin/env python3
"""Check the staged profile for operational material before publication."""
import json
from pathlib import PurePosixPath
import re
import subprocess

PATTERNS = {
    "private key material": r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|PKCS7)-----",
    "JWT-shaped credential": r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "GitHub credential": r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})",
    "historical VLAN join identifier": r"P2R7M4Q9N6X3K8V5D2A",
    "historical shared password": r"Kp8bJ4[A-Za-z0-9]{20,}",
    "subscriber identity fixture": r"\b(?:00101\d{10}|99999\d{10})\b",
}
FORBIDDEN_PARTS = {"private", "raw", "runs", "secrets", "__pycache__", ".venv"}
FORBIDDEN_SUFFIXES = {".key", ".pem", ".p12", ".pcap", ".pcapng", ".tgz", ".log"}

if __name__ == "__main__":
    paths = subprocess.check_output(["git", "ls-files", "-z"]).decode().split('\0')
    findings = []
    checked = 0
    for name in filter(None, paths):
        checked += 1
        path = PurePosixPath(name)
        if FORBIDDEN_PARTS.intersection(path.parts) or path.suffix in FORBIDDEN_SUFFIXES or path.name == ".DS_Store":
            findings.append({"path": name, "issue": "operational or generated file"})
        blob = subprocess.check_output(["git", "show", ":"+name]).decode("utf-8", errors="replace")
        # These patterns deliberately appear in this checker's own definitions.
        if name == "tools/check-public-tree.py":
            continue
        for label, pattern in PATTERNS.items():
            if re.search(pattern, blob):
                findings.append({"path": name, "issue": label})
    print(json.dumps({"staged_files": checked, "issues": findings}, indent=2))
    if findings:
        raise SystemExit(1)
