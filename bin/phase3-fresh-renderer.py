#!/usr/bin/env python3
"""Fail-closed post-renderer for the new experiment, not an in-place upgrade."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import yaml
from phase3_fresh import overlay

spec = importlib.util.spec_from_file_location('base_compat',Path(__file__).with_name('helm-api-compat.py'))
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)

if __name__ == '__main__':
    try:
        path = os.environ.get('PHASE3_FRESH_CONTEXT')
        if not path:
            raise ValueError('PHASE3_FRESH_CONTEXT is required; no stock fallback')
        context = json.loads(Path(path).read_text())
        yaml.safe_dump_all(overlay(compat.normalize(yaml.safe_load_all(sys.stdin)),context),sys.stdout,sort_keys=False)
    except (ValueError,KeyError,OSError,yaml.YAMLError) as error:
        sys.exit('Fresh compatibility gate failed: '+str(error))
