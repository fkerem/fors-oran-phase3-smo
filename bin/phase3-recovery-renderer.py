#!/usr/bin/env python3
"""Recovery-only renderer: exact image locks plus six held, single-attempt Jobs."""
import importlib.util
from pathlib import Path
import sys
import yaml
from phase3_recovery_guards import JOBS, held_job

ROOT = Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('base_renderer',ROOT/'helm-api-compat.py')
renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)

if __name__=='__main__':
    try:
        resources=renderer.normalize(yaml.safe_load_all(sys.stdin))
        output=[held_job(r) if r.get('kind')=='Job' and r.get('metadata',{}).get('name') in JOBS else r for r in resources]
        yaml.safe_dump_all(output,sys.stdout,sort_keys=False)
    except (ValueError,yaml.YAMLError) as error:
        sys.exit('Recovery rendering refused: '+str(error))
