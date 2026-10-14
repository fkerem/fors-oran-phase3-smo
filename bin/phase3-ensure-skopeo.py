#!/usr/bin/env python3
"""Audit/install only the reviewed Skopeo package; refuse upgrades/removals."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from phase3_images import load_lock
TRACE_DIRECTORY=None

def package_plan_safe(text):
    if re.search(r'^Remv\s',text,re.M) or re.search(r'^Inst\s+\S+\s+\[',text,re.M):
        raise ValueError('APT plan would remove or upgrade an existing package')
    names=re.findall(r'^Inst\s+(\S+)',text,re.M)
    if 'skopeo' not in names:raise ValueError('APT plan does not install the requested tool')
    return names

def ensure(apply=False):
    pin=load_lock()['skopeo_package']
    installed=subprocess.run(['dpkg-query','-W','-f=${db:Status-Status}:${Version}','skopeo'],text=True,capture_output=True,timeout=20)
    if installed.returncode==0 and installed.stdout=='installed:'+pin:return {'ready':True,'version':pin,'packages_changed':[]}
    if installed.returncode==0 and installed.stdout.startswith('installed:'):raise ValueError('Unexpected installed Skopeo version; no upgrade allowed')
    if installed.returncode not in (0,1):raise ValueError('Cannot establish package state')
    if subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()!='amd64':raise ValueError('Unexpected host architecture')
    args=['apt-get','--no-install-recommends','--no-upgrade','install','skopeo='+pin]
    simulated=subprocess.run(args[:1]+['-s']+args[1:],text=True,capture_output=True,timeout=90)
    if TRACE_DIRECTORY is not None:
        (TRACE_DIRECTORY/'apt-plan.stdout').write_text(simulated.stdout)
        (TRACE_DIRECTORY/'apt-plan.stderr').write_text(simulated.stderr)
    if simulated.returncode:raise ValueError('Pinned package is unavailable; no substitution allowed')
    names=package_plan_safe(simulated.stdout)
    if apply:
        completed=subprocess.run(['sudo',args[0],'-y']+args[1:],text=True,capture_output=True,timeout=600)
        if TRACE_DIRECTORY is not None:
            (TRACE_DIRECTORY/'apt-install.stdout').write_text(completed.stdout)
            (TRACE_DIRECTORY/'apt-install.stderr').write_text(completed.stderr)
        if completed.returncode:raise RuntimeError('Pinned package installation failed')
        version=subprocess.check_output(['dpkg-query','-W','-f=${Version}','skopeo'],text=True).strip()
        if version!=pin:raise ValueError('Installed package differs from pin')
    return {'ready':apply,'version':pin,'planned_new_packages':names,'packages_changed':names if apply else [],'existing_packages_upgraded':False}

if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true');parser.add_argument('--output',required=True);args=parser.parse_args()
    output=Path(args.output)
    if output.exists():parser.error('Refusing to overwrite a package receipt')
    TRACE_DIRECTORY=output.parent/(output.stem+'-trace')
    TRACE_DIRECTORY.mkdir(mode=0o700)
    try:record=ensure(args.apply)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:record={'ready':False,'failure':str(error)}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(record,indent=2)+'\n')
    print('Pinned Skopeo check '+('passed' if record['ready'] else 'not applied or failed')+'; private record: '+args.output)
    raise SystemExit(0 if record['ready'] else 1)
