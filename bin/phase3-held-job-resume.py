#!/usr/bin/env python3
"""Audit by default; activate existing held Job UIDs only after exact dependencies pass."""
import time
from phase3_scoped_recovery import JOBS, dependencies_ready, execute, flow, one


def apply(session, approved):
    started = set()
    deadline = time.monotonic() + 3600
    while time.monotonic() < deadline:
        session.check()
        pods, workloads, jobs, states = session.inventory()
        active = [n for n, state in states.items() if state == 'active']
        if len(active) > 1 or any(n not in started for n in active):
            raise ValueError('Unreviewed concurrent/previous Job activation')
        session.result['completed'] = sorted(n for n, state in states.items() if state == 'complete')
        held = sorted(n for n, state in states.items() if state == 'held')
        eligible = [n for n in held if dependencies_ready(approved['bindings'][n], workloads, jobs, pods)]
        session.result['blocked'] = [n for n in held if n not in eligible]
        flow.store(session.work / ('progress-%s.json' % time.time_ns()), {'states': states, 'eligible': eligible})
        if not active and eligible:
            name = eligible[0]
            # Immediately recheck all protected identities and dependency states before unsuspension.
            session.check()
            pods, workloads, jobs, states = session.inventory()
            if states[name] != 'held' or not dependencies_ready(approved['bindings'][name], workloads, jobs, pods):
                raise ValueError('Job eligibility changed before activation')
            flow.activate_job(one(jobs, name))
            started.add(name)
            session.result['activated'] = sorted(started)
            print('Activated reviewed existing Job ' + name, flush=True)
        elif not active:
            session.result['status'] = 'blocked' if held else 'scoped-complete'
            return
        time.sleep(15)
    session.result['status'] = 'blocked'
    session.result['monitoring_timeout'] = True
    session.result['workloads_interrupted'] = False


if __name__ == '__main__':
    raise SystemExit(execute('jobs', apply, __doc__))
