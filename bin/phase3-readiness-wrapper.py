#!/usr/bin/env python3
"""Apply one reviewed predicate correction to the otherwise unchanged helper."""
# Predicate derived from ONAP OOM readiness, copyright 2020 Orange and Nokia.
# Licensed under Apache License 2.0: https://www.apache.org/licenses/LICENSE-2.0
import hashlib
from pathlib import Path

SOURCE_SHA256 = '19706add25101b88aa6171783ebe6db1cf1943c76225036badf2ad56f8377a5e'
OLD = '''        if response.status.succeeded == 1:
            job_status_type = response.status.conditions[0].type
            if job_status_type == "Complete":
                complete = True
                log.info("%s is complete", job_name)
            else:
                log.info("%s is NOT complete", job_name)
        else:
            log.info("%s has not succeeded yet", job_name)'''
NEW = '''        conditions = response.status.conditions or []
        complete = (any(c.type == "Complete" and c.status == "True" for c in conditions)
                    and not any(c.type in ("Failed", "Suspended") and c.status == "True"
                                for c in conditions))
        log.info("%s is %scomplete", job_name, "" if complete else "NOT ")'''


def patched_source(blob):
    if hashlib.sha256(blob).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unreviewed stock readiness source; refusing to execute')
    source = blob.decode('utf-8')
    if source.count(OLD) != 1:
        raise ValueError('Stock readiness predicate no longer matches review')
    return source.replace(OLD, NEW)


if __name__ == '__main__':
    # Keep stock argument parsing, API authentication, retry and timeout behavior.
    exec(compile(patched_source(Path('/app/ready.py').read_bytes()),
                 '/app/ready.py', 'exec'), globals())
