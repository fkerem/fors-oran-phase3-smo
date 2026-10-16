#!/usr/bin/env python3
"""In-Job guarded writer. No CLI for recovery, alternate inputs, or replay."""
import http.client
import json
import os
from pathlib import Path
import ssl
import phase3_preload as preload


class KubeJournal:
    def __init__(self, uid):
        self.uid = uid
        self.path = '/api/v1/namespaces/onap/configmaps/'+preload.JOURNAL

    def request(self, method, obj=None):
        context = ssl.create_default_context(cafile='/phase3-api/ca.crt')
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = http.client.HTTPSConnection(os.environ['KUBERNETES_SERVICE_HOST'],
            int(os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS', '443')), context=context, timeout=10)
        try:
            token = Path('/phase3-api/token').read_text().strip()
            conn.request(method, self.path, preload.canonical(obj) if obj is not None else None,
                         {'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'})
            response = conn.getresponse()
            body = response.read(1024*1024+1)
            if response.status != 200 or len(body) > 1024*1024:
                raise preload.Blocked('Journal API request failed; no retry')
            result = preload.strict_json(body)
            if result['metadata']['uid'] != self.uid:
                raise preload.Blocked('Journal identity replaced')
            return result
        finally:
            conn.close()

    def read(self):
        obj = self.request('GET')
        record = preload.strict_json(obj['data']['journal.json'])
        record['_resourceVersion'] = obj['metadata']['resourceVersion']
        return record

    def cas(self, old, new):
        value = {k: v for k, v in new.items() if not k.startswith('_')}
        self.request('PUT', {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': preload.JOURNAL, 'namespace': 'onap', 'uid': self.uid,
            'resourceVersion': old['_resourceVersion']}, 'data': {'journal.json': json.dumps(value, sort_keys=True)}})


def main():
    try:
        root = Path('/phase3-input')
        config = preload.strict_json((root/'input.json').read_bytes())
        if config.get('contract') != preload.CONTRACT:
            raise preload.Blocked('Unreviewed input contract')
        preload.validate_plan(config['plan'])
        journal = KubeJournal(config['journal_uid'])
        transport = preload.Transport(root/'root.cer', config['sms_address'])
        preload.execute(config['plan'], transport, journal, config['binding'], os.environ['PHASE3_POD_UID'])
        print('SMS preload: private postconditions verified; host acceptance remains required')
        return 0
    except Exception:
        print('SMS preload stopped; no retries, rollback or replay; inspect private operator metadata')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
