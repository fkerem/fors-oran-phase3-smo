#!/usr/bin/env python3
"""One guarded DMAAP attempt; no CLI for alternate inputs or replay."""
import http.client
import os
from pathlib import Path
import ssl
import phase3_dmaap as dmaap


class KubeJournal:
    def __init__(self, uid):
        self.uid = uid
        self.path = '/api/v1/namespaces/onap/configmaps/'+dmaap.JOURNAL

    def request(self, method, obj=None):
        context = ssl.create_default_context(cafile='/phase3-api/ca.crt')
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = http.client.HTTPSConnection(os.environ['KUBERNETES_SERVICE_HOST'],
            int(os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS', '443')), context=context, timeout=10)
        try:
            conn.request(method, self.path, dmaap.canonical(obj) if obj is not None else None,
                         {'Authorization': 'Bearer '+Path('/phase3-api/token').read_text().strip(),
                          'Content-Type': 'application/json'})
            response = conn.getresponse()
            body = response.read(1024*1024+1)
            if response.status != 200 or len(body) > 1024*1024:
                raise dmaap.Blocked('DMAAP journal API request failed; no retry')
            result = dmaap.strict_json(body)
            if result['metadata']['uid'] != self.uid:
                raise dmaap.Blocked('DMAAP journal identity replaced')
            return result
        finally:
            conn.close()

    def read(self):
        obj = self.request('GET')
        record = dmaap.strict_json(obj['data']['journal.json'])
        record['_resourceVersion'] = obj['metadata']['resourceVersion']
        return record

    def cas(self, old, new):
        self.request('PUT', {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': dmaap.JOURNAL, 'namespace': 'onap', 'uid': self.uid,
            'resourceVersion': old['_resourceVersion']},
            'data': {'journal.json': dmaap.canonical({k:v for k,v in new.items() if not k.startswith('_')}).decode()}})


def main():
    try:
        root = Path('/phase3-input')
        config = dmaap.strict_json((root/'input.json').read_bytes())
        if set(config) != {'contract','plan','binding','journal_uid','address','credential'} or config['contract'] != 1:
            raise dmaap.Blocked('Unreviewed DMAAP private input')
        transport = dmaap.Transport(root/'root.cer', config['address'], config['credential'])
        dmaap.execute(config['plan'], transport, KubeJournal(config['journal_uid']),
                      config['binding'], os.environ['PHASE3_POD_UID'])
        print('DMAAP private postconditions verified; host acceptance remains required')
        return 0
    except Exception:
        print('DMAAP stopped; no retry, overwrite, rollback or replay')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
