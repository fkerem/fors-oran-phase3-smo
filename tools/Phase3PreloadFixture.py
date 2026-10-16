"""Independent, stateful SMS fixture. All values are synthetic and private.

This module deliberately does not import phase3_preload or its response parsers.
It models the SMS 4.0.2 wire contract, including 201 JSON domain creation and
201 empty secret creation. Exact-image qualification must corroborate that model.
"""
import copy
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import uuid
from urllib.parse import unquote


def encoded(value):
    return json.dumps(value, sort_keys=True).encode('utf-8')


class State:
    def __init__(self, fault='success'):
        self.fault = fault
        self.domains = {}
        self.requests = []

    def request(self, method, path, data=None):
        self.requests.append((method, path))  # Never retain bodies in public logs.
        parts = [unquote(p) for p in path.strip('/').split('/')]
        if parts[:3] != ['v1', 'sms', 'domain']:
            return 404, b'{}'
        if method == 'POST' and len(parts) == 3:
            name = data.get('name') if isinstance(data, dict) else None
            if not isinstance(name, str) or not name:
                return 400, b'{}'
            if self.fault == 'domain-500':
                return 500, b'{}'
            if name in self.domains or self.fault == 'domain-conflict':
                return 409, b'{}'
            self.domains[name] = {}
            if self.fault == 'ambiguous-domain':
                raise ConnectionError('Synthetic uncertain write')
            if self.fault == 'malformed-domain':
                return 201, b'{'
            # SMS returns a domain object; secret values are never in it.
            return 201, encoded({'name': name, 'uuid': str(uuid.uuid4())})
        if len(parts) < 5 or parts[4] != 'secret' or parts[3] not in self.domains:
            return 404, b'{}'
        domain = self.domains[parts[3]]
        if method == 'POST' and len(parts) == 5:
            if self.fault == 'secret-500':
                return 500, b'{}'
            if not isinstance(data, dict) or set(data) != {'name', 'values'}:
                return 400, b'{}'
            name = data['name']
            if name in domain:
                return 409, b'{}'
            domain[name] = copy.deepcopy(data['values'])
            if self.fault == 'ambiguous-secret':
                raise ConnectionError('Synthetic uncertain write')
            return 201, b''
        if method == 'GET' and len(parts) == 5:
            names = sorted(domain)
            if self.fault == 'extra-secret':
                names.append('unplanned')
            return 200, encoded({'secretnames': names})
        if method == 'GET' and len(parts) == 6 and parts[5] in domain:
            if self.fault == 'malformed-readback':
                return 200, b'{'
            values = copy.deepcopy(domain[parts[5]])
            if self.fault == 'changed-readback':
                values[next(iter(values))] += '-changed'
            if self.fault == 'extra-value-key':
                values['unexpected'] = 'synthetic-only'
            return 200, encoded({'name': parts[5], 'values': values})
        return 405, b'{}'

    def counts(self):
        return {'domain_posts': sum(m == 'POST' and p == '/v1/sms/domain' for m, p in self.requests),
                'secret_posts': sum(m == 'POST' and p.endswith('/secret') for m, p in self.requests)}


class KubeState:
    """Independent ConfigMap protocol with server-side UID/RV checks."""
    path = '/api/v1/namespaces/onap/configmaps/phase3-sms-preload-journal'

    def __init__(self, fault='success'):
        self.fault = fault
        self.requests = []
        self.version = 1
        self.record = {'state': 'prepared', 'binding': {'fixture': 'synthetic'}}

    def object(self):
        return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': 'phase3-sms-preload-journal', 'namespace': 'onap',
            'uid': 'fixture-journal-uid', 'resourceVersion': str(self.version)},
            'data': {'journal.json': json.dumps(self.record, sort_keys=True)}}

    def request_with_headers(self, method, path, data, headers):
        self.requests.append((method, path))
        if path != self.path:
            return 404, b'{}'
        if headers.get('Authorization') != 'Bearer isolated-fixture-token':
            return 401, b'{}'
        if method == 'GET':
            if self.fault == 'read-403':
                return 403, b'{}'
            if self.fault == 'read-redirect':
                return 307, b'{}'
            if self.fault == 'malformed-read':
                return 200, b'{'
            if self.fault == 'oversized-read':
                return 200, b' ' * (1024 * 1024 + 1)
            obj = self.object()
            if self.fault == 'replaced-read-uid':
                obj['metadata']['uid'] = 'replacement-uid'
            return 200, encoded(obj)
        if method != 'PUT':
            return 405, b'{}'
        if self.fault == 'write-500':
            return 500, b'{}'
        if self.fault == 'write-redirect':
            return 307, b'{}'
        metadata = data.get('metadata', {})
        if (metadata.get('uid') != 'fixture-journal-uid'
                or metadata.get('resourceVersion') != str(self.version)):
            return 409, b'{}'
        if metadata.get('name') != 'phase3-sms-preload-journal' or metadata.get('namespace') != 'onap':
            return 400, b'{}'
        record = json.loads(data['data']['journal.json'])
        if any(key.startswith('_') for key in record):
            return 400, b'{}'
        self.record = copy.deepcopy(record)
        self.version += 1
        if self.fault == 'ambiguous-commit':
            raise ConnectionError('Synthetic acknowledgement lost after commit')
        obj = self.object()
        if self.fault == 'replaced-write-uid':
            obj['metadata']['uid'] = 'replacement-uid'
        return 200, encoded(obj)


class Server:
    """Bound to loopback only, with explicit TLS and no request-body logging."""
    def __init__(self, state, certificate, key):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle_request(self):
                length = int(self.headers.get('Content-Length', '0'))
                if length > 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                try:
                    data = json.loads(body) if body else None
                    if hasattr(state, 'request_with_headers'):
                        status, blob = state.request_with_headers(self.command, self.path, data, self.headers)
                    else:
                        status, blob = state.request(self.command, self.path, data)
                except ConnectionError:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                except (ValueError, TypeError):
                    status, blob = 400, b'{}'
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(blob)))
                self.end_headers()
                self.wfile.write(blob)

            do_GET = handle_request
            do_POST = handle_request
            do_PUT = handle_request

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certificate), str(key))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=.02), daemon=True)

    def __enter__(self):
        self.thread.start()
        return self.server.server_address[1]

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class Transport:
    def __init__(self, port, ca, readback=None, client=None):
        self.port = port
        self.context = ssl.create_default_context(cafile=str(ca))
        self.observations = []
        self.readback = readback
        self.client = client

    def request(self, method, path, data=None):
        if self.client is not None:
            status, blob = self.client.request(method, path, data)
            self.observe(method, path, status, blob)
            return status, blob
        connection = http.client.HTTPSConnection('localhost', self.port, context=self.context, timeout=5)
        try:
            connection.request(method, path, encoded(data) if data is not None else None,
                               {'Content-Type': 'application/json'})
            response = connection.getresponse()
            blob = response.read(1024 * 1024 + 1)
            if len(blob) > 1024 * 1024:
                raise ValueError('Isolated response exceeds limit')
            self.observe(method, path, response.status, blob)
            return response.status, blob
        finally:
            connection.close()

    def observe(self, method, path, status, blob):
        self.observations.append((method, path, status, len(blob)))
        if method == 'GET' and self.readback is not None:
            # Private full response, never included in the qualification receipt.
            descriptor = os.open(str(self.readback), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, 'ab') as stream:
                stream.write(encoded({'path': path, 'status': status,
                                      'body': blob.decode('utf-8')}) + b'\n')


class Journal:
    """Private in-process CAS; Kubernetes resourceVersion is tested by its adapter."""
    def __init__(self, binding):
        self.data = {'state': 'prepared', 'binding': copy.deepcopy(binding)}
        self.version = 1

    def read(self):
        return dict(copy.deepcopy(self.data), _resourceVersion=str(self.version))

    def cas(self, old, new):
        if old != self.read():
            raise ValueError('Isolated journal CAS conflict')
        self.data = {k: copy.deepcopy(v) for k, v in new.items() if not k.startswith('_')}
        self.version += 1
