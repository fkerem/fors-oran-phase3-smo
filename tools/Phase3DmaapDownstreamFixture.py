"""Synthetic downstream services for exact DMAAP; isolated loopback only."""
import http.server
import json
import os
from pathlib import Path
import ssl
import threading
import time

ROOT=Path('/fixture')


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass

    def do_POST(self):
        length=int(self.headers.get('Content-Length','0'))
        if length>1024*1024:
            self.send_error(413);return
        body=self.rfile.read(length)
        # All bodies/credentials are generated fixture material. Keep them
        # private for independent downstream relationship inspection.
        record={'port':self.server.server_port,'method':'POST','path':self.path,
                'body':json.loads(body),'authorization_present':bool(self.headers.get('Authorization'))}
        fd=os.open(str(ROOT/'downstream.jsonl'),os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
        with os.fdopen(fd,'a') as output: output.write(json.dumps(record,sort_keys=True)+'\n')
        self.send_response(201);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'{}')


if __name__=='__main__':
    servers=[]
    for port in (18443,18080):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler)
        if port==18443:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(ROOT/'server.cer'),str(ROOT/'server.key'))
            server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
    (ROOT/'downstream-ready').touch(mode=0o600)
    while True:time.sleep(1)
