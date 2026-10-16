"""Synthetic HTTPS endpoint; never contacts an experiment or handles real keys."""
import http.server
import json
from pathlib import Path
import ssl

root = Path('/fixture')


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self):
        with (root/'requests.jsonl').open('a') as stream:
            stream.write(json.dumps({'method':self.command,'path':self.path})+'\n')
        blob = json.dumps({'sealstatus':True} if self.command=='GET' else {'error':'fixture refusal'}).encode()
        self.send_response(200 if self.command=='GET' else 500)
        self.send_header('Content-Length',str(len(blob))); self.end_headers(); self.wfile.write(blob)

    do_GET = reply
    do_POST = reply


server = http.server.HTTPServer(('127.0.0.1',10443),Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(root/'server.cer',root/'server.key')
server.socket = context.wrap_socket(server.socket,server_side=True)
(root/'tls-ready').touch()
server.serve_forever()
