"""Production DMAAP transport over verified loopback TLS, synthetic material."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'bin'),str(ROOT/'tools')]
import phase3_dmaap as dmaap
from phase3_lab_pki import certificate,name
from Phase3PreloadFixture import Server


class State:
    def __init__(self): self.requests=[]
    def request_with_headers(self,method,path,data,headers):
        self.requests.append((method,path,data,headers.get('Authorization')))
        return 307,b'{}'  # Must be returned, never followed or replayed.


class DmaapTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.ca=certificate(name('synthetic root'),self.ca_key,name('synthetic root'),self.ca_key,2,True,0)
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        (self.root/'root.cer').write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        (self.root/'server.key').write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))

    def leaf(self,mode):
        key=self.ca_key;issuer=self.ca
        if mode=='wrong-ca':
            key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            issuer=certificate(name('other root'),key,name('other root'),key,2,True,0)
        hostname='wrong.invalid' if mode=='wrong-hostname' else 'localhost'
        leaf=certificate(name(hostname),self.key,issuer.subject,key,1,sans=[hostname])
        if mode=='expired':
            now=datetime.now(timezone.utc)
            leaf=(x509.CertificateBuilder().subject_name(name('localhost')).issuer_name(issuer.subject)
                .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(days=2)).not_valid_after(now-timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False).sign(key,hashes.SHA256()))
        (self.root/'server.cer').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))

    def test_verified_tls_basic_contract_and_no_redirect_follow(self):
        self.leaf('valid');state=State()
        with Server(state,self.root/'server.cer',self.root/'server.key') as port:
            transport=dmaap.Transport(self.root/'root.cer','127.0.0.1','fixture:synthetic-only',hostname='localhost',port=port)
            self.assertEqual((307,b'{}'),transport.request('POST','/webapi/dmaap',{'fixture':'only'}))
        self.assertEqual([('POST','/webapi/dmaap',{'fixture':'only'},'Basic Zml4dHVyZTpzeW50aGV0aWMtb25seQ==')],state.requests)

    def test_tls_negative_controls_never_reach_application(self):
        for mode in ('wrong-ca','wrong-hostname','expired','missing-ca'):
            self.leaf(mode);state=State()
            with Server(state,self.root/'server.cer',self.root/'server.key') as port:
                with self.assertRaises((OSError,ValueError)):
                    transport=dmaap.Transport(self.root/('missing.cer' if mode=='missing-ca' else 'root.cer'),
                        '127.0.0.1','fixture:synthetic-only',hostname='localhost',port=port)
                    transport.request('POST','/webapi/dmaap',{})
            self.assertEqual([],state.requests)

    def test_unreviewed_paths_and_credential_control_characters_rejected(self):
        for credential in ('missing-colon','user:pass\n','user:pass\0'):
            with self.assertRaises(ValueError):dmaap.Transport(self.root/'root.cer','127.0.0.1',credential)
        transport=dmaap.Transport(self.root/'root.cer','127.0.0.1','fixture:synthetic-only')
        for method,path in (('PUT','/webapi/dmaap'),('POST','/webapi/topics?useExisting=true'),('POST','/other')):
            with self.assertRaises(ValueError):transport.request(method,path,{})


if __name__=='__main__':unittest.main()
