"""Private per-experiment PKI. No generated material belongs in the public repo."""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CONFIG_IMAGE = 'nexus3.onap.org:10001/onap/aaf/aaf_config@sha256:681b0a23c5d99e9bf469f532a5e75afb5ff45cce78cb6d16579286fb6e05a3d5'
AGENT_IMAGE = 'nexus3.onap.org:10001/onap/aaf/aaf_agent@sha256:fbc54287e95950956aeb8c5f86f2618fb52192aee389e2fa212c183395bb5c2b'
CORE_IMAGE = 'nexus3.onap.org:10001/onap/aaf/aaf_core@sha256:f8d4d9e0868b4197d01d06d531c6a40a4b54c77f7fade563a379f7d9f6898e51'
ISSUER_CN = 'intermediateCA_9'
SERVICES = ('service', 'locate', 'oauth', 'token', 'introspect', 'gui', 'cm', 'hello')
SANS = sorted({'aaf.osaaf.org', 'aaf-locate.onap', *('aaf-'+s for s in SERVICES),
               *('aaf-'+s+'.onap' for s in SERVICES), *(s+'.aaf.osaaf.org' for s in SERVICES)})


def private_write(path, blob):
    with open(path, 'xb') as output:
        os.chmod(path, 0o600)
        output.write(blob)


def name(cn, identity=None):
    parts = [x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ONAP'),
             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'OSAAF')]
    if identity:
        parts.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, identity))
    return x509.Name(parts + [x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def certificate(subject, key, issuer, issuer_key, days, ca=False, path_length=None, sans=None):
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=not ca, data_encipherment=False, key_agreement=False,
                key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), True))
    if sans:
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
        cert = cert.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)
    return cert.sign(issuer_key, hashes.SHA256())


def p12_encryption(password):
    # Java 11/older OpenSSL compatibility, not the newer PBESv2 packaging default.
    if hasattr(serialization.PrivateFormat, 'PKCS12') and hasattr(serialization.PrivateFormat.PKCS12, 'encryption_builder'):
        return (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000)
                .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                .hmac_hash(hashes.SHA1()).build(password))
    # Ubuntu 22.04 cryptography 3.4 uses this PKCS12 packaging by default.
    return serialization.BestAvailableEncryption(password)


def generate(directory, experiment):
    directory = Path(directory)
    if directory.exists():
        raise ValueError('Refusing to regenerate or overwrite existing experiment PKI')
    directory.mkdir(mode=0o700, parents=True)
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=3072) for _ in range(3)]
    root = certificate(name('Phase3 Lab Root '+experiment), keys[0], name('Phase3 Lab Root '+experiment), keys[0], 1825, True, 1)
    intermediate = certificate(name(ISSUER_CN), keys[1], root.subject, keys[0], 1095, True, 0)
    leaf = certificate(name('aaf.osaaf.org', 'aaf@aaf.osaaf.org'), keys[2], intermediate.subject, keys[1], 365, sans=SANS)
    password = secrets.token_urlsafe(36).encode()
    for filename, cert in [('root',root),('intermediate',intermediate),('server',leaf)]:
        private_write(directory/(filename+'.cer'), cert.public_bytes(serialization.Encoding.PEM))
    # Retain root privately for controlled future issuance, never mount it in Pods.
    private_write(directory/'root-private.key', keys[0].private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password)))
    private_write(directory/'store-password', password)
    for filename, alias, key, cert, chain in [
            ('server.p12',b'aaf@aaf.osaaf.org',keys[2],leaf,[intermediate,root]),
            ('signer.p12',b'aaf_intermediate_9',keys[1],intermediate,[root])]:
        private_write(directory/filename, pkcs12.serialize_key_and_certificates(alias,key,cert,chain,p12_encryption(password)))
    record = {'schema':1, 'experiment':experiment, 'baseline':'fresh-isolated-lab-pki',
              'issuer_dn_retained_for_cadi_compatibility':True, 'stock_truststore_password_retained':True,
              'sans':SANS, 'certificates':{n:{'sha256':c.fingerprint(hashes.SHA256()).hex(),
                'not_after':(c.not_valid_after_utc if hasattr(c,'not_valid_after_utc') else
                    c.not_valid_after.replace(tzinfo=dt.timezone.utc)).isoformat()}
                    for n,c in [('root',root),('intermediate',intermediate),('server',leaf)]}}
    private_write(directory/'public-metadata.json', (json.dumps(record,indent=2)+'\n').encode())
    return record


def trust_config(directory):
    return {n+'.b64':base64.b64encode((Path(directory)/n).read_bytes()).decode()
            for n in ('truststoreONAPall.jks','truststoreONAP.p12')}


def secret(directory, namespace, secret_name):
    files = ('server.p12','signer.p12','store-password','root.cer','intermediate.cer','server.cer',
             'truststoreONAPall.jks','truststoreONAP.p12')
    return {'apiVersion':'v1','kind':'Secret','metadata':{'name':secret_name,'namespace':namespace},
            'type':'Opaque','immutable':True,'data':{n:base64.b64encode((Path(directory)/n).read_bytes()).decode() for n in files}}
