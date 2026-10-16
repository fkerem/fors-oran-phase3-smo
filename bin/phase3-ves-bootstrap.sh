#!/bin/bash
# The pinned image's Java 8 agent reads this public JKS before contacting AAF.
# Keep its stock binaries and conversion script; never expose stock xtrace.
set -euo pipefail
umask 077
state=/phase3-ves-attempt
fail() { echo "$1" >&2; exit 1; }
[ "$(sha256sum /opt/dcae/dcae-cert-setup.sh | cut -d ' ' -f1)" = 31aa68706dd52bcbdb30e243d76c370e60ca222ebf23fe7977de4be4c72b1b0c ] || fail 'Unreviewed VES conversion source'
[ "$(sha256sum /opt/app/aaf_config/bin/agent.sh | cut -d ' ' -f1)" = 8d5ec5e08a57033449511f9ac66773c105d47b79dee620b4314e867c3f4d276d ] || fail 'Unreviewed VES agent source'
cmp /root/.aaf/truststoreONAPall.jks /phase3-ves/truststoreONAPall.jks >/dev/null || fail 'VES trust mount mismatch'
# The latch survives initializer restarts but not an explicitly reviewed new Pod.
mkdir "$state/attempted" 2>/dev/null || fail 'VES issuance already attempted; explicit recovery review required'
if ! bash /opt/dcae/dcae-cert-setup.sh >"$state/stock.log" 2>&1; then
    fail 'VES initialization failed; diagnostics remain private in the attempt volume'
fi
for artifact in cert.p12 cert.jks trust.jks cert.pem key.pem cacert.pem p12.pass jks.pass; do
    test -s "/opt/app/osaaf/$artifact" || fail 'VES artifact validation failed'
done
openssl pkcs12 -in /opt/app/osaaf/cert.p12 -passin file:/opt/app/osaaf/p12.pass -noout >"$state/p12-check.log" 2>&1 || fail 'VES PKCS12 validation failed'
openssl verify -CAfile /phase3-ves/root.cer -untrusted /opt/app/osaaf/cert.pem /opt/app/osaaf/cert.pem >"$state/chain-check.log" 2>&1 || fail 'VES chain validation failed'
openssl x509 -in /opt/app/osaaf/cert.pem -checkend 0 -noout >/dev/null || fail 'VES certificate expired'
root_fp=$(openssl x509 -in /phase3-ves/root.cer -noout -fingerprint -sha256)
actual_fp=$(openssl x509 -in /opt/app/osaaf/cacert.pem -noout -fingerprint -sha256)
[ "$root_fp" = "$actual_fp" ] || fail 'VES exported the wrong CA'
openssl x509 -in /opt/app/osaaf/cert.pem -pubkey -noout >"$state/cert-public.pem"
openssl pkey -in /opt/app/osaaf/key.pem -pubout >"$state/key-public.pem" 2>/dev/null
cmp "$state/cert-public.pem" "$state/key-public.pem" >/dev/null || fail 'VES certificate/key mismatch'
echo 'VES initializer completed; experiment CA and converted artifacts verified'
