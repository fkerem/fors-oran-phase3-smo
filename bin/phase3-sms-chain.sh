#!/bin/bash
# Only public chain assembly. No AAF agent, key generation or credential output.
set -euo pipefail
umask 077
state=/phase3-sms-attempt
public=/phase3-sms
target=/opt/app/osaaf/local/org.onap.aaf-sms.crt
fail() { echo 'SMS public-chain validation failed; review private initializer diagnostics' >&2; exit 1; }
mkdir "$state/attempted" 2>/dev/null || fail
test -s "$target" && test ! -L "$target" || fail
# Retain the issued first leaf, not any packaged or stale appended certificate.
awk '/-----BEGIN CERTIFICATE-----/{n++} n==1{print} /-----END CERTIFICATE-----/ && n==1{exit}' "$target" >"$state/leaf.cer"
test -s "$state/leaf.cer" || fail
openssl verify -CAfile "$public/root.cer" -untrusted "$public/intermediate.cer" \
    -purpose sslserver -verify_hostname aaf-sms.onap "$state/leaf.cer" >"$state/verify.log" 2>&1 || fail
openssl x509 -in "$state/leaf.cer" -checkend 0 -noout >"$state/expiry.log" 2>&1 || fail
cat "$state/leaf.cer" "$public/intermediate.cer" >"$target.phase3-new"
chmod "$(stat -c '%a' "$target")" "$target.phase3-new"
chown "$(stat -c '%u:%g' "$target")" "$target.phase3-new"
mv "$target.phase3-new" "$target"
echo 'SMS issued leaf retained; allocation public chain, purpose and hostname verified'
