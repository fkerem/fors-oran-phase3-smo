#!/bin/bash
# Compatibility packaging only: initialize stock properties offline, then install
# this experiment's reviewed key/issuer material before any server can start.
set -euo pipefail
umask 077
config=/opt/app/aaf_config
osaaf=/opt/app/osaaf
pki=/phase3-pki
expected=5b6b326244d5d8a78fd3157c6c9838ba061f35629dcb291960f5f14446bffe1d
[ "$(sha256sum "$config/bin/agent.sh" | cut -d ' ' -f1)" = "$expected" ] || {
    echo 'AAF bootstrap source differs from reviewed 2.1.23; refusing' >&2; exit 1;
}
mkdir -p "$osaaf/local" "$osaaf/public" "$osaaf/logs"
# Stock output can contain bootstrap configuration; never print it to Pod logs.
bash "$config/bin/agent.sh" >"$osaaf/logs/phase3-stock-bootstrap.log" 2>&1
keyfile="$osaaf/local/org.osaaf.aaf.keyfile"
props="$osaaf/local/org.osaaf.aaf.props"
caprops="$osaaf/local/org.osaaf.aaf.cm.ca.props"
test -s "$keyfile" && test -s "$props" && test -s "$caprops"
cp "$pki/server.p12" "$osaaf/local/org.osaaf.aaf.p12"
cp "$pki/signer.p12" "$osaaf/local/org.osaaf.aaf.signer.p12"
cp "$pki/truststoreONAPall.jks" "$osaaf/public/truststoreONAPall.jks"
cp "$pki/truststoreONAP.p12" "$osaaf/public/truststoreONAP.p12"
cp "$pki/root.cer" "$osaaf/public/AAF_RootCA.cer"
cp "$pki/root.cer" "$osaaf/public/phase3-root.cer"
cp "$pki/intermediate.cer" "$osaaf/public/phase3-intermediate.cer"
pw=$(<"$pki/store-password")
jars=("$config"/bin/aaf-auth-cmd-*-full.jar)
[ "${#jars[@]}" -eq 1 ] && test -f "${jars[0]}"
encrypted=$("$JAVA_HOME/bin/java" -cp "${jars[0]}" \
    org.onap.aaf.cadi.CmdLine digest "$pw" "$keyfile")
[[ "$encrypted" =~ ^[A-Za-z0-9_=-]+$ ]] || { echo 'Invalid CADI digest result' >&2; exit 1; }
# Write values without echoing generated passwords, keys, or encrypted values.
set_prop() {
    local file=$1 name=$2 value=$3
    local temporary
    temporary=$(mktemp "$osaaf/local/phase3-props.XXXXXX")
    awk -v key="$name" 'index($0,key "=")!=1 {print}' "$file" >"$temporary"
    printf '%s=%s\n' "$name" "$value" >>"$temporary"
    mv "$temporary" "$file"
}
set_prop "$props" cadi_keystore_password "enc:$encrypted"
set_prop "$props" cadi_truststore_password changeit
set_prop "$props" cadi_x509_issuers 'CN=intermediateCA_9, OU=OSAAF, O=ONAP, C=US'
set_prop "$caprops" cm_ca.local "org.onap.aaf.auth.cm.ca.LocalCA,$osaaf/local/org.osaaf.aaf.signer.p12;aaf_intermediate_9;enc:$encrypted"
set_prop "$caprops" cm_trust_cas "$osaaf/public/phase3-root.cer"
openssl verify -CAfile "$pki/root.cer" -untrusted "$pki/intermediate.cer" \
    -verify_hostname aaf-locate.onap "$pki/server.cer" >/dev/null
export PHASE3_STORE_PASSWORD="$pw"
"$JAVA_HOME/bin/keytool" -list -keystore "$osaaf/local/org.osaaf.aaf.p12" \
    -storetype PKCS12 -storepass:env PHASE3_STORE_PASSWORD -alias aaf@aaf.osaaf.org >/dev/null 2>&1
"$JAVA_HOME/bin/keytool" -list -keystore "$osaaf/local/org.osaaf.aaf.signer.p12" \
    -storetype PKCS12 -storepass:env PHASE3_STORE_PASSWORD -alias aaf_intermediate_9 >/dev/null 2>&1
unset PHASE3_STORE_PASSWORD pw encrypted
chown -R 1000:1000 "$osaaf/local" "$osaaf/public" "$osaaf/logs"
echo 'AAF offline configuration prepared with experiment-local PKI; live retrieval remains gated'
