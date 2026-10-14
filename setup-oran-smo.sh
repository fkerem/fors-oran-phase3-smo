#!/bin/bash
SRC=$(cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=setup-lib.sh
. "$SRC/setup-lib.sh"
set -eo pipefail
umask 077
if [ -f "$OURDIR/setup-oran-smo-done" ]; then
    exit 0
fi
logtstart oran-smo
work="$OURDIR/phase3-smo"
lock="$work/chart-lock.json"
renderer="$SRC/bin/helm-api-compat.py"
case "$(helm version --short)" in
    v3.*) ;;
    *) echo "ERROR: the pinned ONAP deployment plugin requires Helm 3" >&2; exit 1 ;;
esac

# Repeat the check immediately before install; never fall back to ChartMuseum.
python3 "$SRC/bin/smo-chart-preflight.py" --release "$OSCSMOVERSION" \
    --cache-dir "$work/charts" --output "$lock"
lock_value() {
    python3 - "$lock" "$1" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split('.'):
    value = value[key]
print(value)
PY
}
checkout_source() {
    local repo=$1 destination=$2 commit=$3
    if [ ! -d "$destination/.git" ]; then
        git clone --no-checkout "$repo" "$destination"
        git -C "$destination" checkout --detach "$commit"
    fi
    [ "$(git -C "$destination" rev-parse HEAD)" = "$commit" ] || {
        echo "ERROR: dependency checkout differs from pin: $destination" >&2
        return 1
    }
}
checkout_source https://gerrit.o-ran-sc.org/r/it/dep "$work/dep" "$(lock_value dep_commit)"
checkout_source https://github.com/onap/oom.git "$work/oom" "$(lock_value onap_plugin_commit)"
if git -C "$work/oom" apply --check "$SRC/patches/onap-deploy-failures.patch"; then
    git -C "$work/oom" apply "$SRC/patches/onap-deploy-failures.patch"
elif ! git -C "$work/oom" apply --reverse --check "$SRC/patches/onap-deploy-failures.patch"; then
    echo "ERROR: ONAP plugin failure-propagation patch does not match its pin" >&2
    exit 1
fi
for plugin in deploy undeploy; do
    if ! helm plugin list | awk 'NR>1 {print $1}' | grep -qx "$plugin"; then
        helm plugin install "$work/oom/kubernetes/helm/plugins/$plugin"
    fi
done

values="$work/dep/smo-install/helm-override/powder"
python3 "$SRC/bin/prepare-smo-values.py" --defaults-dir "$work/dep/smo-install/helm-override/default" \
    --output-dir "$values" --release "$OSCSMOVERSION"
if [ ! -e /dockerdata-nfs ]; then
    $SUDO ln -s /storage/nfs /dockerdata-nfs
fi

mkdir -p "$work/rendered" "$work/unpacked" "$work/prepared"
for name in onap nonrtric ru-du-simulators; do
    archive=$(lock_value "charts.$name.path")
    python3 "$SRC/bin/prepare-cached-chart.py" --archive "$archive" \
        --sha256 "$(lock_value "charts.$name.sha256")" --output "$work/prepared/$name.tgz" \
        --record "$work/prepared/$name-changes.json"
    case "$name" in
        onap) overrides=(-f "$values/onap-override.yaml") ;;
        nonrtric) overrides=(-f "$values/oran-override.yaml") ;;
        ru-du-simulators) overrides=(-f "$values/network-simulators-override.yaml" -f "$values/network-simulators-topology-override.yaml") ;;
    esac
    helm template "phase3-$name" "$work/prepared/$name.tgz" --namespace "phase3-preview" \
        --kube-version "$KUBEVERSION" "${overrides[@]}" | "$renderer" > "$work/rendered/$name.yaml"
done
# The plugin expects a relative directory named CHART_ROOT/onap.
tar -xzf "$work/prepared/onap.tgz" -C "$work/unpacked"
strimzi_archive=$(lock_value charts.strimzi-kafka-operator.path)
compatibility="$work/compatibility/strimzi-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$compatibility"
kubectl get --raw /version --request-timeout=30s > "$compatibility/server-version.json"
python3 "$SRC/bin/strimzi-version-compat.py" prepare \
    --server-version-json "$compatibility/server-version.json" --expected-version "$KUBEVERSION" \
    --values-output "$compatibility/values.yaml" --record-output "$compatibility/version-override.json"
helm template strimzi-kafka-operator "$strimzi_archive" --namespace strimzi-system \
    --kube-version "$KUBEVERSION" --include-crds -f "$compatibility/values.yaml" \
    | "$renderer" > "$work/rendered/strimzi.yaml"
kubectl create namespace strimzi-system --dry-run=client -o yaml | kubectl apply -f -
helm upgrade --install strimzi-kafka-operator "$strimzi_archive" --namespace strimzi-system \
    --set resources.limits.memory=1Gi --set resources.requests.memory=1Gi \
    --set watchAnyNamespace=true -f "$compatibility/values.yaml" --post-renderer "$renderer" --wait --timeout 10m
python3 "$SRC/bin/strimzi-version-compat.py" wait \
    --record "$compatibility/version-override.json" --output "$compatibility/operator-gate.json"
kubectl create namespace onap --dry-run=client -o yaml | kubectl apply -f -
cd "$work"
helm -n onap deploy onap unpacked/onap --namespace onap --post-renderer "$renderer" \
    -f "$values/onap-override.yaml"
test -n "$(kubectl -n onap get kafkas.kafka.strimzi.io -o name)" || {
    echo "ERROR: ONAP has not created its expected Kafka resource" >&2; exit 1;
}
kubectl -n onap wait kafkas.kafka.strimzi.io --all --for=condition=Ready --timeout=20m
kubectl -n onap wait deployments --for=condition=Available --all --timeout=60m
helm upgrade --install oran-nonrtric "$work/prepared/nonrtric.tgz" \
    --namespace nonrtric --create-namespace --post-renderer "$renderer" \
    -f "$values/oran-override.yaml" --wait --timeout 30m
helm upgrade --install oran-simulator "$work/prepared/ru-du-simulators.tgz" \
    --namespace network --create-namespace --post-renderer "$renderer" \
    -f "$values/network-simulators-override.yaml" \
    -f "$values/network-simulators-topology-override.yaml" --wait --timeout 20m
for ns in onap nonrtric network; do
    deployments=$(kubectl -n "$ns" get deployments -o name)
    if [ -n "$deployments" ]; then
        kubectl -n "$ns" wait deployments --all --for=condition=Available --timeout=60m
    fi
    while read -r resource; do
        [ -z "$resource" ] || kubectl -n "$ns" rollout status "$resource" --timeout=60m
    done < <(kubectl -n "$ns" get statefulsets -o name)
done
# The ONAP plugin can swallow child Helm failures. Check release states too.
python3 "$SRC/bin/collect-phase3-provenance.py" --output "$work/provenance.json" --require-ready
logtend oran-smo
touch "$OURDIR/setup-oran-smo-done"
