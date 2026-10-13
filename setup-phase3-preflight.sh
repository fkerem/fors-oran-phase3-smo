#!/bin/bash
# Run before Kubernetes installation, so absent cached charts fail early.
SRC=$(cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=setup-lib.sh
. "$SRC/setup-lib.sh"
set -eo pipefail
umask 077

if [ "$NODECOUNT" -ne 3 ] || [ "$INSTALLORANSCSMO" -ne 1 ] ||
   [ "$INSTALLORANSCSMOSIM" -ne 1 ] || [ "$OSCSMOUSECACHEDCHARTS" -ne 1 ] ||
   [ "$DONFS" -ne 1 ] || [ "$DOLOCALREGISTRY" -ne 1 ] ||
   [ "$KUBEDOMETALLB" -ne 0 ] || [ "$PUBLICADDRCOUNT" -ne 0 ]; then
    echo "ERROR: expected the three-node cached SMO-only parameter set" >&2
    exit 1
fi
for feature in INSTALLORANSC INSTALLONFSDRAN INSTALLOPEN5GS INSTALLVNC \
    BUILDOCUDU BUILDSRSRANPROJECT BUILDSRSRAN4G BUILDSRSLTE BUILDOAI; do
    if [ "${!feature}" -ne 0 ]; then
        echo "ERROR: $feature must be disabled for Phase 3" >&2
        exit 1
    fi
done
maybe_install_packages python3-yaml
mkdir -p "$OURDIR/phase3-smo"
python3 "$SRC/bin/smo-chart-preflight.py" --release "$OSCSMOVERSION" \
    --cache-dir "$OURDIR/phase3-smo/charts" --output "$OURDIR/phase3-smo/chart-lock.json"
