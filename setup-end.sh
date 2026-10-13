#!/bin/bash
SRC=$(cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=setup-lib.sh
. "$SRC/setup-lib.sh"
set -eo pipefail
"$SRC/bin/phase3-status.sh"
python3 "$SRC/bin/collect-phase3-provenance.py" --output "$OURDIR/phase3-smo/provenance.json"
echo "Phase 3 SMO setup completed on $NFQDN; certificate tests remain a separate step."
