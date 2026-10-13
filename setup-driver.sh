#!/bin/bash
SRC=$(cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=setup-lib.sh
. "$SRC/setup-lib.sh"
set -eo pipefail
umask 077

if [ -f "$OURDIR/setup-driver-done" ]; then
    echo "Phase 3 setup already completed"
    exit 0
fi
run_stage() {
    echo "Starting $1"
    "$SRC/$1" 2>&1 | tee "/local/logs/$1.log"
}
run_stage setup-ssh.sh
run_stage setup-disk-space.sh
if [ "$HOSTNAME" = "node-0" ]; then
    for stage in setup-phase3-preflight.sh setup-nfs-server.sh setup-nginx.sh \
        setup-ssl.sh setup-kubespray.sh setup-kubernetes-extra.sh setup-oran-smo.sh setup-end.sh; do
        run_stage "$stage"
    done
else
    run_stage setup-nfs-client.sh
fi
touch "$OURDIR/setup-driver-done"
