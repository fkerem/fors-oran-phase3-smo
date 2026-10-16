#!/bin/bash
SRC=$(cd -- "$(dirname -- "$0")" && pwd)
resume_before_smo=0
resume_after_onap=0
resume_after_onap_deploy=0
resume_after_dmaap=0
dmaap_review=
expected_slice=
case "$#:$1" in
    0:) ;;
    3:--resume-before-smo)
        [ "$2" = '--expected-slice' ] && [ -n "$3" ] || exit 2
        resume_before_smo=1; expected_slice=$3 ;;
    3:--resume-after-onap)
        [ "$2" = '--expected-slice' ] && [ -n "$3" ] || exit 2
        resume_after_onap=1; expected_slice=$3 ;;
    3:--resume-after-onap-deploy)
        [ "$2" = '--expected-slice' ] && [ -n "$3" ] || exit 2
        resume_after_onap_deploy=1; expected_slice=$3 ;;
    5:--resume-after-dmaap)
        [ "$2" = '--expected-slice' ] && [ -n "$3" ] && [ "$4" = '--review-file' ] && [ -n "$5" ] || exit 2
        resume_after_dmaap=1; expected_slice=$3; dmaap_review=$5 ;;
    *) echo 'Usage: setup-driver.sh [--resume-before-smo|--resume-after-onap|--resume-after-onap-deploy --expected-slice URN] or --resume-after-dmaap --expected-slice URN --review-file PATH' >&2; exit 2 ;;
esac
umask 077
# The allocation prepares /local/setup before invoking this driver.
exec 9>/local/setup/phase3-driver.lock
flock -n 9 || { echo 'Another setup/recovery holds the driver lock' >&2; exit 1; }
# shellcheck source=setup-lib.sh
. "$SRC/setup-lib.sh"
set -eo pipefail
umask 077

if [ -f "$OURDIR/setup-driver-done" ]; then
    [ "$resume_before_smo" -eq 0 ] || { echo 'Recovery refused: setup already completed' >&2; exit 1; }
    echo "Phase 3 setup already completed"
    exit 0
fi
run_stage() {
    echo "Starting $1"
    "$SRC/$1" 2>&1 | tee "/local/logs/$1.log"
}
if [ "$resume_after_dmaap" -eq 1 ]; then
    [ "$(geni-get slice_urn)" = "$expected_slice" ] && [ "$HOSTNAME" = node-0 ] || exit 1
    PHASE3_RECOVERY_LOCK_FD=9 python3 "$SRC/bin/phase3-dmaap-recovery.py" --continue \
        --expected-slice "$expected_slice" --review-file "$dmaap_review"
    "$SRC/setup-oran-smo.sh" --resume-after-onap 2>&1 | \
        tee "/local/logs/phase3-post-dmaap-resume-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
    run_stage setup-end.sh
    touch "$OURDIR/setup-driver-done"
    exit 0
fi
if [ "$resume_after_onap_deploy" -eq 1 ]; then
    [ "$(geni-get slice_urn)" = "$expected_slice" ] && [ "$HOSTNAME" = node-0 ] || {
        echo 'Post-deployment continuation allocation mismatch' >&2; exit 1;
    }
    PHASE3_RECOVERY_LOCK_FD=9 PHASE3_RESUME_EXPECTED_SLICE="$expected_slice" \
        "$SRC/setup-oran-smo.sh" --resume-after-onap-deploy 2>&1 | \
        tee "/local/logs/phase3-post-deploy-resume-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
    run_stage setup-end.sh
    touch "$OURDIR/setup-driver-done"
    exit 0
fi
if [ "$resume_after_onap" -eq 1 ]; then
    [ "$(geni-get slice_urn)" = "$expected_slice" ] && [ "$HOSTNAME" = node-0 ] || {
        echo 'Post-ONAP continuation allocation mismatch' >&2; exit 1;
    }
    "$SRC/setup-oran-smo.sh" --resume-after-onap 2>&1 | tee /local/logs/phase3-post-onap-resume.log
    run_stage setup-end.sh
    touch "$OURDIR/setup-driver-done"
    exit 0
fi
if [ "$resume_before_smo" -eq 1 ]; then
    PHASE3_RECOVERY_LOCK_FD=9 python3 "$SRC/bin/phase3-predeployment-recovery.py" \
        --expected-slice "$expected_slice" --apply
    run_stage setup-oran-smo.sh
    run_stage setup-end.sh
    touch "$OURDIR/setup-driver-done"
    exit 0
fi
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
