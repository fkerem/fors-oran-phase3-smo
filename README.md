# POWDER Phase 3 SMO profile

This independent profile prepares a three-node OSC SMO deployment for
management and certificate lifecycle research. It derives from the official
`PowderProfiles/O-RAN` repository at
`e26d613e6ff69becd058b46bd55644ce18f06ca4`.

## Import into POWDER

1. Create a repository-backed profile using
   `https://github.com/fkerem/fors-oran-phase3-smo.git`.
2. Use branch `main`, entrypoint `profile.py`, and profile name
   `fors-oran-phase3-smo`. Record the portal's selected commit.
3. Instantiate `p3-smo-cert` in the project with the active three-d740
   reservation, at Emulab. Keep the defaults below.
4. Wait until all startup services show **Finished**, then review the health
   and provenance records on node-0 before launching certificate cases.

| Parameter | Default |
|---|---|
| Nodes / hardware | `3` / `d740` |
| Disk image | `UBUNTU22-64-STD` |
| OSC SMO | enabled, `g-release` |
| Cached charts / NTS simulators | enabled |
| Kubespray / Kubernetes | `v2.30.0` / `v1.34.3` |
| Helm | `3.18.4`, the selected Kubespray baseline |
| Container manager / network | Docker / Calico |
| NFS / local registry | enabled |
| RIC, SD-RAN, Open5GS, VNC, RAN builds | disabled |
| MetalLB / additional public IPs | disabled / `0` |
| Radios, spectrum, shared VLANs | none requested |

`f-release` is available only as a separately recorded compatibility baseline;
the Phase 3 run uses `g-release`. Ordinary node control-network addresses still
exist; zero additional IPs does not mean the nodes have no public SSH address.

## Compatibility changes and provenance

The original cached-simulator command used `f-release` regardless of the
selected release. This profile resolves every chart from the selected
repository and requires the exact version, URL and SHA256 in
`smo-chart-pins.json`. Missing or changed archives stop setup; there is no
uncached ChartMuseum fallback.

The cached ONAP archive contains identical duplicate `serviceAccount`
dependency rows in its TCA chart. `prepare-cached-chart.py` removes only
identical duplicate rows and their stale lock file. Conflicting duplicates
are rejected. The original and derived archive hashes, with the precise
changes, are recorded separately. Templates and dependency versions remain
unchanged.

The Helm post-renderer supports narrowly scoped PDB/CronJob API conversions,
rejects other removed Kubernetes APIs, and pins the stock `zoo-entrance`
and unversioned `curl` references to reviewed registry digests. It rejects any other
explicit or implicit `latest` image reference. Other versioned image tags
remain upstream selections; runtime image IDs are recorded after deployment.

The ONAP deployment plugin is checked out at an exact source commit and
patched to propagate failed Helm operations. Readiness checks also reject
failed releases, missing SDNC services, unready workloads, and pending PVCs.
These local rendering and regression checks do not establish that the older
Strimzi/ONAP stack works on a live Kubernetes 1.34 cluster. That compatibility
must be assessed in the allocated experiment.

Stock Strimzi 0.29.0's Fabric8 client rejects newer `/version` response
fields. The setup uses its documented `STRIMZI_KUBERNETES_VERSION` override
via the pinned chart's `extraEnvs`: the nine recognized fields come from the
actual server response, not a claimed older Kubernetes version. Missing,
malformed, mismatched or differently emulated versions stop setup. The raw
response hash, forwarded fields, additional fields and generated values hash
are recorded under `/local/setup/phase3-smo/compatibility/`.

The operator container is pinned to the stock image digest previously
observed on this experiment. Before ONAP installation it must report the
actual environment version, pass normal probes, and stay Ready without new
restarts for two two-minute reconciliation intervals. Kafka must also become
Ready and reconcile its current generation; deployed Helm releases alone
are insufficient. This does not change client libraries, chart dependencies,
RBAC, probes, Kafka version or certificate behavior, and it does not modify
the API response. Kubernetes 1.34 is outside Strimzi 0.29.0's listed tested
range; this is a recorded research compatibility configuration, not a claim
of upstream support. See the [override documentation](https://strimzi.io/docs/operators/0.29.0/configuring.html#assembly-using-the-cluster-operator-str)
and [tested version matrix](https://strimzi.io/downloads/).

No RIC, radio demo, subscriber fixture, or certificate fault case is launched.
Upstream credential-loading shell tracing is disabled; the completion step
reports health and writes provenance instead of emailing an admin token.
Keep all generated credentials and setup logs private.

The package helpers preserve their upstream inverted predicate contract
while handling it safely under strict shell failure checks. Installed
packages no longer abort preflight; genuine installer failures retain their
exit code. The disk bootstrap also requests only the intended LVM packages.
Regression tests execute the actual helper definitions with mocked package
commands, without sourcing bootstrap side effects or touching real disks.

The portal's `v1.34.3` selection remains unchanged. Only the Kubespray
adapter emits the bare string `"1.34.3"` required by its version comparisons;
Helm/chart inputs retain the selected version. Generated overrides are
rebuilt rather than appended on retries. A clean existing Kubespray checkout
at the configured repository/ref is reused; unexpected source edits or a
different revision stop setup instead of deleting or resetting the checkout.
An explicit Kubespray revision is required; there is no mutable HEAD fallback.

## Inspect the deployment

On node-0:

```sh
/local/repository/bin/phase3-status.sh
cat /local/setup/phase3-smo/chart-lock.json
cat /local/setup/phase3-smo/provenance.json
```

Read setup failures in `/local/logs/setup.log` and
`/local/logs/setup-oran-smo.sh.log`. ONAP child Helm logs are also under
`~/.local/share/helm/plugins/deploy/cache/onap/logs/`.
A failure stops setup and leaves its evidence; it does not silently upgrade
components or uninstall the deployment. The completion marker appears only
after the readiness gate passes.

For SMO UI access, first run this on node-0:

```sh
kubectl -n onap port-forward --address 127.0.0.1 service/sdnc-web-service 8443:8443
```

Then run this locally, substituting the node's portal-provided SSH hostname:

```sh
ssh -N -L 8443:127.0.0.1:8443 fors@NODE_0_HOSTNAME
```

Open `https://localhost:8443`. Read the chart-provided credentials locally on
the allocated node without retaining their values in evidence. Use the
observed TLS certificate deliberately; the dashboard's profile certificate
is separate from the later synthetic certificate cases.

## Certificate experiment prerequisite

The NTS simulators are the SMO connectivity baseline. The earlier Python
certificate notifier belongs to a separate PyNTS/O-RU M-plane implementation.
Its source reproduction pin is
`12124176a491a873eb41423200c7f7add9ea99d4`; this profile does not build or run it.

Before that separate runtime test, establish a TLS management session,
record its configured keystore/truststore paths and CA roles, and obtain a
scheduled leaf-notification positive control. Use isolated synthetic
certificates for healthy, leaf-expiring, CA-expiring, CA-expired, and combined
cases. The original scheduler runs daily and polls hourly: allow roughly
25 hours after simulator startup. Do not change host clocks or shorten the
scheduler while claiming original-scheduler evidence.

## Local checks

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
for script in setup-*.sh bin/*.sh; do bash -n "$script" || exit; done
shellcheck -x -S error setup-lib.sh setup-disk-space.sh setup-kubespray.sh setup-driver.sh setup-oran-smo.sh setup-phase3-preflight.sh setup-end.sh bin/phase3-status.sh bin/kubespray-bootstrap-lib.sh
```

See `NOTICE.md` for upstream attribution and retained license notices.
