# POWDER Phase 3 SMO profile

## New experiments: fresh-start compatibility baseline

**Update/Pull this repository-backed profile in POWDER and compare the full
selected commit with the published `main` before instantiation.** Pushing to
GitHub does not update a portal-cached profile revision. Keep the three-d740
defaults; no radio, spectrum, shared VLAN or extra public IP is needed.
Reinstantiating an old experiment can retain its historical revision: select
the refreshed profile revision deliberately, rather than replaying the old pin.

New installs now use a separate, fail-closed fresh renderer. It does not run
the old experiment's recovery receipts or rotate certificates in an existing
installation. Before ONAP creation it:

- Pins stock readiness 3.0.1, AAF config/core 2.1.23, agent 2.1.20 and Cassandra
  2.1.23 to exact linux/amd64 manifest digests. A read-only readiness wrapper
  verifies the original source SHA-256 and changes only the Job-completion
  predicate: find `Complete=True`, independent of condition order; do not
  accept `Failed=True` or `Suspended=True`. Stock API authentication, argument
  handling, retry duration and timeout behavior remain unchanged.
- Creates a new lab root, issuing intermediate and AAF server certificate
  privately for this allocation. The issuer DN `intermediateCA_9` is retained
  for CADI identity compatibility, **not** its old key, certificate or trust.
  The server's service SANs and store aliases/formats are retained. Root and
  intermediate lifetimes exceed the stock one-year issued-leaf lifetime.
  The stock public-truststore password `changeit` is retained for consumer
  compatibility; private key stores use a new random password. This is a
  laboratory compatibility baseline, not production PKI hardening.
  The normal startup generator explicitly exports both private-key stores
  with `PBE-SHA1-3DES`, SHA-1 MAC and 50,000 encryption/MAC iterations.
  X.509 certificate signatures remain SHA-256. No Python/OpenSSL defaults
  are inherited: Jammy cryptography 3.4 with OpenSSL 3 otherwise produces a
  SHA-256 MAC rejected by this pinned AAF Java runtime. Both Jammy's system
  stack and the modern development stack rehearse against the exact image
  in CI. This fix is automatic for new installs; no recovery flag is needed.
- Rehearses the exact stock AAF bootstrap offline using its digest-pinned
  image, then installs the generated server/signing stores and encrypted
  property references before any server starts. Both JKS and PKCS12 trust
  stores are created with that image's actual Java keytool. The rehearsal
  container has no network or published ports. Original initializer output
  stays in a private file, not Pod logs or CI artifacts.
  A loopback-only Java TLS rehearsal checks both store formats and positive
  hostname validation, with wrong-hostname and untrusted-root rejection.
  Offline regression tests also reject an expired intermediate beneath a
  still-current leaf; none of these controls is a live AAF retrieval claim.
- Supplies all rendered AAF agent trust mounts with the new lab root and
  uses immutable, content-addressed helper ConfigMaps and an immutable
  runtime Secret. The encrypted root private key remains host-private and
  is excluded from the Pod Secret. Existing generated material is never
  silently overwritten or regenerated. PKI directories are mode 0700 and
  generated files are 0600.
- Resolves the newly allocated `node-2` worker's current UID and requires it
  to be Ready/schedulable. The three database StatefulSets and their hostPath
  PVs receive matching placement constraints before first installation.
  A read-only SSH probe to the current logical worker verifies its allocation
  identity and refuses noncanonical or nonempty backing directories before
  first install. It creates, deletes and migrates nothing on the peer.
  This is not data migration or reuse of a previous allocation's disks.

Every new ONAP Job uses `backoffLimit: 0` and `restartPolicy: Never`. Failures
stop acceptance rather than replaying initializers. The post-ONAP gate
requires reconciled controllers, Complete Jobs, a hostname-validated AAF TLS
session presenting this allocation's exact leaf, and successful actual AAF
agent initializers. Only then may non-RT RIC and NTS installation continue.
The final full-SMO provenance gate still controls the completion marker.

The private receipts are under `/local/setup/phase3-smo/fresh-start/`:
`rehearsal.json`, `context.json` and, after live ONAP acceptance,
`onap-acceptance.json`. Do **not** upload that directory: it also holds keys,
passwords and private bootstrap logs. `bin/phase3-status.sh` prints only a
bounded receipt status, not the private payloads. A partially started install
is a separate recovery review; re-running fresh preparation refuses existing
ONAP workloads/claims and never deletes data or resets failed Jobs.

Local regression/render checks and the isolated Linux CI bootstrap do not
prove a complete new experiment. Actual AAF retrieval, full ONAP/SMO/NTS
readiness, and the later scheduled notification positive control must still
pass on the new allocation. No certificate fault cases or PyNTS runtime are
started automatically. The operator's existing full-hour stability gate is
retained, so startup is not expected to be immediate.

## Explicit recovery before any SMO deployment

For the reviewed isolated-rehearsal `HmacPBESHA256 not available` failure
only, audit with `python3 bin/phase3-predeployment-recovery.py --expected-slice URN`.
After reviewing the audit and updating to a CI-tested profile commit, use
`/local/repository/setup-driver.sh --resume-before-smo --expected-slice URN`.
This exclusive-lock path checks allocation/Node identities, completed
infrastructure, absent SMO/operator namespaces/releases/volumes, and empty
backing directories. It preserves every failed PKI artifact and copies the
old logs/receipts to a mode-0700 `predeployment-recovery-*` directory with a
private hash ledger. Nothing is deleted. A new undeployed PKI trial then
runs through the ordinary SMO stage and every live acceptance gate.
Disk, NFS, SSH and Kubernetes provisioning are not replayed. Existing SMO
state or a different failure refuses this recovery. Do not upload archives.

## Explicit stalled-Pod and held-Job recovery

`bin/phase3-statefulset-recovery.py` and `bin/phase3-held-job-resume.py` audit
by default. Both require `--baseline-state`, `--expected-slice-urn`,
`--expected-commit` and a new `--work-dir`. Mutation additionally requires
`--apply`, `--approved-audit` and its `--approved-audit-sha256`; receipts are
mode-specific and expire after 30 minutes. Keep baseline/receipts/traces private.

The baseline schema is `phase3-scoped-v1`: the experiment slice, image-lock
SHA-256, prior protected PVC/PV/Secret-data/excluded-Job snapshot, six held Job
UIDs/specifications, and three original stalled Pods with owner/Node identities
and backing PVC/path. Derive it from retained evidence, not arbitrary current
objects. Audit records preserve exact current contracts for approval.

Rollout accepts only `onap-mariadb-galera`, `onap-policy-mariadb` and
`onap-sdnrdb-master`, one replica each, with unstarted mains and reviewed stock
initializers. Backing hostPath directories must still be empty, canonical,
correctly owned and on the original node. Only a hostname nodeSelector may be
added to each template; document this operational override and retain it during
later Helm reconciliation. No PV/PVC, image, security, probe or credential
change is allowed. Exact UID/resource-version guarded normal Pod deletion is
followed by a 20-minute startup/five-minute stability gate and live positive
controls; there is no forced deletion, automatic second replacement or rollback
of database contents. A new nonempty directory requires separate review.

Job resume unsuspends only the existing reviewed UIDs after exact dependency
controllers are reconciled/Ready or dependency Jobs Complete. It serializes
activation, preserves completed Jobs, retains zero retries and Never restart,
and stops on failure, duplicate Pod execution or drift. These are retry-disabled
controls, not an exactly-once guarantee. A 60-minute monitoring timeout does
not kill an initializer. Exit 0 means the scoped action/audit passed, 2 means
dependencies remain blocked, and 1 means a guard/error stopped orchestration.

Neither helper reinstalls Helm releases, replays AAF SMS/SDNR Jobs, renews
certificates, disables TLS validation, changes clocks, invokes post-ONAP
continuation or writes completion markers. Full SMO and certificate research
acceptance remain separate gates.

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
restarts for a full hour. Its existing chart interface now supplies
`JAVA_OPTS=-Xms256m -Xmx512m`, retaining the 1Gi container memory request
and limit. This explicit heap cap avoids relying on the old JVM's observed
oversized percentage-based selection; Java, the stock image and normal
probes are unchanged. Existing unrelated `extraEnvs` are preserved;
conflicting JVM settings are rejected. Acceptance verifies the actual JVM
arguments, cgroup limit/usage and memory-event counters every 15 seconds.
Three consecutive samples at or above 90 percent, any OOM/heap error,
restart, identity change or loss of readiness stops acceptance. Samples and
failure receipts remain private. The earlier four-minute receipt is historical,
not sufficient for current heap-recovery acceptance.

For an already deployed ONAP cluster, the wait command's
`--require-onap-kafka` flag also requires continuously reconciled, Ready
Kafka with unchanged identities/generations throughout the hour. A fresh
installation checks the operator before creating ONAP. Kafka must also become
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

### Guarded image-availability recovery

`image-availability-lock.json` records five exact old image references,
reviewed source manifests and the linux/amd64 platform. Four replacements
use the same application version from Bitnami Legacy. The exporter uses the
official Prometheus `0.12.1` package instead of the unavailable Bitnami
Debian build; this is a packaging change, not binary-equivalence evidence.
These archived packages are a compatibility baseline, not security hardening.
See the [Bitnami migration notice](https://github.com/bitnami/containers/issues/83267).

The post-renderer maps only those exact references to the existing
LAN cache. `bin/phase3-image-preflight.py` audits all supplied live/rendered
manifests, including init containers and Jobs, without copying by default.
It fails on unavailable artifacts, ambiguous architecture selections or
digest/config mismatches. Its explicit `--cache` mode requires the existing
LAN-only listener and the reviewed Skopeo package version. Copies preserve
digests, use digest-derived tags and refuse unexpected tag overwrites; it
does not install packages, restart Docker or add listeners.

The pinned Ubuntu Skopeo does not provide the newer `--preserve-digests`
option. Its supported native-copy command requests no format conversion or
automatic retry and records the resulting digest with `--digestfile`.
That digest, the cached tag, manifest bytes and config must all match the
reviewed source before any receipt is accepted. A rewrite stops recovery;
it never updates the image lock to accept an alternate artifact. See the
[exact-version copy interface](https://github.com/containers/skopeo/blob/v1.4.1/docs/skopeo-copy.1.md).

The pinned Skopeo installer refuses existing-package upgrades/removals.
The isolated rehearsal uses only owned temporary Docker resources and
synthetic credentials, never production Secrets or volumes. It verifies
all five application versions and the exporter's binary hash, retaining the
Elasticsearch chart's UID/fsGroup 1001 instead of incorrectly forcing its
version probe to UID 10001. The other version probes and isolated database/
exporter positive control use UID 10001. It checks the
unchanged chart command/security/probes, `/metrics` and authenticated
`mysql_up=1`. No ports are published. Successful temporary resources are
removed; failures retain private diagnostic records/resources. This does
not rehearse the full multi-node Galera topology.

`bin/phase3-image-recovery.py` audits by default. Its explicit `--apply`
requires the expected experiment/revision, a successful one-hour operator
gate, cache/rehearsal receipts and both worker pull receipts. It compares
retained subcharts with the pinned archive, renders four targeted Helm
upgrades and rejects all changes except approved image references and the
six exact eligible Jobs' hold/single-attempt controls. Storage identities,
application Secret data and excluded Job specs/UIDs are preserved; Helm's
own release-storage Secrets are recorded by the normal Helm operation.

The six eligible Jobs require complete retained Pod/init-container history
with no externally modifying command execution. The SDNC configuration
initializer is allowed only when its output is Pod-local emptyDir storage.
AAF preload and SDNR initialization are explicitly excluded, not assumed
safe. Recreated candidates start suspended with `backoffLimit: 0` and
`restartPolicy: Never`; dependency readiness controls activation. UID and
resource-version tests protect deletion/activation, and a failed attempt
stops without implicit replay, dependency upgrade or destructive rollback.
Successful Jobs are never recreated.

Only the four selected ONAP child releases are upgraded in existing
experiments; the umbrella plugin and completed disk/Kubernetes/worker setup
must not be rerun. `/local/repository/setup-oran-smo.sh --resume-after-onap`
is a separate continuation for fresh-baseline installs with retained PKI and
ONAP acceptance receipts, gated by a currently healthy accepted operator,
all ONAP Jobs Complete, Ready controllers/Kafka and Bound storage. It skips
Strimzi/ONAP reinstallation and verifies retained continuation chart hashes.
An audit or selected-Job success does not attest to the full SMO baseline.
Actual application, rehearsal and readiness outcomes must be taken from
the allocated experiment's private receipts, not these local tests.

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
