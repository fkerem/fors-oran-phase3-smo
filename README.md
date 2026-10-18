# POWDER Phase 3 SMO profile

## SMS backend custody gate

New allocations mount their own public lab root into the three quorum clients
before the first SMS/Vault startup. SMS, quorum, Vault 1.3.3 and Consul 1.7.1
use exact reviewed image digests. This fixes the quorum clients' packaged-root
mismatch; it does not disable hostname/certificate verification or add mutual
TLS support to the stock quorum binary.

An initialized Vault can be sealed while all its Pods say Ready. The stock SMS
process initially holds bootstrap authority in memory: restarting it before
the three encrypted shards **and** SMS AppRole credentials are persisted can
lose that handoff. Merely fixing TLS afterward does not recreate those keys.
Do not restart SMS/quorum to try to clear this state, reinitialize Vault, reset
Consul/PVC contents, or regenerate root authority. Preserve the allocation and
seek a separate recovery review. A new clean allocation is a separate choice.

`python3 bin/phase3-sms-backend.py audit --expected-slice URN --output NEW_JSON
--preserve-directory NEW_PRIVATE_DIRECTORY` preserves metadata and private
logs/manifests without recovery. Run it as one shell command. Exit 2 means
audit-only/blocked, not permission to preload. It does not retrieve live shard
or backend credential values; raw logs remain private.

Fresh setup automatically rehearses the pinned binaries in a loopback-only
Docker fixture, checks that all five SMS/Vault/quorum backing directories are
empty, and installs a separate immutable public-trust ConfigMap. After initial
ONAP deployment, `wait-fresh` requires the existing one-hour operator gate,
verified SMS TLS, three distinct cryptographically validated persisted recovery
sets, an unsealed Vault, and persisted working scoped AppRole credentials.
Normal first-use SMS bootstrap is limited to one journaled GET; no domain or
secret preload POST is made. A failure never repeats that bootstrap request,
resets data, or fabricates completion. Authentication tokens are short-lived,
kept private and revoked after metadata checks; no root privileges are added.
The internal Vault metadata session retains the chart's existing HTTP
transport; this compatibility gate is not backend transport hardening.
The stock quorum binary retains its normal polling; a failed gate stops setup,
not those running containers, and is not an exactly-once execution guarantee.

Acceptance binds allocation/Pod/PVC/PV identities, image/trust pins and private
material bindings, and observes 120 restart-free seconds. The receipt is
`fresh-start/sms-backend-acceptance.json`; status and continuation recheck its
bindings. Missing/incomplete custody, drift, restart or timeout stops setup.
`wait-fresh` refuses retained contexts without the new empty-storage proof.
Do not invoke it as a recovery command for an initialized old allocation.

The exact-image fixture covers clean bootstrap and restart/reseal recovery,
insufficient quorum, missing/invalid/duplicate recovery material, interruptions
before shard or AppRole custody, and wrong/missing CA, hostname and expiry
rejection. It uses synthetic material and disposable storage, no live API and
no published ports. Fixture ownership is not a live filesystem-permissions
equivalence claim, and these tests do not prove a complete new deployment.

Backend acceptance is a prerequisite for the separate guarded preload gate
below. It alone grants no application-write or full SMO acceptance.

## Fresh-only automatic SMS preload gate

New profiles repair SMS's served public chain using this allocation's existing
root and intermediate. A crypto-only, digest-pinned initializer validates the
issued leaf's chain, server purpose, validity and `aaf-sms.onap` hostname before
replacing any appended historical intermediate. It receives public trust only;
it never invokes AAF or mounts a signing key. The SMS server image is also
digest-pinned. A server-only role label narrows `aaf-sms` so preload Pods can
never become its TCP/10443 endpoints. The immutable Deployment selector,
databases, PVCs and packaged historical certificate Secret are not changed.

New contexts carry `sms_preload_contract: 1`. Preparation qualifies the guarded
client offline and creates its immutable code ConfigMap and scoped ServiceAccount,
Role and RoleBinding after the namespace exists. The fresh renderer replaces
only the reviewed preload Job with the guarded client, initially suspended.
Immediately after backend acceptance, setup runs
`python3 bin/phase3-sms-preload.py run-fresh --context PATH --timeout 600`
under the inherited driver lock (fd 9). This gate controls the first attempt;
it is not a recovery or replay command.

The reviewed inputs contain six `has` secrets and fourteen `osdf` secrets:
two domain POSTs plus twenty secret POSTs, at most **22 POST attempts** total.
The VFC spelling typo is corrected; the two `pciHMS` empty string literals
are retained exactly. Every target must be absent before writing. There are
no POST retries, no overwrite and no missing-only reconciliation. Existing,
partial or uncertain state aborts the attempt for review. A durable allocation
attempt latch and a ConfigMap journal prevent ordinary driver/Pod restart from
replaying it. This is controlled single-writer operation, not protection
against a hostile concurrent writer racing the absence checks.

The gate requires current backend/TLS/input/Job identity checks and private
postcondition comparison before publishing `sms-preload-acceptance.json`.
ONAP waiting, continuation, status and provenance reverify current preload
acceptance; neither Job Complete nor annotations alone establish success.
Full SMO readiness and certificate testing retain their separate later gates.

Retained contexts without this contract keep their existing safety hold.
The old allocation is not replayed or automatically upgraded. After publication,
start a separate new experiment using the refreshed profile revision.
Do not manually unsuspend a legacy Job or invoke the stock writer.
The pinned stock preload binary retries writes, can exit zero
after write failures, continues to secret writes after an `existing domain`
response, and falls back to insecure TLS when its CA file cannot be read.
A log-only kill wrapper is not a request-level interlock. ONAP acceptance
continues to refuse the retained hold, including a manually unsuspended or
completed legacy Job. Existing or uncertain effects require a separate recovery
review; never reset the database or force a completion marker.

`python3 bin/phase3-sms-rehearsal.py --directory NEW_PRIVATE_DIRECTORY` runs
the exact-image chain controls and characterizes the preload binary against
synthetic data. Two containers share only a `--network none` container's
loopback; no ports are published and no live AAF/SMS request is sent. Both
Python crypto stacks run these controls in CI and fresh preparation. A passing
rehearsal explicitly records `live_preload_authorized: false`.
`python3 bin/phase3-sms-preload-rehearsal.py --directory NEW_PRIVATE_DIRECTORY`
qualifies the guarded client separately with synthetic inputs. Fresh preparation
records this as `sms_preload_rehearsal` and verifies its qualification before use.

For the existing held allocation only, `bin/phase3-sms-repair.py --audit` and
`--apply` accept `--expected-slice`, `--rehearsal RESULT_JSON`, and
`--review-file NEW_PRIVATE_PATH`. This distinct repair never replays or
replaces a Job and does not loosen the old main-never-ran refusal. Audit binds
UID/resource versions, templates, current PKI, rehearsal and protected storage
identities. Apply expires after 30 minutes, holds the driver lock, preserves
private logs/manifests with hashes, rolls only the SMS server, verifies two
minutes of restart-free readiness and root-only hostname TLS, then narrows
the Service. Normal AAF leaf retrieval on the new Pod is recorded; the CA is
not rotated. Read-only expected-domain metadata is inspected afterward, but
an empty list or backend HTTP error is **not** proof of absence. Any uncertainty
keeps preload held. Failure stops without an automatic rollback/retry.

## DMAAP guarded provisioning and retained-allocation recovery

New contexts use `dmaap_contract=1`. The chart's provisioning Job is rendered
suspended with a digest-pinned Python client, `restartPolicy: Never`, zero
backoff, a 600-second deadline and distinct labels that do not match the
DMAAP server Service. It activates only after current SMS backend and guarded
preload acceptance. An isolated exact-image rehearsal is mandatory before
deployment; its generated PKI, database and logs remain private.

The allowlist is the six pinned input files: one `dmaap`, one location, one
MR cluster, and three topics with five supplied client relationships. All
eight collection catalogs must be empty and the singleton must match the
qualified first-install defaults. There is no partial reconciliation.
Durable intent and a Kubernetes resourceVersion CAS precede every request.
There are at most **six client POST attempts**, not an exactly-once server
guarantee or a bound on downstream AAF/MR writes. Redirects, conflicts,
malformed/lost responses, timeouts, changed inputs and uncertain attempts
stop without retry, overwrite, rollback or replay. Supplied fields and
relationships are independently read back; Job Complete is insufficient.
The 2.0.8 Topic response's boolean-to-string transaction flag mapping is
explicitly version-qualified, not a general type-coercion allowance.

For an already-running stock Job, the older `phase3-onap-recovery.py` keeps
its **main-never-ran** refusal. A separate recovery requires complete logs
from process start, the exact image/script/process, zero restarts, only
failed pre-write readiness GETs, no configuration override, authoritative
fresh catalogs, current SMS receipts, and the original protected inventory.
Never fix its curl trust in place: that would enable its unbounded writer.
From a separately staged, tested checkout on node-0:

```sh
python3 bin/phase3-dmaap-rehearsal.py --directory /var/tmp/UNIQUE-PRIVATE-QUALIFICATION
python3 bin/phase3-dmaap-recovery.py --audit --expected-slice "$slice" \
  --qualification /var/tmp/UNIQUE-PRIVATE-QUALIFICATION/result.json \
  --review-file /local/setup/phase3-smo/fresh-start/UNIQUE-dmaap-review.json
# Review the private metadata and original evidence before this command.
python3 bin/phase3-dmaap-recovery.py --apply --expected-slice "$slice" \
  --qualification /var/tmp/UNIQUE-PRIVATE-QUALIFICATION/result.json \
  --review-file /local/setup/phase3-smo/fresh-start/UNIQUE-dmaap-review.json
./setup-driver.sh --resume-after-dmaap --expected-slice "$slice" \
  --review-file /local/setup/phase3-smo/fresh-start/UNIQUE-dmaap-review.json
```

Replace the placeholders with new private paths; do not reuse an attempt.
The review expires after 30 minutes. Apply preserves logs/manifests/inputs,
suspends the exact original Job, confirms its Pod is gone, then uses an exact
UID/resourceVersion deletion precondition before creating one held guarded
replacement. The original broad review is retained unchanged; a separate
transition receipt binds that one replacement and the reviewed code. Failed
or uncertain attempts require another review, not re-running these commands.
Existing PKI, accepted SMS state, completed Jobs and infrastructure are not
recreated. The continuation uses the normal ONAP and remaining-SMO gates;
it never forces a Finished marker. Full SMO readiness and the later isolated
PyNTS scheduled positive control remain separate from this startup repair.

### Verification-only closeout of the inspected completed comparator failure

This is **not** permission to adopt an arbitrary uncertain attempt. The explicit
`--audit-completed` / `--accept-completed` modes require the preserved failure
from the inspected host-comparator revision, one succeeded zero-restart Pod,
six attempted/observed requests, the same suspended completed Job, unchanged
private journal and archives, current SMS/PKI/inventory bindings and full API
readback. The DMAAP transport permits GET only. Scoped SMS verification still
uses temporary Vault login/revoke authentication; it does not replay preload.

From the separately tested checkout, with a new private review path:

```sh
python3 bin/phase3-dmaap-recovery.py --audit-completed --expected-slice "$slice" \
  --review-file /local/setup/phase3-smo/fresh-start/UNIQUE-postexecution-review.json
# Review the private binding and the exact allowed verifier-code changes.
python3 bin/phase3-dmaap-recovery.py --accept-completed --expected-slice "$slice" \
  --review-file /local/setup/phase3-smo/fresh-start/UNIQUE-postexecution-review.json
python3 bin/phase3-dmaap-recovery.py --verify
# Use the ORIGINAL DMAAP recovery review for the existing continuation interface.
./setup-driver.sh --resume-after-dmaap --expected-slice "$slice" \
  --review-file /local/setup/phase3-smo/fresh-start/ORIGINAL-dmaap-review.json
```

The 30-minute review authorizes a separate exclusive post-execution receipt;
it never changes the uncertain journal, unsuspends/replaces the completed Job,
creates ordinary DMAAP acceptance, or retries a provisioning request. Failed or
interrupted closeout keeps its latch and requires review, not re-running accept.
Status distinguishes this verification from the normal fresh-run acceptance.
The receipt carries the original reviews/transition and exact code changes;
it does not rebase historical bindings. Fresh contexts retain the ordinary gate
and uncertain attempts are never closed automatically. Verified postconditions
do not establish exactly-once execution or total downstream write counts.

## New experiments: fresh-start compatibility baseline

### Internal-only Kong proxy and retained recovery

Both supported releases now generate `kong.proxy.type=ClusterIP`. New contexts
set `kong_proxy_contract=1`; the first Service/endpoint identity is accepted
after non-RT RIC readiness and reverified before NTS and during provenance.
The proxy retains ports 80/443 and the existing selector. No MetalLB, extra
public IP, NodePort or Kong Admin change is introduced. This is startup/access
compatibility, not a certificate-runtime or vulnerability assessment.

Retained allocations do not acquire this contract or regenerate their values.
For the inspected revision-2 Kong readiness timeout only, stage the reviewed
revision separately and retain both clean historical checkouts (`f952ce5` for
DMAAP acceptance; `26480b1` for O-RU acceptance):

```sh
python3 tools/phase3-kong-proxy.py audit --expected-slice "$slice" \
  --accepted-dmaap-checkout /var/tmp/ACCEPTED-F952CE5-CHECKOUT \
  --accepted-oru-checkout /var/tmp/ACCEPTED-26480B1-CHECKOUT \
  --blocker-archive /local/setup/phase3-smo/nonrtric-kong-lb-blocker-REVIEWED \
  --blocker-archive-sha256 REVIEWED_64_CHARACTER_LEDGER_SHA256 \
  --review-file /local/setup/phase3-smo/fresh-start/UNIQUE-kong-proxy-review.json
# Review the preserved blocker, exact one-field manifest delta and dry-run.
python3 tools/phase3-kong-proxy.py apply --expected-slice "$slice" \
  --accepted-dmaap-checkout /var/tmp/ACCEPTED-F952CE5-CHECKOUT \
  --accepted-oru-checkout /var/tmp/ACCEPTED-26480B1-CHECKOUT \
  --review-file /local/setup/phase3-smo/fresh-start/UNIQUE-kong-proxy-review.json
python3 tools/phase3-kong-proxy.py continue --expected-slice "$slice" \
  --accepted-dmaap-checkout /var/tmp/ACCEPTED-F952CE5-CHECKOUT \
  --accepted-oru-checkout /var/tmp/ACCEPTED-26480B1-CHECKOUT
```

Audit creates a separate hashed ClusterIP override, leaving original values,
charts, contexts, receipts and failed latches untouched. Reviews expire after
30 minutes. Select the previously reviewed blocker directory and ledger hash
explicitly; audit never chooses the first glob result. Byte-identical copies
are preserved, independently verified and bound into the review. Conflicting
matching contents, a wrong path/hash, tampering or a changed copy set block
apply; later verification rechecks every bound copy. Do not delete evidence to
make a cardinality check pass. Archive-selection flags are audit-only; apply
uses the selection already bound into its review.

Apply retains a durable intent latch and sends one type-only JSON
Patch with Service UID/resourceVersion/type preconditions. Kubernetes clears
LoadBalancer-only allocations; any additional change is refused. It then runs
one no-hook Helm reconciliation using the original artifacts plus the separate
override. Service UID/ClusterIP, ports, selector, existing Pods and endpoints
must remain bound. Lost write responses, failures or drift stop without retry,
overwrite, status patch, automatic rollback or readiness bypass.

Only separate current acceptance permits the first, unattempted NTS install and
normal full-SMO checks. No infrastructure, SMS, DMAAP or completed Job is replayed.
Completion markers appear only after normal readiness and current acceptance.
Raw Helm values, API bodies, initializer logs and recovery material stay private.

For optional proxy access, bind only to node-0 loopback and tunnel it over SSH:

```sh
# On node-0:
kubectl -n nonrtric port-forward --address 127.0.0.1 service/oran-nonrtric-kong-proxy 18080:80 18443:443
# Locally, substitute the allocated node-0 hostname:
ssh -N -L 18080:127.0.0.1:18080 -L 18443:127.0.0.1:18443 fors@NODE_0_HOSTNAME
```

The unauthenticated root-response check establishes listener reachability only.
It neither validates authenticated routes nor establishes TLS trust. The proxy
and SDNC dashboard certificates remain distinct from later certificate cases.

### O-RU cross-namespace readiness

New contexts set `oru_readiness_contract=1`. After ONAP acceptance and before
non-RT RIC installation, the profile creates the dedicated
`onap/phase3-oru-aaf-readiness` Role and RoleBinding. Only
`nonrtric:oran-oru-app-read` receives ONAP Pod listing, GET of the three current
AAF ReplicaSet status resources and GET of the three AAF Deployments by name.
No Secrets, exec, write, watch or cluster-wide grant is added. The app shares
this ServiceAccount token and therefore retains those metadata reads. The
ineffective chart-local `oran-read` reference is left unchanged; no broad Role
is manufactured to satisfy it. Changed AAF owner chains require review.

Retained allocations never enter the automatic fresh mode. Stage the tested
public revision separately and retain the clean `f952ce5` acceptance checkout:

```sh
python3 tools/phase3-oru-readiness.py audit --expected-slice "$slice" \
  --accepted-checkout /var/tmp/ACCEPTED-F952CE5-CHECKOUT \
  --review-file /local/setup/phase3-smo/fresh-start/UNIQUE-oru-review.json
# Review the private binding, then use the same arguments with action apply.
# Use --allow-readiness-only-restarts on audit/apply ONLY after explicit review
# of continuous full readiness logs and the pinned read-only helper source.
python3 tools/phase3-oru-readiness.py continue --expected-slice "$slice" \
  --accepted-checkout /var/tmp/ACCEPTED-F952CE5-CHECKOUT
```

Reviews expire after 30 minutes. Apply retains an exclusive latch, creates
only the two scoped RBAC objects, verifies allowed/denied operations and waits
for the same Pod. Agent/app execution before apply, restart, failed retrieval,
missing history, lost write responses or changed identities stop without
retry/reset. Readiness-only restart eligibility is an explicit opt-in and
does not permit an agent/app retry. Raw evidence remains private.

Continuation requires a non-hook manifest-identical render before one
`helm upgrade --no-hooks` of the retained failed release. No force, uninstall,
automatic rollback, Pod-template change or release-status patch is allowed.
It then installs only the unattempted NTS release and runs normal readiness/
provenance checks using the original accepted code. Original receipts, code
bindings and the uncertain DMAAP journal are not rewritten. A new failure
requires review; never replay the setup driver or accept again after a latch.

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
  SMS auth, Consul and all three quorum backing directories must also be empty;
  existing data is never adopted as a fresh initialization.

Every new ONAP Job uses `backoffLimit: 0` and `restartPolicy: Never`. Failures
stop acceptance rather than replaying initializers. The post-ONAP gate
requires reconciled controllers, Complete Jobs, a hostname-validated AAF TLS
session presenting this allocation's exact leaf, and successful actual AAF
agent initializers. Only then may non-RT RIC and NTS installation continue.
The final full-SMO provenance gate still controls the completion marker.

The private receipts are under `/local/setup/phase3-smo/fresh-start/`:
`rehearsal.json`, `context.json`, backend handoff/acceptance records, private
preload attempt evidence and `sms-preload-acceptance.json`, and, after live ONAP acceptance,
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

### Strategy-aware final readiness and retained r4 continuation

Automatic startup and provenance checks now distinguish StatefulSet update
strategies. `RollingUpdate` keeps its normal read-only rollout-status check.
The pinned Strimzi Kafka/ZooKeeper `OnDelete` sets instead require the one
matching Kafka owner, reconciled generations, exact Ready Pod membership and
matching controller/Pod revisions. No strategy change or Pod restart is made.
The startup wait has a single bounded 3,600-second budget; unknown strategies,
desired-state/identity drift and unproved convergence fail closed.

The retained `p3-smo-cert-r4` allocation at profile `1d75faba` stopped only on
the unsupported rollout-status command. It has a separate **final-only**
continuation, not an ONAP/non-RT RIC/simulator deployment replay. Run the new
published revision from its own clean checkout; retain `/local/repository`,
its generated configuration and all existing acceptance evidence unchanged.

Create a new owner-only review directory, then audit:

```sh
python3 -B bin/phase3-final-readiness.py --audit \
  --expected-slice CURRENT_R4_SLICE_URN --accepted-checkout /local/repository \
  --review-file NEW_PRIVATE_DIRECTORY/review.json
```

After reviewing the successful audit, from that same clean checkout:

```sh
./setup-driver.sh --resume-final-readiness \
  --expected-slice CURRENT_R4_SLICE_URN --accepted-checkout /local/repository \
  --review-file NEW_PRIVATE_DIRECTORY/review.json
```

This recovery is allocation-, original-log- and source-pin-specific. It requires
the stopped startup, existing infrastructure markers, accepted operator hour,
current SMS/backend/preload/DMAAP/O-RU/Kong checks, deployed releases, complete
Jobs, Bound claims and independently validated full-SMO readiness. It binds
resource identities/specs, restart counts, chart hashes and private receipts,
and preserves both original logs privately before any continuation.
Only the exact portal OID normalization in `test-common.py` is accepted as a
tracked source difference; arbitrary edits or modes remain blocking.

Apply holds the driver lock and records an allocation-wide exclusive attempt.
It runs only the original provenance/end-stage checks and publishes completion
markers after successful, unchanged final validation. An uncertain/failed
attempt cannot be replayed. Keep the review and raw diagnostics private.
No provisioning Job, Helm release, PKI, backend or application data is modified;
existing authenticated checks can create/revoke scoped readback tokens.
Certificate runtimes, fault cases, long observation and RF remain separately
approved activities. This profile compatibility correction is not a finding
of a default-deployment security vulnerability.

### Targeted fresh-baseline ONAP recovery

Fresh installs now configure the stock VES TLS initializer with this
allocation's public JKS trust. Its observed 2.1.0 image is digest-pinned,
its two startup scripts are hash-checked, and an emptyDir attempt latch
prevents repeated issuance after an initializer failure. Stock diagnostics
remain private; no key, signer, or new CA is supplied to VES. The isolated
Java 8 controls exercise JKS trust, server/signer PKCS12 loading, hostname
and untrusted-CA rejection, and OpenSSL conversion, not a live AAF API.
The modern PKCS12 *truststore* is not asserted equivalent to the VES JKS.
DMAAP provisioning gets a bounded 30-minute prerequisite wait rather than
the stock ten-minute wait; its modifying main still has no automatic retry.

`python3 bin/phase3-onap-recovery.py` provides separate `--audit` and
`--apply` modes with `--expected-slice`, `--target ves|sms|dmaap`, and an
exclusive `--review-file`. VES additionally requires `--ves-rehearsal`
pointing to a successful exact-image isolated rehearsal receipt. Audit
writes private evidence but changes no workload. Apply requires unchanged
UID/resource-version/spec evidence and the still-valid one-hour operator
gate. Review/recover in order: VES, SMS, DMAAP. Dependencies must have been
Ready for two minutes. The SMS dependency check requires all three
reconciled, revision-matched quorum StatefulSet members; arbitrary
multiple matches refuse.
Each failed Job's complete retained history must
prove its main never ran, and executable/storage inputs must match its
retained Helm manifest. SMS also requires matching pre-issuance sponsorship
403s for the same Pod IP and execution window; ambiguity refuses replay.
This does not remove SMS's exclusion from the older image-recovery tool.

Before exact failed-Job replacement, its private manifests and logs are
preserved and hashed. Only the failed Job and its owned terminal Pod are
removed; a replacement is created suspended and released for one attempt.
No successful Job, database, PVC, or umbrella release is recreated. A
failure stops for review, with no broad replay or destructive rollback.
Keep all audit/apply directories private: stock configuration/logs can
contain credentials. The suspected stock AAF organization-index race is
not fixed by this recovery, nor by simply extending a timeout.

After ONAP acceptance succeeds, continue under the driver lock:

```sh
/local/repository/setup-driver.sh --resume-after-onap --expected-slice CURRENT_SLICE_URN
```

This validates the allocation, runs the existing post-ONAP gate and remaining
SMO/simulator stages, then normal end-stage/completion logic. Never create
completion markers manually. Certificate fault tests remain separately gated.

### SMS initializer timing and post-deployment continuation

Fresh startup now gives SMS/Vault/quorum Pod and initializer readiness,
including verified SMS TLS, a separate bounded 1,800-second startup budget.
Only then does the 600-second backend handoff budget begin. The latter
still requires initialized/unsealed Vault, durable validated quorum custody,
the single journaled normal first-use GET, persisted AppRole credentials,
and 120 restart-free seconds. Neither deadline resets on repeated polls.
Timeout evidence identifies the phase and elapsed time; readiness alone
never authorizes preload. This change is automatic in new allocations.

A retained fresh allocation that stopped **only at this pre-first-use
timeout** can be inspected without writes using the reviewed revision:

```sh
python3 bin/phase3-onap-deploy-resume.py --expected-slice CURRENT_SLICE_URN
```

After reviewing that audit, continue from the same reviewed checkout:

```sh
./setup-driver.sh --resume-after-onap-deploy --expected-slice CURRENT_SLICE_URN
```

This is distinct from `--resume-after-onap`, which requires ONAP acceptance
already. The new mode retains the exclusive driver lock and checks the
allocation/context, original timeout, currently accepted operator, private
PKI, exact backend Pod/storage identities, verified TLS, durable shard
custody, deployed Helm revisions and existing controller/Job specs. Before
first use, Vault must already be unsealed, AppRole files must still be
absent, and preload must be suspended with no owned Pod or attempt.

The mode privately preserves and hashes original startup/backend logs and
manifests before proceeding. A durable review binds the unchanged code,
allocation and completed Jobs. It runs only backend acceptance, guarded
preload, Kafka/ONAP acceptance, and the existing remaining SMO stages. It
never runs infrastructure setup, the ONAP deployment plugin, PKI preparation,
backend resets/restarts, or completed Jobs. Existing valid acceptance
receipts are revalidated rather than replayed. An uncertain first-use or
preload attempt, identity change, or unrelated failed Job stops continuation
for separate review. Keep review/archive files private. Do not manually
unsuspend preload or manufacture acceptance/completion markers.

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
