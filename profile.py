#!/usr/bin/env python3
"""Phase 3 SMO-only derivative of the POWDER O-RAN profile."""
import geni.portal as portal
import geni.rspec.pg as RSpec
import geni.rspec.igext as IG
import geni.rspec.emulab  # Register Emulab extensions.
from lxml import etree as ET
from phase3_config import DEFAULTS, validate_parameters

pc = portal.Context()

def parameter(name, label, kind, choices=None, advanced=False, help_text=None):
    options = {"advanced": advanced}
    if help_text:
        options["longDescription"] = help_text
    if choices is not None:
        options["legalValues"] = choices
    pc.defineParameter(name, label, kind, DEFAULTS[name], **options)

parameter("nodeCount", "Number of nodes", portal.ParameterType.INTEGER)
parameter("nodeType", "Hardware type", portal.ParameterType.NODETYPE)
parameter("oscSmoVersion", "OSC SMO release", portal.ParameterType.STRING,
          ["g-release", "f-release"], help_text="Use g-release for Phase 3. f-release is a separate compatibility baseline.")
for name, label in [
    ("installORANSCSMO", "Install O-RAN SC SMO"),
    ("oscSmoUseCachedCharts", "Use pinned cached SMO charts"),
    ("installORANSCSMOSim", "Install NTS management simulators"),
    ("doNFS", "Enable NFS storage"), ("doLocalRegistry", "Enable local registry"),
    ("kubesprayUseVirtualenv", "Use a Kubespray virtual environment"),
    ("kubeAllWorkers", "Allow node-0 to run workloads"),
    ("kubeDoMetalLB", "Enable MetalLB"),
    ("installORANSC", "Install near-RT RIC"), ("installONFSDRAN", "Install SD-RAN"),
    ("installOpen5GS", "Install Open5GS"), ("installVNC", "Install VNC"),
    ("buildORANSC", "Build RIC components"), ("buildOcudu", "Build OCUDU"),
    ("buildSrsRANProject", "Build srsRAN Project"), ("buildSrsRAN4G", "Build srsRAN 4G"),
    ("buildSrsLTE", "Build srsLTE"), ("buildOAI", "Build OAI"),
    ("kubeEnableMultus", "Enable Multus"), ("nfsAsync", "Use asynchronous NFS writes"),
]:
    parameter(name, label, portal.ParameterType.BOOLEAN, advanced=True)
for name, label in [
    ("diskImage", "Ubuntu disk image"), ("kubesprayRepo", "Kubespray repository"),
    ("kubesprayVersion", "Kubespray version"), ("kubeVersion", "Kubernetes version"),
    ("containerManager", "Container manager"), ("kubeNetworkPlugin", "Network plugin"),
    ("kubeProxyMode", "Kubernetes proxy mode"), ("kubePodsSubnet", "Pod subnet"),
    ("kubeServiceAddresses", "Service subnet"), ("kubeFeatureGates", "Additional feature gates"),
    ("kubeletCustomFlags", "Additional kubelet flags"), ("helmVersion", "Helm version"),
    ("dockerVersion", "Docker version"), ("dockerOptions", "Additional Docker options"),
    ("sslCertType", "Dashboard certificate type"), ("sslCertConfig", "Dashboard certificate configuration"),
]:
    parameter(name, label, portal.ParameterType.STRING, advanced=True)
parameter("publicIPCount", "Additional public IP count", portal.ParameterType.INTEGER, advanced=True)
parameter("kubeletMaxPods", "Maximum pods per node", portal.ParameterType.INTEGER, advanced=True)

params = pc.bindParameters()
for field, message in validate_parameters(params):
    pc.reportError(portal.ParameterError(message, [field]))
pc.verifyParameters()
request = pc.makeRequestRSpec()
lan = request.LAN("datalan-1")
lan.best_effort = True
for index in range(params.nodeCount):
    node = request.RawPC("node-%d" % index)
    node.component_manager_id = "urn:publicid:IDN+emulab.net+authority+cm"
    node.hardware_type = params.nodeType
    node.disk_image = params.diskImage
    iface = node.addInterface("if0")
    iface.addAddress(RSpec.IPv4Address("10.10.1.%d" % (index+1), "255.255.255.0"))
    lan.addInterface(iface)
    node.installRootKeys(False, False)
    node.addService(RSpec.Execute(shell="sh", command=(
        "sudo mkdir -p /local/setup /local/logs && "
        "sudo chown `geni-get user_urn | cut -f4 -d+` /local/setup /local/logs && "
        "sudo -u `geni-get user_urn | cut -f4 -d+` -Hi /bin/bash -c "
        "'/local/repository/setup-driver.sh >/local/logs/setup.log 2>&1'")))

class EmulabEncrypt(RSpec.Resource):
    def _write(self, root):
        ET.SubElement(root, "{http://www.protogeni.net/resources/rspec/ext/emulab/1}password",
                      attrib={"name": "adminPass"})
request.addResource(EmulabEncrypt())
tour = IG.Tour()
tour.Description(IG.Tour.MARKDOWN, """
### Phase 3 SMO and certificate lifecycle preparation
Three d740 nodes run Kubernetes, the OSC SMO and NTS management simulators.
The profile requests no radios, spectrum, shared VLANs or extra public IPs.
The later PyNTS certificate experiment is a separate, explicitly launched
runtime; NTS readiness does not validate that notifier.
New experiments use an experiment-local lab PKI and a source-verified Job
readiness compatibility wrapper; this is not the unmodified stock PKI.
SMS public-chain/routing compatibility is included, but its stock preload
is deliberately held pending explicit write-safety review. This revision
does not yet provide unattended full-SMO acceptance.
Fresh quorum clients use the allocation's public root before first startup;
backend acceptance additionally requires durable shard and AppRole custody.
""")
tour.Instructions(IG.Tour.MARKDOWN, """
Wait for every startup service to show **Finished**. On node-0 inspect:
```
kubectl get nodes
kubectl get pods -A
kubectl get pvc -A
cat /local/setup/phase3-smo/chart-lock.json
/local/repository/bin/phase3-status.sh
```
Review `/local/logs/setup.log` and `/local/logs/setup-oran-smo.sh.log` if setup
fails. Failed downloads, checksums, chart/API checks or workload waits stop
setup; no completion marker is written. Keep logs and credentials private.
Fresh-start receipts are under `/local/setup/phase3-smo/fresh-start/`.
That directory also contains private keys and passwords: do not upload it.
The existing one-hour operator stability gate still applies.
The SMS backend gate checks Vault seal status and durable recovery material;
Pod Ready alone is insufficient. Do not restart SMS/quorum, reset Vault storage
or regenerate authority to bypass a failed handoff. See README.md.
Fresh startup uses explicit legacy-compatible PKCS12 packaging automatically.
For a predeployment rehearsal failure, use only the reviewed recovery in
README.md; do not replay infrastructure setup or delete generated PKI.
Kubernetes credentials are in `~/.kube/config`.

The SMS preload safety hold requires review, not more waiting: do not
manually unsuspend it or retry the stock writer. Follow the SMS safety
gate in README.md. A held Job or Job Complete alone is not acceptance.
The intentional hold stops setup before full completion; do not force a
Finished/completion marker or replay setup to clear it.

For local SMO UI access, use an SSH tunnel and loopback Kubernetes port
forward as documented in README.md. Read chart-provided credentials only on
the allocated node; do not paste their values into evidence or GitHub.

Before certificate testing, confirm a TLS management session, the actual
keystore/truststore paths and a scheduled leaf notification. Allow about
25 hours after simulator startup for the original daily scheduler. The
profile does not automatically launch certificate fault cases.
""")
request.addTour(tour)
pc.printRequestRSpec(request)
