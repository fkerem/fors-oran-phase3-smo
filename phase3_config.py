"""Phase 3 defaults and portal validation; no operational secrets."""
DEFAULTS = {
    "nodeCount": 3, "nodeType": "d740",
    "diskImage": "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD",
    "installORANSCSMO": True, "installORANSCSMOSim": True,
    "oscSmoVersion": "g-release", "oscSmoUseCachedCharts": True,
    "kubesprayRepo": "https://github.com/kubernetes-sigs/kubespray.git",
    "kubesprayVersion": "v2.30.0", "kubeVersion": "v1.34.3",
    "kubesprayUseVirtualenv": True, "containerManager": "docker",
    "kubeNetworkPlugin": "calico", "kubeProxyMode": "ipvs",
    "kubePodsSubnet": "10.233.0.0/16", "kubeServiceAddresses": "10.96.0.0/12",
    "kubeFeatureGates": "", "kubeletCustomFlags": "", "kubeletMaxPods": 120,
    "kubeAllWorkers": False, "kubeDoMetalLB": False, "publicIPCount": 0,
    "doNFS": True, "nfsAsync": False, "doLocalRegistry": True,
    "sslCertType": "self", "sslCertConfig": "proxy",
    "helmVersion": "3.18.4", "dockerVersion": "", "dockerOptions": "",
    "installORANSC": False, "buildORANSC": False, "installONFSDRAN": False,
    "installOpen5GS": False, "installVNC": False, "buildOcudu": False,
    "buildSrsRANProject": False, "buildSrsRAN4G": False,
    "buildSrsLTE": False, "buildOAI": False, "kubeEnableMultus": False,
}

def validate_parameters(params):
    errors = []
    for field in ["nodeCount", "nodeType", "diskImage", "publicIPCount"]:
        if getattr(params, field) != DEFAULTS[field]:
            errors.append((field, "This Phase 3 profile requires %s=%s." % (field, DEFAULTS[field])))
    for field in ["installORANSCSMO", "installORANSCSMOSim", "oscSmoUseCachedCharts", "doNFS", "doLocalRegistry"]:
        if not getattr(params, field):
            errors.append((field, "Required for the cached SMO baseline."))
    for field in ["installORANSC", "buildORANSC", "installONFSDRAN", "installOpen5GS", "installVNC",
                  "buildOcudu", "buildSrsRANProject", "buildSrsRAN4G", "buildSrsLTE", "buildOAI", "kubeDoMetalLB"]:
        if getattr(params, field):
            errors.append((field, "Disabled in this SMO-only profile."))
    if params.oscSmoVersion not in ("g-release", "f-release"):
        errors.append(("oscSmoVersion", "Choose g-release or the separate f-release compatibility baseline."))
    return errors
