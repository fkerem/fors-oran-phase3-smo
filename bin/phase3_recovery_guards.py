"""Read-only gates for image-only recovery; never replay an uncertain initializer."""
import copy
from phase3_images import replacements

JOBS = {
    "onap-dmaap-dr-mariadb-init-config-job": "onap-dmaap",
    "onap-nengdb-init-config-job": "onap-sdnc",
    "onap-policy-clamp-galera-config": "onap-policy",
    "onap-dmaap-bc-dmaap-provisioning": "onap-dmaap",
    "onap-policy-galera-config": "onap-policy",
    "onap-sdnc-dbinit-job": "onap-sdnc",
}
PRESERVE_JOBS = {"onap-aaf-sms-preload", "onap-sdnc-sdnrdb-init-job"}
MAIN_IMAGES = {name: "docker.io/bitnami/mariadb:10.5.8" for name in JOBS}
MAIN_IMAGES.update({"onap-dmaap-bc-dmaap-provisioning": "nexus3.onap.org:10001/onap/dmaap/dbc-client:1.0.9",
                    "onap-policy-galera-config": "nexus3.onap.org:10001/onap/policy-db-migrator:2.4.3",
                    "onap-sdnc-dbinit-job": "nexus3.onap.org:10001/onap/sdnc-image:2.3.0"})
READINESS_IMAGE = "nexus3.onap.org:10001/onap/oom/readiness:3.0.1"

def executed(container):
    return bool(container.get("imageID") or container.get("restartCount", 0) or container.get("lastState") or
                container.get("state", {}).get("running") or container.get("state", {}).get("terminated"))

def init_behavior(container, pod_spec, job_name):
    command = (container.get("command") or []) + (container.get("args") or [])
    if container["image"] == READINESS_IMAGE and command and command[0] == "/app/ready.py" and not container.get("volumeMounts"):
        return "readiness-only"
    if job_name == "onap-sdnc-dbinit-job" and container["name"] == "sdnc-update-config":
        if (container["image"] != "docker.io/dibi/envsubst:1" or command != ["sh", "-c",
                "cd /config-input && for PFILE in `ls -1 .`; do envsubst <${PFILE} >/config/${PFILE}; done"]):
            raise ValueError("Config initializer differs from reviewed Pod-local substitution")
        mounts = {m["mountPath"]: m["name"] for m in container.get("volumeMounts", [])}
        volumes = {v["name"]: v for v in pod_spec.get("volumes", [])}
        if set(mounts) != {"/config-input", "/config"} or "emptyDir" not in volumes.get(mounts["/config"], {}) or "configMap" not in volumes.get(mounts["/config-input"], {}):
            raise ValueError("Config initializer writes outside reviewed emptyDir")
        return "pod-local-config"
    if job_name == "onap-policy-galera-config" and container["name"] == "onap-policy-galera-config" and container["image"] == "docker.io/mariadb:10.5.8":
        return "must-never-have-executed"
    raise ValueError("Unreviewed initializer layout or side effect")

def operator_health(deployment, pods):
    status = deployment.get("status", {})
    if status.get("observedGeneration", 0) < deployment["metadata"].get("generation", 1) or any(
            status.get(key, 0) != 1 for key in ("readyReplicas", "updatedReplicas", "availableReplicas")):
        raise ValueError("Strimzi operator is not reconciled and Ready")
    live = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
    if len(live) != 1:
        raise ValueError("Expected one current operator pod")
    pod = live[0]
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if len(statuses) != 1 or not statuses[0].get("ready"):
        raise ValueError("Operator container is not Ready")
    if statuses[0].get("lastState", {}).get("terminated", {}).get("reason") == "OOMKilled":
        raise ValueError("Operator OOM recurrence requires separate review; image recovery refused")
    return {"uid": pod["metadata"]["uid"], "restarts": statuses[0].get("restartCount", 0)}

def job_guard(job, pods):
    metadata = job["metadata"]
    name = metadata["name"]
    if (name not in JOBS or metadata.get("namespace") != "onap" or
            metadata.get("annotations", {}).get("meta.helm.sh/release-name") != JOBS.get(name) or
            "helm.sh/hook" in metadata.get("annotations", {})):
        raise ValueError("Unapproved Job identity or ownership")
    status = job.get("status", {})
    if status.get("succeeded", 0) or status.get("active", 0) or not status.get("failed", 0):
        raise ValueError("Job is active, completed or not demonstrably failed")
    owned = [p for p in pods if any(o.get("uid") == metadata["uid"] and o.get("kind") == "Job"
                                   for o in p["metadata"].get("ownerReferences", []))]
    if len(owned) != status["failed"]:
        raise ValueError("Incomplete retained Pod history; initializer replay refused")
    pod_spec = job["spec"]["template"]["spec"]
    containers = pod_spec.get("containers", [])
    if len(containers) != 1 or containers[0]["image"] != MAIN_IMAGES[name]:
        raise ValueError("Unexpected initializer image or layout")
    behaviors = {c["name"]: init_behavior(c, pod_spec, name) for c in pod_spec.get("initContainers", [])}
    if not behaviors: raise ValueError("Missing reviewed readiness initializer")
    for pod in owned:
        if pod.get("status", {}).get("phase") != "Failed":
            raise ValueError("Job Pod is not terminal; retry race")
        declared = {c["name"]: c for c in pod_spec.get("initContainers", [])}
        actual = {c["name"]: c for c in pod.get("spec", {}).get("initContainers", [])}
        if set(actual) != set(declared) or any(actual[n].get(k) != declared[n].get(k) for n in declared for k in ("image", "command", "args")):
            raise ValueError("Retained Pod initializer contract differs from Job")
        for init_name,behavior in behaviors.items():
            if behavior!='pod-local-config':continue
            retained=copy.deepcopy(actual[init_name])
            retained['volumeMounts']=[m for m in retained.get('volumeMounts',[]) if not (
                m.get('mountPath')=='/var/run/secrets/kubernetes.io/serviceaccount' and m.get('readOnly') is True)]
            if init_behavior(retained,pod['spec'],name)!=behavior:
                raise ValueError('Retained Pod configuration writes outside reviewed local storage')
        main_status = pod.get("status", {}).get("containerStatuses", [])
        init_status = pod.get("status", {}).get("initContainerStatuses", [])
        if len(main_status) != 1 or main_status[0].get("name") != containers[0]["name"] or set(c["name"] for c in init_status) != set(behaviors):
            raise ValueError("Incomplete main/init execution history")
        for container in main_status:
            if executed(container):
                raise ValueError("Initializer execution record exists; replay refused")
        for container in init_status:
            if container["name"] not in behaviors: raise ValueError("Unreviewed init-container history")
            if behaviors[container["name"]] == "must-never-have-executed" and executed(container):
                raise ValueError("Side-effecting init container already executed; replay refused")
    return {"name": name, "uid": metadata["uid"], "resource_version": metadata["resourceVersion"],
            "retained_failed_pods": len(owned), "initialization_execution_observed": False,
            "reviewed_init_behaviors": behaviors}

def held_job(resource):
    result = copy.deepcopy(resource)
    if result.get("kind") != "Job" or result.get("metadata", {}).get("name") not in JOBS:
        raise ValueError("Recovery controls are limited to eligible exact Job names")
    if result["spec"]["template"]["spec"].get("restartPolicy") != "Never":
        raise ValueError("Recovery Jobs require restartPolicy Never")
    result["spec"]["suspend"] = True
    result["spec"]["backoffLimit"] = 0
    return result

def recovery_diff(before, after):
    # Compare rendered documents after accepting only named suspension/single-attempt controls.
    if len(before) != len(after): raise ValueError("Unexpected resource count")
    normalized = copy.deepcopy(after)
    controls = []
    for old, new in zip(before, normalized):
        if old.get("kind") == new.get("kind") == "Job" and old["metadata"]["name"] == new["metadata"]["name"] and old["metadata"]["name"] in JOBS:
            if new["spec"].get("backoffLimit") != 0 or new["spec"].get("suspend") is not True:
                raise ValueError("Eligible recovery Job is not held/single-attempt")
            for key in ("backoffLimit", "suspend"):
                if key in old["spec"]: new["spec"][key] = old["spec"][key]
                else: new["spec"].pop(key, None)
            controls.append(old["metadata"]["name"])
    return {"image_changes": image_only_diff(before, normalized), "held_single_attempt_jobs": controls}

def image_only_diff(before, after):
    """Fail closed on credentials, storage, probes, security contexts or any non-image diff."""
    allowed = replacements()
    changes = []
    def walk(old, new, path):
        if type(old) is not type(new):
            raise ValueError("Unexpected render difference at " + path)
        if isinstance(old, dict):
            if old.keys() != new.keys():
                raise ValueError("Unexpected render keys at " + path)
            for key in old:
                if key == "image" and isinstance(old[key], str) and old[key] != new[key]:
                    if allowed.get(old[key]) != new[key]:
                        raise ValueError("Unreviewed image difference at " + path)
                    changes.append({"path": path + ".image", "original": old[key], "replacement": new[key]})
                else:
                    walk(old[key], new[key], path + "." + key)
        elif isinstance(old, list):
            if len(old) != len(new):
                raise ValueError("Unexpected render list length at " + path)
            for i, (left, right) in enumerate(zip(old, new)):
                walk(left, right, path + "[%d]" % i)
        elif old != new:
            raise ValueError("Unexpected non-image difference at " + path)
    walk(copy.deepcopy(before), after, "resources")
    return changes

def onap_ready(nodes, deployments, statefulsets, jobs, pvcs, kafkas, releases):
    if len(nodes) != 3 or not all(any(c["type"] == "Ready" and c["status"] == "True"
                                   for c in n.get("status", {}).get("conditions", [])) for n in nodes):
        raise ValueError("Expected three Ready nodes")
    if not deployments or not statefulsets or not jobs or not pvcs or not kafkas:
        raise ValueError("Incomplete ONAP baseline inventory")
    for w in deployments + statefulsets:
        status = w.get("status", {})
        replicas = w["spec"].get("replicas", 1)
        if (status.get("readyReplicas", 0) != replicas or
                status.get("observedGeneration", 0) < w["metadata"].get("generation", 1)):
            raise ValueError("ONAP workload is not Ready: " + w["metadata"]["name"])
    for job in jobs:
        if not any(c["type"] == "Complete" and c["status"] == "True"
                   for c in job.get("status", {}).get("conditions", [])):
            raise ValueError("ONAP Job is not Complete: " + job["metadata"]["name"])
    if not all(p.get("status", {}).get("phase") == "Bound" for p in pvcs):
        raise ValueError("ONAP PVC is not Bound")
    for kafka in kafkas:
        status = kafka.get("status", {})
        if (status.get("observedGeneration", 0) < kafka["metadata"].get("generation", 1) or not any(
                c["type"] == "Ready" and c["status"] == "True" for c in status.get("conditions", []))):
            raise ValueError("Kafka is not reconciled and Ready")
    names = {r["name"] for r in releases if r.get("status") == "deployed"}
    if not {"onap", "onap-mariadb-galera", "onap-policy", "onap-dmaap", "onap-sdnc"} <= names:
        raise ValueError("Required ONAP releases are not deployed")
    if any(r.get("status") != "deployed" for r in releases):
        raise ValueError("An ONAP release is failed or pending")
