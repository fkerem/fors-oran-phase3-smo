import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
import phase3_images as images
import phase3_recovery_guards as guards

class ImageTests(unittest.TestCase):
    def test_exact_five_locks_and_exporter_packaging(self):
        lock = images.load_lock()
        self.assertEqual(5, len(images.replacements(lock)))
        exporter = lock["images"][-1]
        self.assertEqual("0.12.1", exporter["application_version"])
        self.assertEqual("/bin/mysqld_exporter", exporter["binary_path"])
        self.assertIn("not binary equivalence", exporter["provenance"])
        self.assertTrue(exporter["digest"].startswith("sha256:3851cf4"))

    def test_invalid_reference_digest_and_platform_lock_rejected(self):
        original = images.load_lock()
        variants = []
        for key, value in (("platform", "linux/arm64"), ("cache_registry", "0.0.0.0:5000")):
            lock = copy.deepcopy(original); lock[key] = value; variants.append(lock)
        lock = copy.deepcopy(original); lock["images"][0]["digest"] = "latest"; variants.append(lock)
        lock = copy.deepcopy(original); lock["images"][0]["original"] = "unreviewed:1"; variants.append(lock)
        lock = copy.deepcopy(original); lock["images"][0]["source_repository"] = "docker.io/untrusted/db"; variants.append(lock)
        for lock in variants:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "lock.json"; path.write_text(json.dumps(lock))
                with self.assertRaises(ValueError): images.load_lock(path)

    def test_implicit_docker_host_and_explicit_registry(self):
        self.assertEqual(("docker.io", "library/kong", "2.5"), images.split_reference("kong:2.5"))
        self.assertEqual(("docker.io", "prom/mysqld-exporter", "0.12.1"), images.split_reference("prom/mysqld-exporter:0.12.1"))
        self.assertEqual(("10.10.1.1:5000", "x/y", "v1"), images.split_reference("10.10.1.1:5000/x/y:v1"))

    def test_unversioned_and_latest_rejected(self):
        for reference in ("nginx", "quay.io/example:latest", "a@wrong", "https://registry/image:1"):
            with self.assertRaises(ValueError): images.split_reference(reference)

    def test_inventory_includes_init_job_and_cr_images(self):
        inventory = {"items": [{"kind": "Job", "spec": {"template": {"spec": {
            "containers": [{"image": "db:1"}], "initContainers": [{"image": "init:1"}]}}}},
            {"kind": "Kafka", "spec": {"image": "kafka:1"}}]}
        self.assertEqual({"db:1", "init:1", "kafka:1"}, images.images_in(inventory))

    def test_audit_missing_artifact_is_failure_not_fallback(self):
        with patch.object(images, "inspect", side_effect=urllib.error.HTTPError("u", 404, "missing", {}, None)) as probe:
            record = images.audit({images.load_lock()["images"][0]["original"]})
        self.assertFalse(record["ready"])
        self.assertEqual(1, probe.call_count)
        self.assertIn("@sha256:", probe.call_args.args[0])

    def test_audit_maps_cache_reference_to_exact_source(self):
        image = next(iter(images.replacements().values()))
        with patch.object(images, "inspect", return_value={"digest": "locked", "platform": "linux/amd64"}) as probe:
            self.assertTrue(images.audit({image})["ready"])
        self.assertTrue(probe.call_args.args[0].startswith("docker.io/bitnamilegacy/"))

    def test_manifest_digest_mismatch_rejected(self):
        with patch.object(images, "request_blob", return_value=b"{}"):
            with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
                images.inspect("example.org/x@sha256:" + "0" * 64)

    def test_ambiguous_index_rejected(self):
        manifest = {"manifests": [{"digest": "sha256:" + str(i) * 64,
                                 "platform": {"os": "linux", "architecture": "amd64"}} for i in (1, 2)]}
        with patch.object(images, "request_blob", return_value=json.dumps(manifest).encode()):
            with self.assertRaisesRegex(ValueError, "Ambiguous"):
                images.inspect("example.org/x:1")

    def test_config_digest_and_architecture_checked(self):
        import hashlib
        config = json.dumps({"os": "linux", "architecture": "arm64"}).encode()
        manifest = json.dumps({"config": {"digest": "sha256:" + hashlib.sha256(config).hexdigest()}}).encode()
        with patch.object(images, "request_blob", side_effect=[manifest, config]):
            with self.assertRaisesRegex(ValueError, "platform mismatch"):
                images.inspect("example.org/x:1")
        with patch.object(images, "request_blob", side_effect=[manifest, b"{}"]):
            with self.assertRaisesRegex(ValueError, "config digest mismatch"):
                images.inspect("example.org/x:1")

    def test_registry_binding_must_already_be_lan_only(self):
        container = {"State": {"Running": True}, "HostConfig": {"PortBindings": {
            "5000/tcp": [{"HostIp": "10.10.1.1", "HostPort": "5000"}]}}}
        images.verify_registry_binding([container])
        container["HostConfig"]["PortBindings"]["5000/tcp"][0]["HostIp"] = "0.0.0.0"
        with self.assertRaisesRegex(ValueError, "LAN-only"): images.verify_registry_binding([container])

    def test_cache_must_preserve_digests_and_never_install_packages(self):
        lock = images.load_lock()
        registry = [{"State": {"Running": True}, "HostConfig": {"PortBindings": {
            "5000/tcp": [{"HostIp": "10.10.1.1", "HostPort": "5000"}]}}}]
        copied=set()
        def probe(reference):
            if ":sha256-" in reference and reference not in copied:
                raise urllib.error.HTTPError("u", 404, "missing", {}, None)
            digest=reference.split('@',1)[1] if '@' in reference else 'sha256:'+reference.rsplit(':sha256-',1)[1]
            return {"digest":digest,"platform":"linux/amd64"}
        def call(argv, **kwargs):
            if argv[0] == "sudo": return json.dumps(registry).encode()
            if argv[0] == "dpkg-query": return lock["skopeo_package"].encode()
            if argv[0]=='skopeo':
                Path(argv[argv.index('--digestfile')+1]).write_text(argv[-2].split('@',1)[1])
                copied.add(argv[-1].removeprefix('docker://'))
            return b""
        with patch.object(images, "inspect", side_effect=probe), patch.object(images, "run", side_effect=call) as run:
            self.assertEqual(5, len(images.cache(lock)))
        copies = [c.args[0] for c in run.call_args_list if c.args[0][0] == "skopeo"]
        self.assertEqual(5, len(copies))
        for argv in copies:
            self.assertNotIn("--preserve-digests", argv)
            self.assertIn('--digestfile',argv)
            self.assertNotIn('--format',argv)
            self.assertEqual('0',argv[argv.index('--retry-times')+1])
            self.assertIn("--dest-tls-verify=false", argv)
            self.assertNotIn("--src-tls-verify=false", argv)
            self.assertIn("docker://10.10.1.1:5000/phase3-compat/", argv[-1])
        self.assertFalse(any("apt-get" in c.args[0] for c in run.call_args_list))

    def test_native_copy_digest_rewrite_is_rejected_without_next_image(self):
        lock=images.load_lock()
        registry=[{'State':{'Running':True},'HostConfig':{'PortBindings':{'5000/tcp':[{'HostIp':'10.10.1.1','HostPort':'5000'}]}}}]
        def call(argv,**kwargs):
            if argv[0]=='sudo':return json.dumps(registry).encode()
            if argv[0]=='dpkg-query':return lock['skopeo_package'].encode()
            Path(argv[argv.index('--digestfile')+1]).write_text('sha256:'+'0'*64);return b''
        def probe(reference):
            if ':sha256-' in reference:raise urllib.error.HTTPError('u',404,'missing',{},None)
            return {'digest':reference.split('@',1)[1]}
        with patch.object(images,'run',side_effect=call) as command,patch.object(images,'inspect',side_effect=probe):
            with self.assertRaisesRegex(ValueError,'changed manifest digest'):images.cache(lock)
        self.assertEqual(1,len([c for c in command.call_args_list if c.args[0][0]=='skopeo']))

    def test_cache_does_not_overwrite_conflicting_tag(self):
        lock = images.load_lock()
        registry = [{"State": {"Running": True}, "HostConfig": {"PortBindings": {
            "5000/tcp": [{"HostIp": "10.10.1.1", "HostPort": "5000"}]}}}]
        with patch.object(images, "run", side_effect=[json.dumps(registry).encode(), lock["skopeo_package"].encode()]) as run, \
             patch.object(images, "inspect", side_effect=[{"digest": lock["images"][0]["digest"]}, {"digest": "other"}]):
            with self.assertRaisesRegex(ValueError, "overwrite"): images.cache()
        self.assertEqual(2, run.call_count)

    def test_cache_failure_propagates_without_next_copy(self):
        with patch.object(images, "run", side_effect=RuntimeError("unavailable")):
            with self.assertRaises(RuntimeError): images.cache()

class RecoveryGuardTests(unittest.TestCase):
    def operator(self):
        deployment = {"metadata": {"generation": 1}, "status": {"observedGeneration": 1,
                       "readyReplicas": 1, "updatedReplicas": 1, "availableReplicas": 1}}
        pods = [{"metadata": {"uid": "pod-uid"}, "status": {"containerStatuses": [{"ready": True, "restartCount": 1}]}}]
        return deployment, pods

    def test_ready_operator_receipt(self):
        self.assertEqual({"uid": "pod-uid", "restarts": 1}, guards.operator_health(*self.operator()))

    def test_inter_restarts_ready_does_not_mask_oom(self):
        deployment, pods = self.operator()
        pods[0]["status"]["containerStatuses"][0]["lastState"] = {"terminated": {"reason": "OOMKilled"}}
        with self.assertRaisesRegex(ValueError, "OOM recurrence"): guards.operator_health(deployment, pods)

    def test_unready_or_stale_operator_rejected(self):
        deployment, pods = self.operator()
        deployment["status"]["observedGeneration"] = 0
        with self.assertRaises(ValueError): guards.operator_health(deployment, pods)
        deployment, pods = self.operator(); pods[0]["status"]["containerStatuses"][0]["ready"] = False
        with self.assertRaises(ValueError): guards.operator_health(deployment, pods)

    def job(self):
        name = next(iter(guards.JOBS))
        job = {"metadata": {"name": name, "namespace": "onap", "uid": "job-uid", "resourceVersion": "1",
                            "annotations": {"meta.helm.sh/release-name": guards.JOBS[name]}},
               "status": {"failed": 1}, "spec": {"template": {"spec": {"containers": [
                   {"name": "initializer", "image": "docker.io/bitnami/mariadb:10.5.8"}], "initContainers": [{"name": "readiness",
                   "image": guards.READINESS_IMAGE, "command": ["/app/ready.py"], "args": ["--container-name", "db"]}]}}}}
        pods = [{"metadata": {"ownerReferences": [{"uid": "job-uid", "kind": "Job"}]},
                 "spec": copy.deepcopy(job["spec"]["template"]["spec"]),
                 "status": {"phase": "Failed", "containerStatuses": [{"name": "initializer", "state": {"waiting": {"reason": "PodInitializing"}}}],
                            "initContainerStatuses": [{"name": "readiness", "imageID": "readiness-digest", "state": {"terminated": {"exitCode": 1}}}]}}]
        return job, pods

    def test_failed_initializer_never_executed_is_guardable(self):
        self.assertFalse(guards.job_guard(*self.job())["initialization_execution_observed"])

    def test_active_completed_and_missing_history_fail(self):
        for key in ("active", "succeeded"):
            job, pods = self.job(); job["status"][key] = 1
            with self.assertRaises(ValueError): guards.job_guard(job, pods)
        with self.assertRaisesRegex(ValueError, "history"): guards.job_guard(self.job()[0], [])

    def test_wrong_uid_owner_image_or_hook_fail(self):
        for mutation in (lambda j: j["metadata"].update(name="other"),
                         lambda j: j["metadata"]["annotations"].update({"helm.sh/hook": "post-install"}),
                         lambda j: j["metadata"].update(uid="other"),
                         lambda j: j["spec"]["template"]["spec"]["containers"][0].update(image="db:latest")):
            job, pods = self.job(); mutation(job)
            with self.assertRaises(ValueError): guards.job_guard(job, pods)

    def test_any_initializer_execution_record_blocks_replay(self):
        for field, value in (("imageID", "digest"), ("restartCount", 1), ("lastState", {"terminated": {}}),
                             ("state", {"terminated": {"exitCode": 1}}), ("state", {"running": {"startedAt": "t"}})):
            job, pods = self.job(); pods[0]["status"]["containerStatuses"][0][field] = value
            with self.assertRaisesRegex(ValueError, "execution"): guards.job_guard(job, pods)

    def test_only_exact_image_render_changes_allowed(self):
        old = {"kind": "Pod", "spec": {"containers": [{"image": next(iter(images.ORIGINALS)),
                "env": [{"valueFrom": {"secretKeyRef": {"name": "same-secret", "key": "password"}}}]}]}}
        new = copy.deepcopy(old); new["spec"]["containers"][0]["image"] = images.replacements()[old["spec"]["containers"][0]["image"]]
        self.assertEqual(1, len(guards.image_only_diff(old, new)))
        new["spec"]["containers"][0]["env"][0]["valueFrom"]["secretKeyRef"]["name"] = "changed-secret"
        with self.assertRaisesRegex(ValueError, "non-image"): guards.image_only_diff(old, new)

    def test_unapproved_image_and_added_resource_rejected(self):
        for after in ([{"image": "unapproved:1"}], [{"image": "same:1"}, {"kind": "Secret"}]):
            with self.assertRaises(ValueError): guards.image_only_diff([{"image": "same:1"}], after)

    def test_resume_refuses_incomplete_onap_and_failed_jobs(self):
        with self.assertRaises(ValueError): guards.onap_ready([], [], [], [], [], [], [])

if __name__ == "__main__":
    unittest.main()
