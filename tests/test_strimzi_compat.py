import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("strimzi_compat", ROOT / "bin/strimzi-version-compat.py")
compat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compat)


def response():
    return {"major": "1", "minor": "34", "gitVersion": "v1.34.3", "gitCommit": "0123456789abcdef",
            "gitTreeState": "clean", "buildDate": "2025-12-09T14:59:13Z", "goVersion": "go1.24.11",
            "compiler": "gc", "platform": "linux/amd64", "emulationMajor": "1", "emulationMinor": "34",
            "minCompatibilityMajor": "1", "minCompatibilityMinor": "33"}


def record():
    return {"method": compat.METHOD, "expected_version": "v1.34.3", "reported_version": response(),
            "override_fields": compat.version_fields(response(), "v1.34.3"), "operator_image": compat.IMAGE}


def resources():
    env = [{"name": "STRIMZI_KUBERNETES_VERSION",
            "value": "\n".join(k + "=" + response()[k] for k in compat.FIELDS)}]
    container = {"name": "strimzi-cluster-operator", "image": compat.IMAGE, "env": env}
    deployment = {"metadata": {"generation": 2}, "spec": {"template": {"spec": {"containers": [container]}}},
                  "status": {"observedGeneration": 2, "readyReplicas": 1, "updatedReplicas": 1, "availableReplicas": 1}}
    pod = {"metadata": {"name": "operator-test", "uid": "test-uid"}, "spec": {"containers": [copy.deepcopy(container)]},
           "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                      "containerStatuses": [{"name": container["name"], "ready": True, "restartCount": 0,
                                             "imageID": "docker-pullable://" + compat.IMAGE}]}}
    return deployment, [pod]


class VersionTests(unittest.TestCase):
    def test_modern_fields_not_forwarded_and_version_not_falsified(self):
        for expected in ("v1.34.3", "1.34.3"):
            fields = compat.version_fields(response(), expected)
            self.assertEqual(set(compat.FIELDS), set(fields))
            self.assertEqual("34", fields["minor"])
            self.assertEqual("v1.34.3", fields["gitVersion"])

    def test_missing_empty_or_malformed_fields_rejected(self):
        for key in compat.FIELDS:
            for value in (None, "", 34, True, "value\nmajor=1", "a,b", "a=b"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    compat.version_fields(dict(response(), **{key: value}), "v1.34.3")

    def test_version_mismatch_and_false_emulation_rejected(self):
        for changes in ({"major": "2"}, {"minor": "33"}, {"gitVersion": "v1.34.2"},
                        {"emulationMajor": "2"}, {"emulationMinor": "33"}):
            with self.assertRaises(ValueError):
                compat.version_fields(dict(response(), **changes), "v1.34.3")
        for expected in ("", "vv1.34.3", "1.34", "latest"):
            with self.assertRaises(ValueError): compat.version_fields(response(), expected)
        with self.assertRaises(ValueError): compat.version_fields([], "v1.34.3")

    def test_prepare_hashes_preserves_raw_and_owner_only_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "server.json"
            raw = json.dumps(response()).encode()
            source.write_bytes(raw)
            generated = compat.prepare(source, "v1.34.3", base / "values.yaml", base / "record.json")
            values = yaml.safe_load((base / "values.yaml").read_text())
            self.assertEqual(1, len(values["extraEnvs"]))
            self.assertNotIn("emulationMajor", values["extraEnvs"][0]["value"])
            self.assertEqual(raw, source.read_bytes())
            self.assertEqual(hashlib.sha256(raw).hexdigest(), generated["server_version_sha256"])
            self.assertEqual(hashlib.sha256((base / "values.yaml").read_bytes()).hexdigest(), generated["values_sha256"])
            self.assertEqual(0o600, (base / "record.json").stat().st_mode & 0o777)
            with self.assertRaises(ValueError): compat.prepare(source, "v1.34.3", base / "values.yaml", base / "record.json")

    def test_duplicate_or_invalid_json_writes_no_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "server.json"
            for raw in ('{"major":"1","major":"2"}', '{broken'):
                source.write_text(raw)
                with self.assertRaises(ValueError): compat.prepare(source, "v1.34.3", base / "values", base / "record")
                self.assertFalse((base / "values").exists())
                self.assertFalse((base / "record").exists())

    def test_failed_api_command_does_not_mask_error_or_print_credentials(self):
        result = subprocess.CompletedProcess([], 1, "", "credential-bearing server message")
        with patch.object(compat.subprocess, "run", return_value=result), self.assertRaises(RuntimeError) as raised:
            compat.command(["kubectl", "get", "--raw", "/version"])
        self.assertNotIn("credential-bearing", str(raised.exception))


class OperatorTests(unittest.TestCase):
    def test_ready_pinned_operator_with_truthful_override(self):
        sample = compat.operator_sample(*resources(), record())
        self.assertEqual("test-uid", sample["uid"])
        self.assertEqual(0, sample["restarts"])

    def test_wrong_image_digest_or_override_rejected(self):
        for change in ("image", "digest", "override", "duplicate"):
            deployment, pods = resources()
            if change == "image": deployment["spec"]["template"]["spec"]["containers"][0]["image"] = compat.IMAGE_TAG
            elif change == "digest": pods[0]["status"]["containerStatuses"][0]["imageID"] = "wrong"
            elif change == "override": deployment["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] = "major=1\nminor=24"
            else: deployment["spec"]["template"]["spec"]["containers"][0]["env"] *= 2
            with self.assertRaises(ValueError): compat.operator_sample(deployment, pods, record())

    def test_stale_deployment_or_unready_pod_not_accepted(self):
        deployment, pods = resources()
        deployment["status"]["observedGeneration"] = 1
        self.assertIsNone(compat.operator_sample(deployment, pods, record()))
        deployment, pods = resources()
        pods[0]["status"]["conditions"][0]["status"] = "False"
        self.assertIsNone(compat.operator_sample(deployment, pods, record()))

    def test_actual_environment_log_required_and_discovery_failure_rejected(self):
        compat.verify_log("Environment facts gathered: PlatformFeaturesAvailability(KubernetesVersion=1.34,OpenShiftRoutes=false)", record())
        for log in ("Environment facts gathered: KubernetesVersion=1.24,", "Failed to gather environment facts",
                    "UnrecognizedPropertyException", "no environment facts"):
            with self.assertRaises(ValueError): compat.verify_log(log, record())

    def run_gate(self, samples, clock):
        with patch.object(compat, "command", side_effect=[json.dumps(resources()[0]), json.dumps({"items": resources()[1]}),
                                                         "Environment facts gathered: KubernetesVersion=1.34,"] * 3), \
             patch.object(compat, "operator_sample", side_effect=samples), \
             patch.object(compat.time, "monotonic", side_effect=clock), patch.object(compat.time, "sleep"):
            return compat.wait_operator(record(), timeout=600, stability=240)

    def test_two_reconciliation_intervals_required(self):
        sample = compat.operator_sample(*resources(), record())
        result = self.run_gate([sample, sample], [0, 0, 0, 0, 240, 240])
        self.assertTrue(result["ready"])
        self.assertEqual(240, result["stability_seconds"])
        self.assertEqual(2, len(result["observations"]))

    def test_restart_during_stability_window_fails(self):
        sample = compat.operator_sample(*resources(), record())
        with self.assertRaisesRegex(ValueError, "restarted"):
            self.run_gate([sample, dict(sample, restarts=1)], [0, 0, 0, 0, 120])

    def test_timeout_is_a_failure(self):
        with patch.object(compat.time, "monotonic", side_effect=[0, 601]), self.assertRaisesRegex(ValueError, "bounded"):
            compat.wait_operator(record())


if __name__ == "__main__": unittest.main()
