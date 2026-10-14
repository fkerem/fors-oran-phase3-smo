import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from test_strimzi_compat import response, resources, record

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("memory_compat", ROOT / "bin/strimzi-version-compat.py")
compat = importlib.util.module_from_spec(spec); spec.loader.exec_module(compat)

def memory_record():
    return dict(record(), operator_memory=compat.MEMORY)

def memory_resources():
    deployment, pods = resources()
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    container["env"].append({"name": "JAVA_OPTS", "value": compat.MEMORY["java_opts"]})
    container["resources"] = {"requests": {"memory": "1Gi", "cpu": "200m"}, "limits": {"memory": "1Gi", "cpu": "1"}}
    pods[0]["spec"]["containers"][0] = copy.deepcopy(container)
    return deployment, pods

def runtime(argv=None, limit=1073741824, current=600000000, events="oom 0\noom_kill 0\n"):
    argv = argv or ["java", "-Xms256m", "-Xmx512m", "io.strimzi.operator.cluster.Main"]
    return "\0".join(argv) + "\0\nLIMIT\n%d\n\nCURRENT\n%d\n\nEVENTS\n%s" % (limit, current, events)

class HeapConfigurationTests(unittest.TestCase):
    def test_unrelated_env_preserved_with_version_and_heap(self):
        extra = {"name": "UNCHANGED", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}
        value = "\n".join(k + "=" + response()[k] for k in compat.FIELDS)
        merged = compat.merge_env([extra, {"name": "STRIMZI_KUBERNETES_VERSION", "value": value}], value)
        self.assertEqual(extra, merged[0]); self.assertEqual(compat.MEMORY["java_opts"], merged[-1]["value"])
        self.assertEqual(merged, compat.merge_env(merged, value))

    def test_conflicting_and_duplicate_env_rejected(self):
        for env in ([{"name": "JAVA_OPTS", "value": "-Xmx2g"}], [{"name": "JAVA_OPTS", "valueFrom": {}}],
                    [{"name": "_JAVA_OPTIONS", "value": "x"}], [{"name": "JDK_JAVA_OPTIONS", "value": "x"}],
                    [{"name": "JAVA_TOOL_OPTIONS", "value": "x"}], [{"name": "A"}, {"name": "A"}],
                    [{"name": "STRIMZI_KUBERNETES_VERSION", "value": "wrong"}]):
            with self.assertRaises(ValueError): compat.merge_env(env, "actual")

    def test_malformed_env_rejected(self):
        for env in ({}, ["not-a-mapping"], [{"value": "no-name"}]):
            with self.assertRaises(ValueError): compat.merge_env(env, "actual")

    def test_pinned_operator_and_retained_resources(self):
        self.assertEqual(0, compat.operator_sample(*memory_resources(), memory_record())["restarts"])
        deployment, pods = memory_resources()
        deployment["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = "2Gi"
        with self.assertRaises(ValueError): compat.operator_sample(deployment, pods, memory_record())

    def test_runtime_heap_values_and_cgroup(self):
        sample = compat.parse_runtime(runtime())
        self.assertEqual(536870912, sample["verified_heap_maximum_bytes"])
        self.assertEqual(1073741824, sample["memory_limit_bytes"])

    def test_runtime_conflicting_heap_or_wrong_main_rejected(self):
        base = ["java", "-Xms256m", "-Xmx512m", "io.strimzi.operator.cluster.Main"]
        for argv in (base + ["-Xmx2g"], base + ["-XX:MaxHeapSize=2g"], base + ["-Xmx512m"], base[:-1]):
            with self.assertRaises(ValueError): compat.parse_runtime(runtime(argv))

    def test_oom_or_unexpected_cgroup_limit_rejected(self):
        for raw in (runtime(limit=2147483648), runtime(events="oom 1\noom_kill 0\n"), runtime(events="oom 0\noom_kill 1\n")):
            with self.assertRaises(ValueError): compat.parse_runtime(raw)

    def test_last_oom_and_heap_failure_log_rejected(self):
        deployment, pods = memory_resources()
        pods[0]["status"]["containerStatuses"][0]["lastState"] = {"terminated": {"reason": "OOMKilled"}}
        with self.assertRaises(ValueError): compat.operator_sample(deployment, pods, memory_record())
        with self.assertRaises(ValueError): compat.verify_log("OutOfMemoryError: Java heap space", memory_record())

class MemoryGateTests(unittest.TestCase):
    def run_gate(self, clocks, memory, kafka=None):
        sample = compat.operator_sample(*memory_resources(), memory_record())
        with patch.object(compat, "command", side_effect=[json.dumps(memory_resources()[0]), json.dumps({"items": memory_resources()[1]}),
             "Environment facts gathered: KubernetesVersion=1.34,"] * 6), \
             patch.object(compat, "operator_sample", return_value=sample), \
             patch.object(compat, "runtime_sample", side_effect=memory), \
             patch.object(compat, "kafka_sample", side_effect=kafka or [[], [], []]), \
             patch.object(compat.time, "monotonic", side_effect=clocks), patch.object(compat.time, "sleep"):
            return compat.wait_operator(memory_record(), timeout=4500, stability=3600, require_kafka=bool(kafka))

    def test_four_minute_gate_cannot_accept_memory_recovery(self):
        with self.assertRaisesRegex(ValueError, "one-hour"):
            compat.wait_operator(memory_record(), stability=240)

    def test_full_hour_required_and_samples_retained(self):
        result = self.run_gate([0, 0, 0, 0, 3600, 3600], [compat.parse_runtime(runtime())] * 2)
        self.assertEqual(3600, result["stability_seconds"]); self.assertEqual(2, len(result["observations"]))

    def test_three_pressure_samples_stop_recovery(self):
        with self.assertRaisesRegex(ValueError, "90 percent"):
            self.run_gate([0, 0, 0, 0, 15, 15, 30], [compat.parse_runtime(runtime(current=1000000000))] * 3)

    def test_kafka_identity_change_stops_gate(self):
        with self.assertRaisesRegex(ValueError, "Kafka identity"):
            self.run_gate([0, 0, 0, 0, 15], [compat.parse_runtime(runtime())] * 2,
                          [[{"name": "k", "uid": "old", "generation": 1}], [{"name": "k", "uid": "new", "generation": 1}]])

    def test_stale_kafka_is_rejected(self):
        items = [{"metadata": {"name": "k", "uid": "u", "generation": 2}, "status": {"observedGeneration": 1,
                  "conditions": [{"type": "Ready", "status": "True"}]}}]
        with patch.object(compat, "command", return_value=json.dumps({"items": items})), self.assertRaises(ValueError):
            compat.kafka_sample()

if __name__ == "__main__": unittest.main()
