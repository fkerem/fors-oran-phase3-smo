import io
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml
from lxml import etree

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phase3_config import DEFAULTS, validate_parameters

def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "bin" / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

cache = module("cache", "smo-chart-preflight.py")
compat = module("compat", "helm-api-compat.py")
prepare = module("prepare", "prepare-cached-chart.py")
provenance = module("provenance", "collect-phase3-provenance.py")
values = module("values", "prepare-smo-values.py")
PINS = json.loads((ROOT / "smo-chart-pins.json").read_text())

class ProfileTests(unittest.TestCase):
    def test_both_release_defaults_are_valid(self):
        for release in ("g-release", "f-release"):
            self.assertEqual([], validate_parameters(SimpleNamespace(**dict(DEFAULTS, oscSmoVersion=release))))

    def test_rejects_out_of_scope_allocations_and_stacks(self):
        for field, value in {"nodeCount": 4, "publicIPCount": 1, "nodeType": "d430",
                             "installORANSC": True, "buildOcudu": True, "oscSmoUseCachedCharts": False}.items():
            errors = validate_parameters(SimpleNamespace(**dict(DEFAULTS, **{field: value})))
            self.assertIn(field, [e[0] for e in errors])

    def test_actual_genilib_rspec_default_and_f_release(self):
        for args in ([], ["--oscSmoVersion", "f-release"]):
            result = subprocess.run([sys.executable, str(ROOT / "profile.py")] + args,
                                    cwd=ROOT, capture_output=True, text=True, check=True)
            tree = etree.fromstring(result.stdout.encode())
            ns = {"r": "http://www.geni.net/resources/rspec/3", "p": "http://www.protogeni.net/resources/rspec/ext/profile-parameters/1"}
            self.assertEqual(["node-0", "node-1", "node-2"], tree.xpath("//r:node/@client_id", namespaces=ns))
            self.assertEqual(["d740"] * 3, tree.xpath("//r:hardware_type/@name", namespaces=ns))
            self.assertEqual(1, len(tree.xpath("//r:link", namespaces=ns)))
            self.assertFalse(tree.xpath("//*[local-name()='spectrum' or local-name()='routable_pool' or local-name()='link_shared_vlan']"))
            self.assertEqual(set(DEFAULTS), {e.get("name").split('.')[-1] for e in tree.xpath("//p:data_item", namespaces=ns)})

    def test_portal_rejects_ric_before_generating_topology(self):
        result = subprocess.run([sys.executable, str(ROOT / "profile.py"), "--installORANSC", "true"], cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('<node ', result.stdout)

class CachedChartTests(unittest.TestCase):
    def index(self, release):
        pin = PINS["releases"][release]
        return {"entries": {name: [{"version": p["version"], "urls": [p["url"]]}] for name, p in pin["charts"].items()}}

    def test_g_and_f_select_their_own_repository(self):
        for release in ("g-release", "f-release"):
            selected = cache.select_charts(self.index(release), PINS["releases"][release])
            self.assertTrue(all('/powder-osc-smo-' + release + '/' in p["url"] for p in selected.values()))

    def test_missing_chart_fails_without_fallback(self):
        index = self.index("g-release")
        del index["entries"]["ru-du-simulators"]
        with self.assertRaisesRegex(ValueError, "Missing"):
            cache.select_charts(index, PINS["releases"]["g-release"])

    def test_changed_url_and_index_digest_fail(self):
        for update in ({"urls": ["https://example.invalid/chart.tgz"]}, {"digest": "0"*64}):
            index = self.index("g-release")
            index["entries"]["onap"][0].update(update)
            with self.assertRaises(ValueError):
                cache.select_charts(index, PINS["releases"]["g-release"])

    def test_checksum_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            cache.verify_archive(b"invalid", PINS["strimzi"], "strimzi")

    def test_network_failure_writes_no_lock(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cache, "fetch", side_effect=OSError("unavailable")):
            lock = Path(directory) / "lock.json"
            with self.assertRaises(OSError):
                cache.prepare("g-release", Path(directory) / "charts", lock)
            self.assertFalse(lock.exists())

class CompatibilityTests(unittest.TestCase):
    def test_g_overlay_preserves_storage_and_unrelated_settings(self):
        base = {"global": {"persistence": {"existing": True}}, "odu-app": {"image": {"tag": "1.0.0"}}}
        result = values.merge(base, values.fragments("g-release")["oran-override.yaml"])
        self.assertEqual("/storage/nfs/deployment-1", result["global"]["persistence"]["mountPath"])
        self.assertTrue(result["global"]["persistence"]["existing"])
        self.assertEqual("1.0.0", result["odu-app"]["image"]["tag"])
        self.assertNotIn("mountPath", base["global"]["persistence"])

    def test_f_overlay_has_no_g_repository_replacement(self):
        fragment = values.fragments("f-release")["oran-override.yaml"]
        self.assertNotIn("odu-app", fragment)
        self.assertEqual([], fragment["a1policymanagement"]["rics"])

    def test_identical_dependencies_collapse(self):
        dependency = {"name": "serviceAccount", "version": "~10.x-0", "repository": "@local"}
        chart, removed = prepare.deduplicate_dependencies({"dependencies": [dependency, dependency.copy()]})
        self.assertEqual([dependency], chart["dependencies"])
        self.assertEqual(["serviceAccount"], removed)

    def test_conflicting_dependencies_rejected(self):
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            prepare.deduplicate_dependencies({"dependencies": [{"name": "x", "version": "1"}, {"name": "x", "version": "2"}]})

    def test_prepared_archive_retains_templates_and_removes_stale_lock(self):
        buffer = io.BytesIO()
        data = {"demo/Chart.yaml": yaml.safe_dump({"apiVersion": "v2", "name": "demo", "version": "1.0.0", "dependencies": [{"name": "x"}, {"name": "x"}]}).encode(),
                "demo/Chart.lock": b"obsolete", "demo/templates/deployment.yaml": b"unchanged-template"}
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, blob in data.items():
                info = tarfile.TarInfo(name); info.size = len(blob); archive.addfile(info, io.BytesIO(blob))
        result, changes = prepare.prepare_archive(buffer.getvalue())
        with tarfile.open(fileobj=io.BytesIO(result), mode="r:gz") as archive:
            self.assertNotIn("demo/Chart.lock", archive.getnames())
            self.assertEqual(b"unchanged-template", archive.extractfile("demo/templates/deployment.yaml").read())
        self.assertEqual(2, len(changes))

    def test_nonempty_pdb_and_cronjob_conversion(self):
        docs = compat.normalize([{"apiVersion": "policy/v1beta1", "kind": "PodDisruptionBudget", "spec": {"selector": {"matchLabels": {"app": "demo"}}}},
                                 {"apiVersion": "batch/v1beta1", "kind": "CronJob", "spec": {}}])
        self.assertEqual(["policy/v1", "batch/v1"], [d["apiVersion"] for d in docs])

    def test_empty_pdb_and_other_removed_apis_rejected(self):
        for doc in [{"apiVersion": "policy/v1beta1", "kind": "PodDisruptionBudget", "spec": {"selector": {}}},
                    {"apiVersion": "extensions/v1beta1", "kind": "Ingress"}]:
            with self.assertRaises(ValueError): compat.normalize([doc])

    def test_known_latest_pinned_and_unknown_latest_rejected(self):
        doc = {"apiVersion": "v1", "kind": "Pod", "spec": {"containers": [{"image": "docker.io/scholzj/zoo-entrance:latest"}]}}
        self.assertIn('@sha256:', compat.normalize([doc])[0]["spec"]["containers"][0]["image"])
        for image in ["example.invalid/demo:latest", "busybox"]:
            with self.assertRaises(ValueError):
                compat.normalize([{"apiVersion": "v1", "kind": "Pod", "spec": {"containers": [{"image": image}]}}])

class ReadinessTests(unittest.TestCase):
    def baseline(self):
        nodes = [{"ready": True}] * 3
        workloads = [{"namespace": ns, "name": "demo", "ready": True} for ns in provenance.SMO_NAMESPACES]
        releases = [{"name": name, "namespace": "onap", "status": "deployed"} for name in provenance.REQUIRED_RELEASES]
        services = [{"namespace": "onap", "name": name} for name in ["sdnc-oam", "sdnc-web-service"]]
        pods = [{"namespace": ns, "name": "demo", "phase": "Running", "ready": True} for ns in provenance.SMO_NAMESPACES]
        kafkas = [{"namespace": "onap", "name": "demo", "ready": True, "generation": 1, "observed_generation": 1}]
        return nodes, workloads, pods, [], releases, services, kafkas

    def test_healthy_baseline(self): self.assertEqual([], provenance.assess(*self.baseline()))

    def test_swallowed_child_failure_and_pending_pvc_fail(self):
        nodes, workloads, pods, pvcs, releases, services, kafkas = self.baseline()
        releases.append({"name": "onap-dmaap", "namespace": "onap", "status": "failed"})
        pvcs.append({"name": "demo", "namespace": "onap", "phase": "Pending"})
        errors = provenance.assess(nodes, workloads, pods, pvcs, releases, services, kafkas)
        self.assertTrue(any("onap-dmaap" in e for e in errors))
        self.assertTrue(any("PVC" in e for e in errors))

    def test_missing_services_and_nodes_fail(self):
        nodes, workloads, pods, pvcs, releases, services, kafkas = self.baseline()
        self.assertTrue(provenance.assess(nodes[:2], workloads, pods, pvcs, releases, [], kafkas))

    def test_missing_unready_or_stale_kafka_fails(self):
        baseline = list(self.baseline())
        for kafkas in ([], [dict(baseline[-1][0], ready=False)], [dict(baseline[-1][0], generation=2)]):
            self.assertTrue(any("Kafka" in error for error in provenance.assess(*baseline[:-1], kafkas)))

if __name__ == "__main__": unittest.main()
