import copy
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
    def test_both_releases_preserve_kong_settings_except_proxy_type(self):
        base = {"kong": {"proxy": {"type": "LoadBalancer", "annotations": {"retain": "yes"},
                                  "http": {"enabled": True, "servicePort": 80, "containerPort": 8000},
                                  "tls": {"enabled": True, "servicePort": 443, "containerPort": 8443}},
                         "admin": {"enabled": False}, "env": {"database": "off"}},
                "unrelated": {"retain": [1, 2]}}
        original = copy.deepcopy(base)
        expected = copy.deepcopy(base["kong"])
        expected["proxy"]["type"] = "ClusterIP"
        for release in ("g-release", "f-release"):
            with self.subTest(release=release), tempfile.TemporaryDirectory() as temp:
                source, target = Path(temp)/"defaults", Path(temp)/"prepared"
                source.mkdir()
                names = ["onap-override.yaml", "oran-override.yaml", "network-simulators-override.yaml",
                         "network-simulators-topology-override.yaml"]
                for name in names:
                    (source/name).write_text(yaml.safe_dump(base))
                values.prepare(source, target, release)
                self.assertEqual(set(names), {p.name for p in target.iterdir()})
                for name in names:
                    result = yaml.safe_load((target/name).read_text())
                    self.assertEqual(expected if name == "oran-override.yaml" else original["kong"], result["kong"])
                    self.assertEqual(original["unrelated"], result["unrelated"])
                    self.assertEqual(original, yaml.safe_load((source/name).read_text()))
                self.assertEqual(original, yaml.safe_load((target/"network-simulators-topology-override.yaml").read_text()))

    def test_kong_fragments_keep_the_other_approved_nonrtric_values(self):
        for release in ("g-release", "f-release"):
            with self.subTest(release=release):
                fragments = values.fragments(release)
                expected = {"global": {"persistence": {"mountPath": "/storage/nfs/deployment-1"}},
                            "nonrtric": {"persistence": {"mountPath": "/storage/nfs/deployment-1"}},
                            "a1policymanagement": {"enabled": False, "rics": []},
                            "kong": {"proxy": {"type": "ClusterIP"}}}
                if release == "g-release":
                    expected.update({"odu-app": {"image": {"repository": "nexus3.o-ran-sc.org:10002/o-ran-sc/nonrtric-rapp-ransliceassurance"}},
                                     "odu-app-ics-version": {"image": {"repository": "nexus3.o-ran-sc.org:10002/o-ran-sc/nonrtric-rapp-ransliceassurance-icsversion"}}})
                self.assertEqual(expected, fragments["oran-override.yaml"])
                self.assertEqual({"onap-override.yaml", "oran-override.yaml", "network-simulators-override.yaml"}, set(fragments))
                for name in ("onap-override.yaml", "network-simulators-override.yaml"):
                    self.assertNotIn("kong", fragments[name])

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

class KongProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/"context.json"
        self.context = {"slice_urn": "urn:publicid:IDN+emulab.net:fixture+slice+new", "kong_proxy_contract": 1}

    def collect(self, outcome):
        def command(args):
            if args[:2] == ["helm", "list"]:
                return '[]'
            if 'get' in args:
                return '{"items":[]}'
            if args[:2] == ["kubectl", "version"]:
                return '{}'
            return 'fixture'

        self.path.write_text(json.dumps(self.context))
        original = self.path.read_bytes()
        with patch.object(provenance, 'command', side_effect=command), \
                patch.object(provenance, 'assess', return_value=[]), \
                patch.object(provenance.subprocess, 'run') as run:
            if isinstance(outcome, Exception):
                run.side_effect = outcome
            else:
                run.return_value = outcome
            result = provenance.collect(self.path)
        self.assertEqual(original, self.path.read_bytes())
        self.assertEqual([self.path], list(self.path.parent.iterdir()))
        return result, run

    def test_new_contract_verification_is_readonly(self):
        result, run = self.collect(SimpleNamespace(returncode=0))
        self.assertEqual({'verified': True}, result['kong_proxy_current'])
        self.assertEqual([], result['readiness_errors'])
        run.assert_called_once_with(['python3', str(ROOT/'tools/phase3-kong-proxy.py'), 'verify-fresh',
            '--context', str(self.path), '--expected-slice', self.context['slice_urn']], capture_output=True, timeout=180)

    def test_cli_failure_timeout_and_launch_error_fail_readiness(self):
        for outcome in (SimpleNamespace(returncode=1), subprocess.TimeoutExpired('kong-verify', 180), OSError('unavailable')):
            with self.subTest(outcome=outcome):
                result, run = self.collect(outcome)
                run.assert_called_once()
                self.assertEqual({'verified': False}, result['kong_proxy_current'])
                self.assertEqual(['Kong proxy current verification is not established'], result['readiness_errors'])

    def test_retained_context_without_contract_skips_cli(self):
        del self.context['kong_proxy_contract']
        result, run = self.collect(SimpleNamespace(returncode=1))
        run.assert_not_called()
        self.assertIsNone(result['kong_proxy_current'])
        self.assertEqual([], result['readiness_errors'])

    def test_malformed_contract_fails_without_launching_cli(self):
        for value in (0, 2, -1, None, '1', True, False, 1.0, [], {}):
            with self.subTest(value=value):
                self.context['kong_proxy_contract'] = value
                result, run = self.collect(SimpleNamespace(returncode=0))
                run.assert_not_called()
                self.assertEqual({'verified': False}, result['kong_proxy_current'])
                self.assertEqual(['Kong proxy current verification is not established'], result['readiness_errors'])

    def test_require_ready_exits_unsuccessfully_and_records_kong_failure(self):
        result, _ = self.collect(SimpleNamespace(returncode=1))
        output = self.path.parent/'provenance.json'
        with patch.object(provenance, 'collect', return_value=result), \
                patch.object(sys, 'argv', ['collect-phase3-provenance.py', '--require-ready', '--output', str(output)]), \
                patch('builtins.print'), self.assertRaises(SystemExit) as exit_result:
            provenance.main()
        self.assertEqual(1, exit_result.exception.code)
        self.assertEqual({'verified': False}, json.loads(output.read_text())['kong_proxy_current'])


if __name__ == "__main__": unittest.main()
