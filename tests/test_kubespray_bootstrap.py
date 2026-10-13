"""Exercise actual pure helpers/config generation; never source setup-lib.sh."""
from collections import Counter
import importlib.util
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HELPERS = (ROOT / "bin/kubespray-bootstrap-lib.sh").read_text()
SCRIPT = (ROOT / "setup-kubespray.sh").read_text()
GENERATOR = SCRIPT[SCRIPT.index("OVERRIDES=$INVDIR/overrides.yml"):
                   SCRIPT.index("# Validate adapter output before Kubespray")]
spec = importlib.util.spec_from_file_location("kubespray_validator", ROOT / "bin/validate-kubespray-overrides.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class KubesprayValidationTests(unittest.TestCase):
    def test_valid_normalized_string(self):
        self.assertEqual("1.34.3", validator.validate('kube_version: "1.34.3"\n', "v1.34.3"))

    def test_empty_selection_has_no_override(self):
        self.assertIsNone(validator.validate("disable_swap: true\n", ""))
        with self.assertRaises(ValueError):
            validator.validate('kube_version: "1.34.3"\n', "")

    def test_duplicate_wrong_type_and_wrong_release_are_rejected(self):
        for text in ['kube_version: "1.34.3"\nkube_version: "1.34.3"\n',
                     'kube_version: "v1.34.3"\n', 'kube_version: 1.34\n',
                     'kube_version: "1.35.0"\n', '- kube_version\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                validator.validate(text, "v1.34.3")


class KubesprayVersionTests(unittest.TestCase):
    def render(self, directory, version):
        fixture = '''
INVDIR=%s
PYTHONBIN=/usr/bin/python3
SWAPPER=testowner
CONTAINERMANAGER=docker
DOCKERVERSION=
KUBEVERSION=%s
KUBEFEATUREGATES=
KUBELETCUSTOMFLAGS=
KUBELETMAXPODS=120
KUBENETWORKPLUGIN=calico
HEAD_DATA_IP=10.10.1.1
KUBEENABLEMULTUS=0
KUBEPROXYMODE=ipvs
KUBEPODSSUBNET=10.233.0.0/16
KUBESERVICEADDRESSES=10.96.0.0/12
HELMVERSION=3.18.4
MGMTLAN=datalan-1
DATALANS=datalan-1
HEAD=node-0
DOCKEROPTIONS=
KUBEDOMETALLB=0
getnodeip() { printf '10.10.1.1\\n'; }
getnetmaskprefix() { printf '24\\n'; }
''' % (shlex.quote(str(directory)), shlex.quote(version))
        result = subprocess.run(["sh", "-c", "set -e\n" + HELPERS + fixture + GENERATOR],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        return (directory / "overrides.yml").read_text()

    def test_prefixed_and_bare_versions_have_identical_string_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            prefixed = self.render(directory, "v1.34.3")
            bare = self.render(directory, "1.34.3")
            self.assertEqual(prefixed, bare)
            self.assertEqual("1.34.3", yaml.safe_load(bare)["kube_version"])
            self.assertIn('kube_version: "1.34.3"', bare)

    def test_empty_version_preserves_upstream_default_behavior(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertNotIn("kube_version", yaml.safe_load(self.render(Path(temporary), "")))

    def test_repeated_generation_replaces_stale_keys_without_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "overrides.yml").write_text("kube_version: v1.34.3\nstale_only: true\n")
            first = self.render(directory, "v1.34.3")
            second = self.render(directory, "v1.34.3")
            self.assertEqual(first, second)
            keys = [k.value for k, _ in yaml.compose(second).value]
            self.assertFalse([k for k, count in Counter(keys).items() if count > 1])
            self.assertNotIn("stale_only", keys)

    def test_unrelated_selected_settings_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefixed = yaml.safe_load(self.render(Path(temporary), "v1.34.3"))
            bare = yaml.safe_load(self.render(Path(temporary), "1.34.3"))
            self.assertEqual(prefixed, bare)
            self.assertEqual({"container_manager": "docker", "helm_version": "3.18.4",
                "kube_network_plugin": "calico", "kube_proxy_mode": "ipvs", "kubelet_max_pods": 120,
                "kube_pods_subnet": "10.233.0.0/16", "kube_service_addresses": "10.96.0.0/12",
                "ansible_user": "testowner", "disable_swap": True, "override_system_hostname": False},
                {k: bare[k] for k in ["container_manager", "helm_version", "kube_network_plugin",
                    "kube_proxy_mode", "kubelet_max_pods", "kube_pods_subnet", "kube_service_addresses",
                    "ansible_user", "disable_swap", "override_system_hostname"]})


class KubesprayCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.destination = self.root / "checkout"
        self.git("init", "-q", str(self.source))
        (self.source / "requirements.txt").write_text("fixture\n")
        self.git("-C", str(self.source), "add", "requirements.txt")
        self.git("-C", str(self.source), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-q", "-m", "fixture source")
        self.git("-C", str(self.source), "tag", "fixture-release")

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], text=True, stderr=subprocess.DEVNULL).strip()

    def checkout(self, prefix="", revision="fixture-release"):
        body = "set -e\n" + HELPERS + prefix + "\nphase3_kubespray_checkout %s %s %s\n" % (
            shlex.quote(str(self.source)), shlex.quote(str(self.destination)), shlex.quote(revision))
        return subprocess.run(["sh", "-c", body], capture_output=True, text=True, timeout=20)

    def test_absent_checkout_is_cloned_at_selected_revision(self):
        result = self.checkout()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(self.git("-C", str(self.source), "rev-parse", "fixture-release"),
                         self.git("-C", str(self.destination), "rev-parse", "HEAD"))

    def test_matching_checkout_is_reused_without_clone_or_deletion(self):
        self.assertEqual(0, self.checkout().returncode)
        sentinel = self.destination / ".git/reuse-sentinel"
        sentinel.write_text("preserve\n")
        result = self.checkout('git() { if [ "$1" = clone ]; then return 77; fi; command git "$@"; }')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("preserve\n", sentinel.read_text())

    def test_dirty_checkout_is_rejected_without_reset(self):
        self.assertEqual(0, self.checkout().returncode)
        fixture = self.destination / "requirements.txt"
        fixture.write_text("local edit\n")
        self.assertNotEqual(0, self.checkout().returncode)
        self.assertEqual("local edit\n", fixture.read_text())

    def test_wrong_revision_is_rejected_without_checkout(self):
        self.assertEqual(0, self.checkout().returncode)
        self.git("-C", str(self.destination), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-q", "--allow-empty", "-m", "different revision")
        before = self.git("-C", str(self.destination), "rev-parse", "HEAD")
        self.assertNotEqual(0, self.checkout().returncode)
        self.assertEqual(before, self.git("-C", str(self.destination), "rev-parse", "HEAD"))

    def test_wrong_repository_is_rejected(self):
        self.assertEqual(0, self.checkout().returncode)
        self.git("-C", str(self.destination), "remote", "set-url", "origin", str(self.root / "unexpected"))
        self.assertNotEqual(0, self.checkout().returncode)

    def test_non_git_destination_is_preserved(self):
        self.destination.mkdir()
        sentinel = self.destination / "sentinel"
        sentinel.write_text("preserve\n")
        self.assertNotEqual(0, self.checkout().returncode)
        self.assertEqual("preserve\n", sentinel.read_text())

    def test_clone_failure_retains_exit_code(self):
        self.assertEqual(17, self.checkout('git() { return 17; }').returncode)

    def test_checkout_failure_retains_exit_code_and_partial_checkout(self):
        result = self.checkout('git() { if [ "$3" = checkout ]; then return 23; fi; command git "$@"; }')
        self.assertEqual(23, result.returncode)
        self.assertTrue((self.destination / ".git").is_dir())

    def test_missing_revision_is_rejected_without_clone(self):
        self.assertNotEqual(0, self.checkout(revision="").returncode)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
