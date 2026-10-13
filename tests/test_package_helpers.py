"""Test actual helper definitions without sourcing the mutating bootstrap."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "setup-lib.sh").read_text()
HELPERS = SOURCE[SOURCE.index("are_packages_installed()"):
                 SOURCE.index("##\n## Figure out the system python version.")]
MOCKS = r'''
dpkg() {
    [ "$#" -eq 2 ] && [ "$1" = -s ] || return 99
    case "$2" in installed|lvm2|thin-provisioning-tools) return 0;; *) return 1;; esac
}
fake_install() {
    printf 'INSTALL:%s\n' "$#"
    for package do printf 'ARG:%s\n' "$package"; done
    for package do
        if [ "$package" = broken ]; then return 23; fi
    done
    return 0
}
APTGETINSTALL=fake_install
DO_APT_UPGRADE=0
'''


class PackageHelperTests(unittest.TestCase):
    def run_case(self, body, expected_code=0, expected_lines=()):
        for shell in ("bash", "sh"):
            with self.subTest(shell=shell):
                strict = "set -e -o pipefail\n" if shell == "bash" else "set -e\n"
                result = subprocess.run([shell, "-c", strict + HELPERS + MOCKS + body],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(expected_code, result.returncode, result.stderr)
                self.assertEqual(list(expected_lines), result.stdout.splitlines())

    def test_installed_preflight_package_is_successful_without_install(self):
        self.run_case("maybe_install_packages installed; echo CONTINUED",
                      expected_lines=["CONTINUED"])

    def test_missing_package_installs_under_errexit(self):
        self.run_case("maybe_install_packages missing; echo CONTINUED",
                      expected_lines=["INSTALL:1", "ARG:missing", "CONTINUED"])

    def test_mixed_orders_install_only_missing_packages(self):
        for packages in ("installed missing", "missing installed"):
            with self.subTest(packages=packages):
                self.run_case("maybe_install_packages " + packages + "; echo CONTINUED",
                              expected_lines=["INSTALL:1", "ARG:missing", "CONTINUED"])

    def test_empty_list_is_noop_in_both_upgrade_modes(self):
        for upgrade in (0, 1):
            self.run_case("DO_APT_UPGRADE=%d; maybe_install_packages; echo CONTINUED" % upgrade,
                          expected_lines=["CONTINUED"])

    def test_upgrade_installs_all_arguments_together(self):
        self.run_case("DO_APT_UPGRADE=1; maybe_install_packages installed missing",
                      expected_lines=["INSTALL:2", "ARG:installed", "ARG:missing"])

    def test_disabled_installer_remains_noop(self):
        self.run_case("APTGETINSTALL='true fake_install'; maybe_install_packages missing; echo CONTINUED",
                      expected_lines=["CONTINUED"])

    def test_installer_failure_is_not_masked_by_later_installed_package(self):
        for packages in ("broken installed", "installed broken missing"):
            with self.subTest(packages=packages):
                self.run_case("maybe_install_packages " + packages + "; echo INCORRECT",
                              expected_code=23, expected_lines=["INSTALL:1", "ARG:broken"])

    def test_upgrade_failure_retains_installer_exit_code(self):
        self.run_case("DO_APT_UPGRADE=1; maybe_install_packages installed broken; echo INCORRECT",
                      expected_code=23, expected_lines=["INSTALL:2", "ARG:installed", "ARG:broken"])

    def test_legacy_predicate_contract_and_caller_state_are_preserved(self):
        self.run_case('''
retval=71
if are_packages_installed installed; then exit 80; else code=$?; fi
[ "$code" -eq 1 ]
if are_packages_installed missing; then code=0; else exit 81; fi
[ "$code" -eq 0 ]
[ "$retval" -eq 71 ]
maybe_install_packages installed
[ "$retval" -eq 71 ]
echo CONTINUED
''', expected_lines=["CONTINUED"])

    def test_package_argument_boundaries_are_preserved(self):
        self.run_case("maybe_install_packages 'package with spaces'",
                      expected_lines=["INSTALL:1", "ARG:package with spaces"])

    def test_disk_package_request_has_no_function_name_argument(self):
        source = (ROOT / "setup-disk-space.sh").read_text()
        self.assertTrue(source.startswith("#!/bin/sh\n"))
        request = next(line for line in source.splitlines()
                       if line.startswith("maybe_install_packages lvm2"))
        self.assertEqual("maybe_install_packages lvm2 thin-provisioning-tools", request)
        self.run_case(request + "; echo CONTINUED", expected_lines=["CONTINUED"])


if __name__ == "__main__":
    unittest.main()
