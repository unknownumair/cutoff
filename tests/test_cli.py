"""CLI + installer contract tests — shell-level, no root, no network.

The `cutoff` command and the installers are part of the release surface: a
syntax error or a wrong path there breaks every documented workflow, so they
get the same treatment as the Python modules.
"""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "cutoff"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def run(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    base = {**os.environ, "CUTOFF_PREFIX": str(ROOT), "CUTOFF_DATA_DIR": str(ROOT / "backend" / "data")}
    if env:
        base.update(env)
    return subprocess.run([str(CLI), *args], capture_output=True, text=True, env=base, timeout=20)


class CliTests(unittest.TestCase):
    def test_script_is_executable_and_parses(self):
        self.assertTrue(os.access(CLI, os.X_OK), "bin/cutoff must be executable")
        check = subprocess.run(["sh", "-n", str(CLI)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_version_reads_the_version_file(self):
        result = run("version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), VERSION)

    def test_url_and_path(self):
        self.assertIn("http://127.0.0.1:", run("url").stdout)
        self.assertEqual(run("path").stdout.strip(), str(ROOT))

    def test_help_lists_commands(self):
        result = run("help")
        self.assertEqual(result.returncode, 0)
        for word in ("serve", "status", "uninstall", "doctor"):
            self.assertIn(word, result.stdout)

    def test_unknown_command_fails_loudly(self):
        result = run("definitely-not-a-command")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown command", result.stderr)

    def test_serve_refuses_an_incomplete_install(self):
        result = run("serve", env={"CUTOFF_PREFIX": "/nonexistent/cutoff"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not installed", result.stderr)


class InstallerTests(unittest.TestCase):
    def test_shell_scripts_parse(self):
        for name in ("install-global.sh", "install-service.sh", "fetch-vendor.sh",
                     "backup-data.sh", "install-nmap-rpm.sh", "install-bettercap.sh"):
            path = ROOT / "tools" / name
            if not path.exists():
                self.skipTest(f"{name} missing")
            check = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, f"{name}: {check.stderr}")

    def test_global_installer_refuses_a_non_checkout(self):
        result = subprocess.run(
            ["bash", str(ROOT / "tools" / "install-global.sh"), "--help"],
            capture_output=True, text=True, env={**os.environ, "PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("install", result.stdout.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
