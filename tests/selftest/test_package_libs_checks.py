#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Packaging helpers fail closed on availability, not on versions.

tools/package resolves runtime libraries through ambient
readelf and ldconfig (see tools/package_libs.py). Both are
documented ambient exceptions to the pinned-input claim:
packaging aborts when either helper is missing or errors,
and neither version is checked or recorded. This probe
pins that availability behavior: a run against a trivial
system binary succeeds, hiding ldconfig from PATH aborts
with nothing resolved, and an unreadable ELF aborts via
the readelf failure. Standard library only.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "tools", "package_libs.py")


def run_helper(args, env=None):
    return subprocess.run(
        [sys.executable, SCRIPT] + args,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, env=env)


class PackageLibsChecks(unittest.TestCase):
    def test_system_binary_resolves(self):
        binary = shutil.which("true") or "/bin/true"
        self.assertTrue(os.path.isfile(binary))
        tmp = tempfile.mkdtemp(prefix="packagelibs-")
        try:
            proc = run_helper([tmp, binary])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(proc.returncode, 0, proc.stdout[-500:])
        self.assertIn("S libc.so.6", proc.stdout)

    def test_missing_ldconfig_aborts(self):
        binary = shutil.which("true") or "/bin/true"
        tmp = tempfile.mkdtemp(prefix="packagelibs-")
        try:
            env = dict(os.environ)
            env["PATH"] = tmp
            proc = run_helper([tmp, binary], env=env)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("ldconfig", proc.stdout)
        self.assertNotIn("\nB ", "\n" + proc.stdout)
        self.assertNotIn("\nS ", "\n" + proc.stdout)

    def test_failed_readelf_aborts(self):
        tmp = tempfile.mkdtemp(prefix="packagelibs-")
        try:
            bogus = os.path.join(tmp, "not-an-elf")
            with open(bogus, "w", encoding="utf-8") as handle:
                handle.write("not an ELF file\n")
            proc = run_helper([tmp, bogus])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("readelf", proc.stdout)


if __name__ == "__main__":
    unittest.main()
