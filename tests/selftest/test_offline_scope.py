#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Offline scope controls: selected skips fail, host exclusions are declared.

A required selected live test that exits 77, or an ABI probe subcase
that skips, must make the suite result non-success even though CTest's
own aggregate status stays zero. Host-only exclusions are declared
NOT_RUN cases, never a hidden pass.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SKIPPED_CTEST = """\
Test project /fake/build
    Start 1: ring_framing
1/3 Test  #1: ring_framing .....................   Passed    0.01 sec
    Start 2: poll_semantics
2/3 Test  #2: poll_semantics ...................***Skipped   0.00 sec
    Start 3: exports
3/3 Test  #3: exports ..........................   Passed    0.04 sec

100% tests passed, 0 tests failed out of 3

Total Test time (real) =   0.05 sec

The following tests did not run:
\t  2 - poll_semantics (Skipped)
"""

PASSED_CTEST = """\
Test project /fake/build
    Start 1: ring_framing
1/2 Test #1: ring_framing ......................   Passed    0.01 sec
    Start 2: exports
2/2 Test #2: exports ...........................   Passed    0.04 sec

100% tests passed, 0 tests failed out of 2

Total Test time (real) =   0.05 sec
"""

HOST_SKIPPED_CTEST = """\
Test project /fake/build
    Start 1: native_host_ring_framing
1/2 Test  #1: native_host_ring_framing .........***Skipped   0.00 sec
    Start 2: exports
2/2 Test  #2: exports ..........................   Passed    0.04 sec

50% tests passed, 0 tests failed out of 2

Total Test time (real) =   0.05 sec

The following tests did not run:
\t  1 - native_host_ring_framing (Skipped)
"""

TIMEOUT_CTEST = """\
Test project /fake/build
    Start 1: ring_framing
1/3 Test  #1: ring_framing .....................   Passed    0.01 sec
    Start 2: poll_semantics
2/3 Test  #2: poll_semantics ...................***Timeout   1.50 sec
    Start 3: exports
3/3 Test  #3: exports ..........................   Passed    0.04 sec

66% tests passed, 1 tests failed out of 3

Total Test time (real) =   1.55 sec

The following tests FAILED:
\t  2 - poll_semantics (Timeout)
"""

FAILED_SKIPPED_CTEST = """\
Test project /fake/build
    Start 1: ring_framing
1/3 Test  #1: ring_framing .....................***Failed    0.01 sec
    Start 2: poll_semantics
2/3 Test  #2: poll_semantics ...................***Skipped   0.00 sec
    Start 3: exports
3/3 Test  #3: exports ..........................   Passed    0.04 sec

33% tests passed, 1 tests failed out of 3

Total Test time (real) =   0.05 sec

The following tests FAILED:
\t  1 - ring_framing (Failed)

The following tests did not run:
\t  2 - poll_semantics (Skipped)
"""

FAILED_CTEST = """\
Test project /fake/build
    Start 1: ring_framing
1/2 Test  #1: ring_framing .....................***Failed    0.01 sec
    Start 2: exports
2/2 Test  #2: exports ..........................   Passed    0.04 sec

50% tests passed, 1 tests failed out of 2

Total Test time (real) =   0.05 sec

The following tests FAILED:
\t  1 - ring_framing (Failed)
"""

V1_SYMBOLS = (
    "lmb_open lmb_load lmb_attach lmb_poll lmb_map_info lmb_map_read "
    "lmb_map_write lmb_stats lmb_last_error lmb_detach lmb_close"
).split()


class OfflineScope(unittest.TestCase):
    def run_native(self, ctest_output, args, with_guard=False, ctest_rc=0):
        """Drive tools/test native against a canned ctest transcript."""
        build_name = "build-selftest-scope"
        build_dir = ROOT / build_name
        self.assertFalse(build_dir.exists(), "stale fake build tree")
        with tempfile.TemporaryDirectory() as tmp:
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            fake = bindir / "ctest"
            fake.write_text("#!/bin/sh\ncat <<'EOF'\n" + ctest_output
                            + "EOF\nexit %d\n" % ctest_rc)
            fake.chmod(0o755)
            build_dir.mkdir()
            try:
                (build_dir / "CTestTestfile.cmake").write_text("# fake\n")
                if with_guard:
                    (build_dir / "liblmb_host_guard.so").write_bytes(b"fake")
                env = dict(os.environ)
                env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
                env["LMB_BUILD_DIR"] = build_name
                proc = subprocess.run(
                    [str(ROOT / "tools/test"), "native", *args],
                    cwd=ROOT, env=env, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                return proc.returncode, proc.stdout
            finally:
                shutil.rmtree(build_dir, ignore_errors=True)

    def test_required_live_skip_fails_native_suite(self):
        rc, out = self.run_native(SKIPPED_CTEST, [])
        self.assertNotEqual(rc, 0,
                            "a skipped required live test must fail the suite")
        self.assertIn("selection incomplete, skipped or not run: "
                      "poll_semantics", out)

    def test_clean_native_selection_passes(self):
        rc, _ = self.run_native(PASSED_CTEST, [])
        self.assertEqual(rc, 0)

    def test_timeout_preserves_ctest_exit_code(self):
        rc, out = self.run_native(TIMEOUT_CTEST, [], ctest_rc=8)
        self.assertEqual(rc, 8,
                         "a genuine CTest failure code must survive diagnostics")
        self.assertIn("selection incomplete, skipped or not run: "
                      "poll_semantics", out)

    def test_failed_plus_skipped_preserves_ctest_exit_code(self):
        rc, out = self.run_native(FAILED_SKIPPED_CTEST, [], ctest_rc=8)
        self.assertEqual(rc, 8,
                         "a genuine CTest failure code must survive diagnostics")
        self.assertIn("selection incomplete, skipped or not run: "
                      "poll_semantics", out)

    def test_failed_alone_preserves_ctest_exit_code(self):
        rc, _ = self.run_native(FAILED_CTEST, [], ctest_rc=8)
        self.assertEqual(rc, 8)

    def test_host_only_skip_fails_and_exclusion_is_declared(self):
        rc, out = self.run_native(HOST_SKIPPED_CTEST, ["--host-only"],
                                  with_guard=True)
        self.assertNotEqual(rc, 0,
                            "a skipped selected host test must fail the suite")
        self.assertIn("host-only selection incomplete, skipped or not run: "
                      "native_host_ring_framing", out)
        self.assertIn("NOT_RUN", out)

    def test_probe_subcase_skip_exits_77(self):
        cc = (shutil.which("cc") or shutil.which("gcc")
              or shutil.which("clang"))
        self.assertIsNotNone(cc, "a system C compiler is required")
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            stub_c = tmpdir / "stub.c"
            stub_c.write_text("".join(
                "int %s(void){return 0;}\n" % name for name in V1_SYMBOLS))
            stub_so = tmpdir / "stub.so"
            subprocess.run(
                [cc, "-shared", "-fPIC", "-o", str(stub_so), str(stub_c)],
                check=True, cwd=ROOT, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
            probe = tmpdir / "probe"
            build = subprocess.run(
                [cc, "-std=c11", "-D_GNU_SOURCE", "-o", str(probe),
                 str(ROOT / "tests/native/generic_abi_probe.c"),
                 "-I", str(ROOT / "native/include"), "-ldl"],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True)
            self.assertEqual(build.returncode, 0, build.stdout)
            proc = subprocess.run(
                [str(probe), str(stub_so)], cwd=ROOT, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertIn("SKIP generic-behavior", proc.stdout)
            self.assertEqual(proc.returncode, 77,
                             "a skipped probe subcase must exit 77, never 0")


if __name__ == "__main__":
    unittest.main()
