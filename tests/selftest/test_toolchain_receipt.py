#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Isolated controls for tool-version probe accounting in build receipts.

Every unsuccessful or unusable probe must fail the receipt closed,
retaining argv, exit status, and diagnostic output: nonzero exits
(even with version-looking output), empty or blank output, and
launch errors. Only an exit-0 probe with a usable first line is
recorded, and a failed probe emits no receipt. No subprocess runs
and no file is written; fakes stand in for the runner, the source
manifest, and the build tree. Standard library only.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import build_receipt


class _Result:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout


def _run(result=None, error=None):
    def fake(cmd, **kwargs):
        if error is not None:
            raise error
        return result
    return fake


class ToolchainReceipt(unittest.TestCase):
    def test_success_records_stripped_first_line(self):
        out = build_receipt.probe_tool_version(
            ["tool", "--version"], ".",
            run=_run(_Result(0, "  tool 1.2.3  \nsecond line\n")))
        self.assertEqual(out, "tool 1.2.3")

    def test_nonzero_exit_rejected_with_evidence(self):
        for stdout in ("tool 1.2.3\n", "", "boom\n"):
            with self.subTest(stdout=stdout):
                with self.assertRaises(SystemExit) as ctx:
                    build_receipt.probe_tool_version(
                        ["tool", "--version"], ".",
                        run=_run(_Result(9, stdout)))
                message = str(ctx.exception.code)
                self.assertIn("argv=", message)
                self.assertIn("tool", message)
                self.assertIn("exit=9", message)
                self.assertIn("diagnostic=", message)
                if stdout.strip():
                    self.assertIn(stdout.strip(), message)

    def test_empty_output_rejected_with_evidence(self):
        for stdout in ("", "   \n  \n", "\ntool 1.0\n", None):
            with self.subTest(stdout=stdout):
                with self.assertRaises(SystemExit) as ctx:
                    build_receipt.probe_tool_version(
                        ["tool", "--version"], ".",
                        run=_run(_Result(0, stdout)))
                message = str(ctx.exception.code)
                self.assertIn("argv=", message)
                self.assertIn("exit=0", message)
                self.assertIn("diagnostic=", message)

    def test_launch_error_rejected_with_evidence(self):
        with self.assertRaises(SystemExit) as ctx:
            build_receipt.probe_tool_version(
                ["missing-tool", "--version"], ".",
                run=_run(error=OSError(2, "No such file or directory")))
        message = str(ctx.exception.code)
        self.assertIn("argv=", message)
        self.assertIn("missing-tool", message)
        self.assertIn("exit=launch-error", message)
        self.assertIn("diagnostic=", message)
        self.assertIn("No such file or directory", message)

    def test_main_emits_no_receipt_when_probe_fails(self):
        build_dir = "selftest-no-such-build-dir"
        self.assertFalse((ROOT / build_dir).exists())
        saved_run = build_receipt.subprocess.run
        saved_manifest = build_receipt.provenance.source_manifest
        build_receipt.subprocess.run = _run(_Result(9, "bogus 1.0\n"))
        build_receipt.provenance.source_manifest = (
            lambda root: {"digest": "selftest-fake"})
        try:
            with self.assertRaises(SystemExit) as ctx:
                build_receipt.main(
                    ["build_receipt.py", build_dir, "cc", "off"])
            self.assertIn("exit=9", str(ctx.exception.code))
            self.assertFalse(
                (ROOT / build_dir / "build-receipt.json").exists())
        finally:
            build_receipt.subprocess.run = saved_run
            build_receipt.provenance.source_manifest = saved_manifest


if __name__ == "__main__":
    unittest.main()
