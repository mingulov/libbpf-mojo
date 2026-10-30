#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Build receipts retain every checked tool version and pin."""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import build_receipt


class ToolchainReceipt(unittest.TestCase):
    def test_probes_cover_checked_toolchain(self):
        names = [name for name, _ in build_receipt.PROBES]
        for name in ("pixi", "mojo", "clang", "bpftool", "cmake",
                     "ninja", "make", "gcc", "pkg-config",
                     "zlib", "python"):
            self.assertIn(name, names, names)

    def test_cmake_floor_matches_lock(self):
        lock = json.loads(
            (ROOT / "toolchain.lock.json").read_text())
        pinned = lock["minimum_versions"]["cmake"]
        text = (ROOT / "native/CMakeLists.txt").read_text()
        match = re.search(
            r"cmake_minimum_required\(VERSION ([0-9.]+)\)", text)
        self.assertIsNotNone(match, "no cmake_minimum_required")
        self.assertEqual(match.group(1), pinned)

    def test_dependency_identities_read_lock_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = {"toolchain": {"libbpf_source": {
                "tarball_sha256": "l" * 64}}}
            (Path(tmp) / "toolchain.lock.json").write_text(
                json.dumps(lock))
            identities = build_receipt.dependency_identities(tmp)
            self.assertEqual(
                identities["libbpf_tarball_sha256"], "l" * 64)


if __name__ == "__main__":
    unittest.main()
