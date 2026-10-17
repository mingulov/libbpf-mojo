#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The package lane records the pinned clean-room base digest."""

import importlib.util
import os
import re
import sys
import unittest
from importlib.machinery import SourceFileLoader

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))


def load_package_lane():
    path = os.path.join(ROOT, "tests", "package", "test_package.py")
    loader = SourceFileLoader("lmbpackagelane", path)
    spec = importlib.util.spec_from_loader("lmbpackagelane", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class CleanBase(unittest.TestCase):
    def test_base_digest_is_pinned(self):
        lane = load_package_lane()
        digest = lane.clean_base_digest()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        with open(os.path.join(
                ROOT, "tests", "package",
                "Dockerfile.clean")) as handle:
            text = handle.read()
        self.assertIn(digest, text)


if __name__ == "__main__":
    unittest.main()
