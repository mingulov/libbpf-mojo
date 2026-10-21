#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The package lane records the pinned clean-room base digest."""

import contextlib
import importlib.util
import io
import os
import re
import sys
import unittest
from importlib.machinery import SourceFileLoader
from types import SimpleNamespace
from unittest import mock

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

    def test_clean_room_emits_pinned_digest(self):
        lane = load_package_lane()
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return SimpleNamespace(returncode=0,
                                   stdout="CLEAN-PASS\n")

        out = io.StringIO()
        with mock.patch.object(lane.shutil, "which",
                               return_value="/usr/bin/docker"), \
                mock.patch.object(lane, "run",
                                  side_effect=fake_run), \
                mock.patch.object(lane, "remove_owned_container",
                                  return_value=None), \
                contextlib.redirect_stdout(out):
            lane.clean_room("dummy.tgz", "0.2.1")
        digest = lane.clean_base_digest()
        self.assertIn("clean base: ubuntu:26.04@sha256:"
                      + digest, out.getvalue())
        self.assertIn("clean room: CLEAN-PASS", out.getvalue())
        self.assertTrue(any(cmd[:2] == ["docker", "build"]
                            for cmd in calls))


if __name__ == "__main__":
    unittest.main()
