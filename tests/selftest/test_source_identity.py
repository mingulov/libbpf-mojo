#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Real Git ownership controls for source exports and linked worktrees."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import build_receipt
import provenance


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args],
                                   stderr=subprocess.DEVNULL, text=True).strip()


def checkout(root):
    root.mkdir()
    git(root, "init", "-q")
    (root / ".gitignore").write_text("exports/\n")
    git(root, "add", ".gitignore")
    git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "initial")


class SourceIdentity(unittest.TestCase):
    def test_exports_do_not_borrow_clean_or_dirty_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "parent"
            checkout(parent)
            export = parent / "exports" / "source"
            export.mkdir(parents=True)
            (export / "input.txt").write_text("source\n")
            for dirty in (False, True):
                if dirty:
                    (parent / "unrelated.txt").write_text("dirty\n")
                sealed = provenance.source_manifest(str(export))
                self.assertEqual(sealed["mode"], "archive")
                self.assertEqual(set(sealed["files"]), {"input.txt"})
                self.assertEqual(build_receipt.git_sha(str(export)), "unknown")
                with self.assertRaises(SystemExit):
                    provenance.source_manifest(str(export), "git")

    def test_checkout_and_git_file_worktree_keep_own_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "parent"
            checkout(parent)
            head = git(parent, "rev-parse", "HEAD")
            linked = Path(tmp) / "linked"
            git(parent, "worktree", "add", "--detach", str(linked), "HEAD")
            self.assertTrue((linked / ".git").is_file())
            for root in (parent, linked):
                self.assertEqual(build_receipt.git_sha(str(root)), head)
                self.assertEqual(provenance.source_manifest(str(root))["mode"], "git")
                (root / "new.txt").write_text("dirty\n")
                self.assertEqual(build_receipt.git_sha(str(root)), head + "-dirty")
            # A canonical path alias still names the actual checkout.
            alias = Path(tmp) / "alias"
            alias.symlink_to(parent, target_is_directory=True)
            self.assertEqual(build_receipt.git_sha(str(alias)), head + "-dirty")

    def test_archive_timestamp_is_stable_and_override_is_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            for supplied, expected in ((None, 0), ("0", 0), ("1700000000", 1700000000)):
                self.assertEqual(provenance.archive_mtime(tmp, supplied), expected)
            for bad in ("", "-1", "+1", "1.0", " 1", "1\n", "abc", "١", "99999999999999999999"):
                with self.subTest(bad=bad), self.assertRaises(SystemExit):
                    provenance.archive_mtime(tmp, bad)
            parent = Path(tmp) / "parent"
            checkout(parent)
            expected = int(git(parent, "log", "-1", "--format=%ct"))
            self.assertEqual(provenance.archive_mtime(str(parent), None), expected)
            export = parent / "exports"
            export.mkdir()
            self.assertEqual(provenance.archive_mtime(str(export), None), 0)


if __name__ == "__main__":
    unittest.main()
