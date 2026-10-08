#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unprivileged probes for tools/provenance.py inventories.

Git checkouts and sourceless archives must seal the same file
set; seals must be deterministic, round-trip through the check,
and reject drift (modified, added, removed files). Receipts
sealed before inventory modes existed verify as git. Standard
library only; exit 0 on pass, 1 on failure.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import provenance  # noqa: E402


def check_fails(root, sealed):
    """True when check_manifest rejects (SystemExit)."""
    try:
        provenance.check_manifest(root, sealed, "selftest")
    except SystemExit:
        return True
    return False


def ignore_env_dirs(path, names):
    """copytree ignore: environment dirs, never same-named files."""
    skipped = {".git", ".pixi", "build", "build-san", "dist",
               "__pycache__", ".pytest_cache", ".mypy_cache"}
    return [name for name in names
            if name in skipped
            and os.path.isdir(os.path.join(path, name))]


def main():
    # 1. Both modes deterministic over the live checkout.
    git_once = provenance.source_manifest(ROOT, "git")
    git_twice = provenance.source_manifest(ROOT, "git")
    if git_once["digest"] != git_twice["digest"]:
        return "git seal not deterministic"
    if git_once["mode"] != "git":
        return "git seal records mode %r" % (git_once["mode"],)
    arc_once = provenance.source_manifest(ROOT, "archive")
    arc_twice = provenance.source_manifest(ROOT, "archive")
    if arc_once["digest"] != arc_twice["digest"]:
        return "archive seal not deterministic"
    if arc_once["mode"] != "archive":
        return "archive seal records mode %r" % (arc_once["mode"],)

    # 2. Same tree, same file set in both modes: the declared
    # archive excludes must mirror .gitignore exactly here.
    only_git = sorted(set(git_once["files"]) - set(arc_once["files"]))
    only_arc = sorted(set(arc_once["files"]) - set(git_once["files"]))
    if only_git or only_arc:
        return ("inventory file sets differ: git-only %r, "
                "archive-only %r" % (only_git[:5], only_arc[:5]))
    if git_once["digest"] != arc_once["digest"]:
        return "same files but different digests across modes"

    # 3. Both seals round-trip through the check.
    provenance.check_manifest(ROOT, git_once, "selftest")
    provenance.check_manifest(ROOT, arc_once, "selftest")

    # 4. Drift is rejected: modify, add, remove.
    tmp = tempfile.mkdtemp(prefix="seal-drift-")
    try:
        with open(os.path.join(tmp, "a.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("a\n")
        with open(os.path.join(tmp, "b.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("b\n")
        sealed = provenance.source_manifest(tmp, "archive")
        provenance.check_manifest(tmp, sealed, "selftest")
        with open(os.path.join(tmp, "a.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("modified\n")
        if not check_fails(tmp, sealed):
            return "modified file accepted"
        with open(os.path.join(tmp, "a.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("a\n")
        with open(os.path.join(tmp, "c.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("c\n")
        if not check_fails(tmp, sealed):
            return "added file accepted"
        os.unlink(os.path.join(tmp, "c.txt"))
        os.unlink(os.path.join(tmp, "b.txt"))
        if not check_fails(tmp, sealed):
            return "removed file accepted"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 5. A sourceless copy seals via the CLI (the tools/build
    # path) in archive mode and verifies.
    stage = tempfile.mkdtemp(prefix="seal-archive-")
    try:
        dest = os.path.join(stage, "tree")
        shutil.copytree(ROOT, dest, ignore=ignore_env_dirs)
        out = subprocess.run(
            [sys.executable,
             os.path.join(ROOT, "tools", "provenance.py"),
             "seal", dest],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if out.returncode != 0:
            return "CLI seal of sourceless tree failed: %s" % out.stderr
        sealed = json.loads(out.stdout)
        if sealed["mode"] != "archive":
            return "sourceless seal records mode %r" % sealed["mode"]
        provenance.check_manifest(dest, sealed, "selftest")
        if set(sealed["files"]) != set(git_once["files"]):
            return "sourceless file set differs from checkout"
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    # 6. Pre-mode receipts verify as git.
    legacy = {"files": git_once["files"], "digest": git_once["digest"]}
    provenance.check_manifest(ROOT, legacy, "selftest")

    # 7. A git seal cannot be checked without git metadata:
    # the check must fail on the missing inventory, not compare
    # across modes (the files below match on purpose).
    bare = tempfile.mkdtemp(prefix="seal-bare-")
    try:
        with open(os.path.join(bare, "a.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("a\n")
        forged = provenance.source_manifest(bare, "archive")
        forged["mode"] = "git"
        try:
            provenance.check_manifest(bare, forged, "selftest")
        except SystemExit as exc:
            if "git inventory unavailable" not in str(exc):
                return ("git-seal-in-archive failed wrong: %s" % exc)
        else:
            return "git seal verified without git metadata"
    finally:
        shutil.rmtree(bare, ignore_errors=True)

    print("PASS test_archive_seal: determinism, parity, round-trip, "
          "drift, sourceless, legacy, no-cross-mode")
    return None


if __name__ == "__main__":
    error = main()
    if error is not None:
        print("FAIL test_archive_seal: %s" % error, file=sys.stderr)
        sys.exit(1)
