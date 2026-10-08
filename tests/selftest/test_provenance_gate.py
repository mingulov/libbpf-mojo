#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unprivileged probes for the provenance gate itself.

The gate must pass on a sourceless export: without git
metadata it falls back to the declared archive inventory
instead of failing. It must also fail closed when the
build's dependency pins or version constants drift from
the lock and the ABI contract: a mismatched CMake
URL/hash, header constant, or document version fails the
gate instead of passing on syntax alone. Standard library
only; exit 0 on pass, 1 on failure.
"""

# (label, tree-relative file, exact anchor, tampered text,
#  expected FAIL line): anchors must match the live tree
# exactly, so a legitimate pin change breaks loudly here
# instead of silently disabling the control.
NEGATIVES = [
    ("cmake-sha", "native/CMakeLists.txt",
     'set(LIBBPF_SHA256 '
     '"7ab5feffbf78557f626f2e3e3204788528394494715a30fc2070fcddc2051b7b")',
     'set(LIBBPF_SHA256 "' + "0" * 64 + '")',
     "FAIL lock-libbpf-matches-cmake"),
    ("cmake-url", "native/CMakeLists.txt",
     'set(LIBBPF_URL "https://github.com/libbpf/libbpf/archive/'
     'refs/tags/v1.7.0.tar.gz")',
     'set(LIBBPF_URL "https://github.com/libbpf/libbpf/archive/'
     'refs/tags/v9.9.9.tar.gz")',
     "FAIL lock-libbpf-matches-cmake"),
    ("header-abi", "native/include/libbpf_mojo.h",
     "LMB_ABI_VERSION = 1,",
     "LMB_ABI_VERSION = 2,",
     "FAIL abi-constants"),
    ("doc-framing", "docs/abi-v1.md",
     "| 4 | u16 LE | framing version, must be 1 |",
     "| 4 | u16 LE | framing version, must be 2 |",
     "FAIL abi-versions-agree"),
]

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def ignore_env_dirs(path, names):
    """copytree ignore: environment dirs, never same-named files."""
    skipped = {".git", ".pixi", "build", "build-san", "dist",
               "__pycache__", ".pytest_cache", ".mypy_cache"}
    return [name for name in names
            if name in skipped
            and os.path.isdir(os.path.join(path, name))]


def run_gate(tree):
    """Run the provenance gate with cwd inside tree."""
    return subprocess.run(
        [sys.executable, os.path.join(
            tree, "tests", "provenance", "test_provenance.py")],
        cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)


def tamper(path, old, new):
    """Replace one anchor; False when the anchor is missing."""
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if old not in text:
        return False
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text.replace(old, new, 1))
    return True


def negative(dest, rel, old, new, want):
    """Tampered trees must fail the gate naming want."""
    if not tamper(os.path.join(dest, rel), old, new):
        return "tamper anchor missing in %s" % rel
    out = run_gate(dest)
    if out.returncode == 0:
        return "gate passed a tampered tree (%s)" % rel
    if want not in out.stdout:
        return ("gate failed without naming %s: %s"
                % (want, out.stdout.strip()))
    return None


def main():
    # 1. A sourceless export passes the gate: no .git, no
    # failure, and the passing seal line on stdout.
    stage = tempfile.mkdtemp(prefix="gate-archive-")
    try:
        dest = os.path.join(stage, "tree")
        shutil.copytree(ROOT, dest, ignore=ignore_env_dirs)
        if os.path.isdir(os.path.join(dest, ".git")):
            return "sourceless copy still carries .git"
        out = run_gate(dest)
        if out.returncode != 0:
            return ("sourceless gate failed (exit %d): %s%s"
                    % (out.returncode, out.stdout.strip(),
                       out.stderr.strip()))
        if "provenance: all checks passed" not in out.stdout:
            return "sourceless gate passed without the seal line"
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    # 2-5. Each pin/version drift fails its own check.
    for label, rel, old, new, want in NEGATIVES:
        stage = tempfile.mkdtemp(prefix="gate-negative-")
        try:
            dest = os.path.join(stage, "tree")
            shutil.copytree(ROOT, dest, ignore=ignore_env_dirs)
            error = negative(dest, rel, old, new, want)
            if error is not None:
                return "%s: %s" % (label, error)
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    print("PASS test_provenance_gate: sourceless export passes, "
          "4 pin/version negatives fail")
    return None


if __name__ == "__main__":
    error = main()
    if error is not None:
        print("FAIL test_provenance_gate: %s" % error, file=sys.stderr)
        sys.exit(1)
