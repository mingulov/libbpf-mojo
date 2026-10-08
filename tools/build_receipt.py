#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Write the build receipt. Invoked by tools/build on success.

Usage: build_receipt.py <build-dir> <c-compiler> <sanitize-flag>

Records the OBSERVED build inputs: a sealed source manifest
(every input file, mode plus hash — not just HEAD plus "-dirty";
git inventory in a checkout, declared archive inventory in a
source tree without git metadata), toolchain versions as
executed, build
configuration, and hashes of the produced artifacts. The manifest
is sealed before compiling (tools/build writes sources-pre.json)
and re-sealed here; any mid-build edit fails the receipt.
tools/package requires this receipt, re-hashes the staged
artifacts against it, and rejects worktree drift, so a stale or
mixed tree cannot be packaged. Shares tools/provenance.py.
Standard library only.
"""

import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import provenance  # noqa: E402

PROBES = [
    ("pixi", ["pixi", "--version"]),
    ("mojo", ["pixi", "run", "--frozen", "mojo", "--version"]),
    ("clang", ["clang", "--version"]),
    ("cmake", ["cmake", "--version"]),
    ("ninja", ["ninja", "--version"]),
    ("gcc", ["gcc", "--version"]),
    ("python", ["python3", "--version"]),
]

ARTIFACTS = [
    "libbpf_mojo.so.1",
    "examples/tracepoint_main",
    "examples/tracepoint_trigger",
    "examples/probe.bpf.o",
    "examples/reference_consumer",
    "examples/fault_driver",
]


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_sha(root):
    if not provenance.owns_git_root(root):
        return "unknown"
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    sha = out.stdout.strip() if out.returncode == 0 else ""
    if not sha:
        return "unknown"
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if dirty.returncode != 0:
        sys.exit("receipt: cannot inspect owning Git tree")
    if dirty.stdout.strip():
        return sha + "-dirty"
    return sha


def main(argv):
    if len(argv) != 4:
        sys.exit("usage: build_receipt.py <build-dir> <cc> <sanitize>")
    build_dir, cc, sanitize = argv[1], argv[2], argv[3]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sealed = provenance.source_manifest(root)
    pre_path = os.path.join(root, build_dir, "sources-pre.json")
    if os.path.isfile(pre_path):
        with open(pre_path, "r", encoding="utf-8") as handle:
            pre = json.load(handle)
        if not isinstance(pre, dict) or pre.get("digest") != sealed["digest"]:
            sys.exit("receipt: sources changed during the build; "
                     "rebuild from a quiet tree")
    cache_path = os.path.join(root, build_dir, "CMakeCache.txt")
    cache_hash = provenance.sha256_of(cache_path) \
        if os.path.isfile(cache_path) else None
    toolchain = {}
    for name, cmd in PROBES:
        try:
            out = subprocess.run(cmd, cwd=root,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True)
        except OSError as exc:
            sys.exit("receipt: cannot run %s: %s" % (cmd[0], exc))
        first = out.stdout.splitlines()[0] if out.stdout else ""
        toolchain[name] = first.strip()
    artifacts = {}
    for rel in ARTIFACTS:
        full = os.path.join(root, build_dir, rel)
        if not os.path.isfile(full):
            sys.exit("receipt: missing build artifact: %s" % rel)
        artifacts[rel] = sha256_of(full)
    receipt = {
        "git": git_sha(root),
        "sources": sealed,
        "c_compiler": cc,
        "sanitize": sanitize,
        "mojo_target_cpu": "x86-64-v2",
        "cmake_cache_sha256": cache_hash,
        "toolchain_observed": toolchain,
        "artifacts": artifacts,
    }
    path = os.path.join(root, build_dir, "build-receipt.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("receipt: %s" % path)


if __name__ == "__main__":
    main(sys.argv)
