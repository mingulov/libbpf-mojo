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
    ("bpftool", ["bpftool", "--version"]),
    ("cmake", ["cmake", "--version"]),
    ("ninja", ["ninja", "--version"]),
    ("make", ["make", "--version"]),
    ("gcc", ["gcc", "--version"]),
    ("pkg-config", ["pkg-config", "--version"]),
    ("zlib", ["pkg-config", "--modversion", "zlib"]),
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


def dependency_identities(root):
    """Pinned dependency bytes the build consumed."""
    lock_path = os.path.join(root, "toolchain.lock.json")
    with open(lock_path, "r", encoding="utf-8") as handle:
        lock = json.load(handle)
    return {
        "libbpf_tarball_sha256": lock["toolchain"][
            "libbpf_source"]["tarball_sha256"],
    }


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


def probe_tool_version(cmd, cwd, run=None):
    """Return the stripped first line of a tool-version probe.

    Fails closed: a probe that cannot launch, exits nonzero, or
    yields no version line aborts the receipt instead of recording
    a guess. Every failure retains the exact argv, the exit status,
    and the diagnostic output. The optional run hook executes the
    probe; tests inject fakes, production uses subprocess.run.
    """
    runner = run if run is not None else subprocess.run
    try:
        out = runner(cmd, cwd=cwd, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, text=True)
    except OSError as exc:
        sys.exit("receipt: tool probe failed to launch: argv=%r "
                 "exit=launch-error diagnostic=%r" % (cmd, str(exc)))
    diagnostic = out.stdout if out.stdout else ""
    if out.returncode != 0:
        sys.exit("receipt: tool probe failed: argv=%r exit=%d "
                 "diagnostic=%r"
                 % (cmd, out.returncode, diagnostic.strip()))
    first = diagnostic.splitlines()[0] if diagnostic.strip() else ""
    if not first.strip():
        sys.exit("receipt: tool probe returned no version output: "
                 "argv=%r exit=%d diagnostic=%r"
                 % (cmd, out.returncode, diagnostic.strip()))
    return first.strip()


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
        toolchain[name] = probe_tool_version(cmd, root)
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
        "dependencies": dependency_identities(root),
        "artifacts": artifacts,
    }
    path = os.path.join(root, build_dir, "build-receipt.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("receipt: %s" % path)


if __name__ == "__main__":
    main(sys.argv)
