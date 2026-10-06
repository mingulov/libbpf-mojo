#!/usr/bin/env python3
"""Write the package MANIFEST.json. Invoked by tools/package.

Usage: package_manifest.py <version> <stage> <lock> <receipt>
                           <build-dir> <sysneeds> <pixi-lib>
                           <libbpf-src>

Verifies the build receipt four ways — build outputs, staged
copies, worktree sources, and conda runtime bytes all match
their seals — then records bridge/BPF/build identities plus
per-file hashes so a redistributed tarball stays auditable. Any
mismatch (stale tree, torn copy, concurrent rebuild, mid-build
edit, altered runtime) fails packaging. Shares
tools/provenance.py and tools/package_runtime.py. Standard
library only.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import package_runtime  # noqa: E402
import provenance  # noqa: E402

# Receipt artifact path (under the build dir) to staged path: the
# ship list. fault_driver is a receipt artifact but not shipped;
# it stays covered by the build-dir check.
STAGED = {
    "libbpf_mojo.so.1": "lib/libbpf_mojo.so.1",
    "examples/tracepoint_main": "examples/tracepoint_main",
    "examples/tracepoint_trigger": "examples/tracepoint_trigger",
    "examples/probe.bpf.o": "examples/probe.bpf.o",
    "examples/reference_consumer": "examples/reference_consumer",
}

# Staged path to source-seal path for files copied from the
# worktree: the copies are bound to their sealed hashes, so an
# altered staged header, runner, or notice fails instead of
# shipping under the original seal.
SEALED_COPIES = {
    "include/libbpf_mojo.h": "native/include/libbpf_mojo.h",
    "mojo/libbpf_mojo/__init__.mojo": "src/libbpf_mojo/__init__.mojo",
    "mojo/libbpf_mojo/_ffi.mojo": "src/libbpf_mojo/_ffi.mojo",
    "mojo/libbpf_mojo/batch.mojo": "src/libbpf_mojo/batch.mojo",
    "mojo/libbpf_mojo/error.mojo": "src/libbpf_mojo/error.mojo",
    "mojo/libbpf_mojo/session.mojo": "src/libbpf_mojo/session.mojo",
    "run-tracepoint.sh": "examples/tracepoint/run-tracepoint.sh",
    "licenses/GPL-3.0.txt": "tools/notices/GPL-3.0.txt",
    "licenses/RUNTIME.LIBRARY.EXCEPTION":
        "tools/notices/GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt",
    "licenses/LICENSE.zlib": "tools/notices/ZLIB.txt",
}

# Bundled soname to the notice files that must cover it. A bundled
# library without an entry fails packaging: new components need a
# human-written notice mapping, never a silent omission.
SONAME_NOTICES = {
    "libgcc_s.so.1": ("licenses/RUNTIME.LIBRARY.EXCEPTION",
                      "licenses/GPL-3.0.txt"),
    "libstdc++.so.6": ("licenses/RUNTIME.LIBRARY.EXCEPTION",
                       "licenses/GPL-3.0.txt"),
    "libz.so.1": ("licenses/LICENSE.zlib",),
    "libKGENCompilerRTShared.so": ("licenses/NOTICE.mojo-runtime.md",
                                  "licenses/LICENSE.mojo-compiler",
                                  "licenses/Third-Party-Notices."
                                  "mojo-compiler"),
    "libMSupportGlobals.so": ("licenses/NOTICE.mojo-runtime.md",
                              "licenses/LICENSE.mojo-compiler",
                              "licenses/Third-Party-Notices."
                              "mojo-compiler"),
    "libAsyncRTRuntimeGlobals.so": ("licenses/NOTICE.mojo-runtime.md",
                                   "licenses/LICENSE.mojo-compiler",
                                   "licenses/Third-Party-Notices."
                                   "mojo-compiler"),
}


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _check_staged_licenses(pixi_lib, stage):
    """Re-bind staged proprietary licenses to package bytes.

    Mirrors the notices step independently: same owner trace,
    same expected file set, and the staged bytes must equal
    the package's own license files.
    """
    prefix = os.path.dirname(os.path.abspath(pixi_lib.rstrip("/")))
    by_file = package_runtime.load_file_index(prefix)
    seen = set()
    for soname in package_runtime.staged_runtime_libs(stage):
        meta = package_runtime.trace_owner(
            by_file, prefix, pixi_lib, soname)
        if meta is None:
            raise package_runtime.AttributionError(
                "%s traces to no conda package" % soname)
        if not meta.get("license", "").startswith("LicenseRef"):
            continue
        key = (meta["name"], meta["version"], meta["build"])
        if key in seen:
            continue
        seen.add(key)
        mapping = package_runtime.PROPRIETARY_LICENSES.get(meta["name"])
        if mapping is None:
            raise package_runtime.AttributionError(
                "no license mapping for proprietary package %s"
                % meta["name"])
        pkgdir = package_runtime.package_dir(*key)
        if pkgdir is None:
            raise package_runtime.AttributionError(
                "package %s %s (%s) has no extracted cache dir" % key)
        found = package_runtime.package_license_files(
            prefix, pkgdir, *key)
        if set(found) != set(mapping):
            raise package_runtime.AttributionError(
                "package %s %s (%s) license set changed" % key)
        for base, staged_rel in sorted(mapping.items()):
            staged = os.path.join(stage, staged_rel)
            if not os.path.isfile(staged):
                raise package_runtime.AttributionError(
                    "staged license missing: %s" % staged_rel)
            if sha256_of(staged) != package_runtime.sha256_of(
                    found[base]):
                raise package_runtime.AttributionError(
                    "staged %s does not match package "
                    "%s %s (%s) bytes" % ((staged_rel,) + key))


def main(argv):
    if len(argv) != 9:
        sys.exit("usage: package_manifest.py <version> <stage> <lock> "
                 "<receipt> <build-dir> <sysneeds> <pixi-lib> "
                 "<libbpf-src>")
    version, stage, lock_path = argv[1], argv[2], argv[3]
    receipt_path, build_dir, sysneeds_path = argv[4], argv[5], argv[6]
    pixi_lib, libbpf_src = argv[7], argv[8]
    with open(lock_path, "r", encoding="utf-8") as handle:
        lock = json.load(handle)
    with open(receipt_path, "r", encoding="utf-8") as handle:
        receipt = json.load(handle)
    if not receipt.get("cmake_cache_sha256"):
        sys.exit("manifest: receipt seals no native configuration; "
                 "rebuild with current tools/build")
    for rel, want in sorted(receipt.get("artifacts", {}).items()):
        full = os.path.join(build_dir, rel)
        if not os.path.isfile(full):
            sys.exit("manifest: receipt artifact missing: %s" % rel)
        if sha256_of(full) != want:
            sys.exit("manifest: stale build tree: %s changed since "
                     "tools/build ran; rebuild before packaging" % rel)
    # The seal binds the staged copies, not just the build dir: a
    # torn copy or a concurrent rebuild between staging and this
    # check mismatches and fails instead of shipping. The ship
    # list drives: receipt-only artifacts (fault_driver) stay
    # covered by the build-dir check above.
    sealed_artifacts = receipt.get("artifacts", {})
    for rel, staged_rel in sorted(STAGED.items()):
        want = sealed_artifacts.get(rel)
        if want is None:
            sys.exit("manifest: receipt seals no hash for %s; rebuild "
                     "with current tools/build" % rel)
        full = os.path.join(stage, staged_rel)
        if not os.path.isfile(full):
            sys.exit("manifest: staged artifact missing: %s" % staged_rel)
        if sha256_of(full) != want:
            sys.exit("manifest: staged %s does not match its receipt "
                     "hash (torn copy or concurrent rebuild); rebuild "
                     "and repackage from a quiet tree" % staged_rel)
    root = os.path.dirname(os.path.abspath(build_dir))
    provenance.check_manifest(root, receipt.get("sources"), "manifest")
    sealed_sources = receipt.get("sources", {}).get("files", {})
    for staged_rel, sealed_rel in sorted(SEALED_COPIES.items()):
        want = sealed_sources.get(sealed_rel, {}).get("sha256")
        if want is None:
            sys.exit("manifest: receipt seals no hash for %s; rebuild "
                     "with current tools/build" % sealed_rel)
        full = os.path.join(stage, staged_rel)
        if not os.path.isfile(full):
            sys.exit("manifest: staged copy missing: %s" % staged_rel)
        if sha256_of(full) != want:
            sys.exit("manifest: staged %s does not match its sealed "
                     "source %s (torn copy or mid-flow edit); rebuild "
                     "and repackage from a quiet tree"
                     % (staged_rel, sealed_rel))
    libbpf_license = os.path.join(libbpf_src, "LICENSE.BSD-2-Clause")
    staged_libbpf = os.path.join(
        stage, "licenses", "LICENSE.BSD-2-Clause.libbpf")
    if not os.path.isfile(libbpf_license):
        sys.exit("manifest: missing libbpf license in build tree")
    if not os.path.isfile(staged_libbpf):
        sys.exit("manifest: staged libbpf license missing")
    if sha256_of(staged_libbpf) != sha256_of(libbpf_license):
        sys.exit("manifest: staged libbpf license does not match "
                 "the build-tree copy (torn copy or mid-flow edit)")
    try:
        verified = package_runtime.verify_staged_runtime(
            pixi_lib, stage)
    except package_runtime.AttributionError as exc:
        sys.exit("manifest: %s" % exc)
    try:
        _check_staged_licenses(pixi_lib, stage)
    except package_runtime.AttributionError as exc:
        sys.exit("manifest: %s" % exc)
    with open(sysneeds_path, "r", encoding="utf-8") as handle:
        system_needs = sorted({line.strip() for line in handle
                               if line.strip()})
    files = []
    for dirpath, _dirnames, filenames in os.walk(stage):
        for name in sorted(filenames):
            if name == "MANIFEST.json":
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, stage)
            files.append({
                "path": rel,
                "sha256": sha256_of(full),
                "bytes": os.path.getsize(full),
            })
    files.sort(key=lambda row: row["path"])
    by_path = {row["path"]: row["sha256"] for row in files}
    bridge = by_path.get("lib/libbpf_mojo.so.1")
    bpf = by_path.get("examples/probe.bpf.o")
    if not bridge or not bpf:
        sys.exit("manifest: staged bridge or BPF object missing")
    bundled = sorted(path for path in by_path
                     if path.startswith("lib/")
                     and path != "lib/libbpf_mojo.so.1")
    coverage = {}
    for path in bundled:
        soname = os.path.basename(path)
        notices = SONAME_NOTICES.get(soname)
        if notices is None:
            sys.exit("manifest: no notice mapping for bundled %s; "
                     "add notices before packaging" % soname)
        for notice in notices:
            if notice not in by_path:
                sys.exit("manifest: %s lacks staged notice %s"
                         % (soname, notice))
        coverage[path] = sorted(notices)
    manifest = {
        "package": "libbpf-mojo",
        "version": version,
        "abi": "lmb-v1",
        "build": {
            "arch": os.uname().machine,
            "cpu_baseline": receipt.get("mojo_target_cpu", "unknown"),
            "kernel_min": "7.0",
            "glibc_min": "2.38",
            "toolchain_expected": lock.get("expected_first_lines", {}),
            "receipt": receipt,
        },
        "bridge": {
            "file": "lib/libbpf_mojo.so.1",
            "sha256": bridge,
        },
        "bpf": {
            "file": "examples/probe.bpf.o",
            "sha256": bpf,
        },
        "runtime": {
            "needs": ["glibc", "libelf", "zlib", "bpf-privilege"],
            "system_libraries": system_needs,
            "bundled_libs": bundled,
            "verified": verified,
        },
        "licenses": coverage,
        "files": files,
    }
    with open(os.path.join(stage, "MANIFEST.json"), "w",
              encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main(sys.argv)
