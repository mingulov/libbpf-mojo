#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Provenance gate: licenses, pins, versions, and packager inputs.

Every first-party source file carries an SPDX identifier from a
known set with its license text staged; upstream notice texts stay
verbatim and untagged; the toolchain lock pins libbpf by hash with
no unknown origins and agrees with the pixi manifest; the package
version, native ABI version, and wire framing version stay
distinct; and every static input tools/package needs from this
tree exists. Exits nonzero on the first failure.
Standard library only.
"""

import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import provenance  # noqa: E402

KNOWN_IDS = {
    "GPL-3.0-or-later": "LICENSE",
    "GPL-2.0-only": "LICENSES/GPL-2.0-only.txt",
    "GPL-2.0-or-later": "LICENSES/GPL-2.0-or-later.txt",
}

CODE_SUFFIXES = (
    ".mojo", ".c", ".h", ".py", ".sh", ".md", ".yml", ".yaml",
)
CODE_BASENAMES = ("Makefile", "CMakeLists.txt", "Dockerfile")
SKIP_DIRS = ("build", "build-san", "dist", ".pixi", "__pycache__",
             ".pytest_cache", ".git", ".mypy_cache")

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def tracked_files():
    rels = provenance.git_files(ROOT)
    if rels is None:
        rels = provenance.archive_files(ROOT)
    return rels


def is_code(rel):
    parts = rel.split("/")
    if any(part in SKIP_DIRS for part in parts[:-1]):
        return False
    # Verbatim upstream license texts: tagging them with our own
    # SPDX line would misattribute them.
    if parts[0] == "tools" and len(parts) > 2 and parts[1] == "notices" \
            and parts[-1].endswith(".txt"):
        return False
    base = parts[-1]
    if rel == "pixi.toml" or parts[0] == "tools":
        return True
    if base in CODE_BASENAMES or base.startswith("Dockerfile"):
        return True
    return base.endswith(CODE_SUFFIXES)


def spdx_of(path):
    with open(path, "rb") as handle:
        head = handle.read(4096).decode("utf-8", "replace")
    match = re.search(r"SPDX-License-Identifier:\s*(\S+)", head)
    return match.group(1) if match else None


def main():
    files = tracked_files()
    check("file-inventory-nonempty", len(files) > 50,
          "got %d" % len(files))

    offenders = []
    seen_ids = set()
    for rel in sorted(files):
        if not is_code(rel):
            continue
        found = spdx_of(os.path.join(ROOT, rel))
        if found is None:
            offenders.append(rel + " (missing)")
        elif found not in KNOWN_IDS:
            offenders.append(rel + " (unknown id %s)" % found)
        else:
            seen_ids.add(found)
    check("spdx-coverage", not offenders, "; ".join(offenders[:5]))

    for ident in sorted(seen_ids):
        staged = os.path.join(ROOT, KNOWN_IDS[ident])
        check("license-text-%s" % ident, os.path.isfile(staged), staged)
    check("license-default", os.path.isfile(os.path.join(ROOT, "LICENSE")))

    for name in ("GPL-3.0.txt", "ZLIB.txt",
                 "GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt"):
        path = os.path.join(ROOT, "tools", "notices", name)
        check("notice-input-%s" % name,
              os.path.isfile(path) and os.path.getsize(path) > 100,
              path)

    lock_path = os.path.join(ROOT, "toolchain.lock.json")
    with open(lock_path) as handle:
        lock = json.load(handle)
    check("lock-version", lock.get("lock_version") == "1.0.0")
    libbpf = lock["toolchain"]["libbpf_source"]
    check("lock-libbpf-pin",
          libbpf.get("version") == "1.7.0"
          and HEX40.match(libbpf.get("commit", ""))
          and HEX64.match(libbpf.get("tarball_sha256", "")),
          json.dumps(libbpf, sort_keys=True)[:160])
    with open(os.path.join(ROOT, "native", "CMakeLists.txt")) as handle:
        cmake = handle.read()
    murl = re.search(r'set\(LIBBPF_URL\s+"([^"]+)"\)', cmake)
    msha = re.search(r'set\(LIBBPF_SHA256\s+"([^"]+)"\)', cmake)
    check("cmake-libbpf-pin-present", bool(murl) and bool(msha))
    check("lock-libbpf-matches-cmake",
          libbpf.get("tarball_url") == murl.group(1)
          and libbpf.get("tarball_sha256") == msha.group(1),
          "lock %.12s / cmake %.12s"
          % (libbpf.get("tarball_sha256", ""), msha.group(1)))
    dumped = json.dumps(lock).lower()
    check("lock-no-unknown",
          "unknown" not in dumped and "tbd" not in dumped)

    with open(os.path.join(ROOT, "pixi.toml")) as handle:
        pixi = handle.read()
    mver = re.search(r'^version\s*=\s*"([^"]+)"', pixi, re.M)
    mmojo = re.search(r'^mojo\s*=\s*"==([^"]+)"', pixi, re.M)
    check("pixi-manifest", bool(mver) and bool(mmojo))
    check("lock-mojo-agrees-pixi",
          lock["toolchain"]["mojo"]["version"] == mmojo.group(1))
    check("pixi-license-declared", 'license = "GPL-3.0-or-later"' in pixi)

    abi_doc = os.path.join(ROOT, "docs", "abi-v1.md")
    check("abi-doc-present", os.path.isfile(abi_doc))
    with open(abi_doc) as handle:
        abi = handle.read()
    check("abi-version-pinned", "Must be 1" in abi)
    headers = sorted(glob.glob(
        os.path.join(ROOT, "native", "include", "*.h")))
    check("abi-headers-present", len(headers) >= 1)
    with open(headers[0]) as handle:
        header = handle.read()
    check("abi-version-field", "abi_version" in header)
    mabi = re.search(r"LMB_ABI_VERSION\s*=\s*(\d+)", header)
    mframe = re.search(r"LMB_FRAME_VERSION\s*=\s*(\d+)", header)
    check("abi-constants", bool(mabi) and bool(mframe)
          and mabi.group(1) == "1" and mframe.group(1) == "1",
          os.path.basename(headers[0]))
    mdoc_abi = re.search(r"`abi_version` \| Must be (\d+)", abi)
    mdoc_frame = re.search(r"framing version, must be (\d+)", abi)
    check("abi-doc-versions", bool(mdoc_abi) and bool(mdoc_frame))
    check("abi-versions-agree",
          mdoc_abi.group(1) == mabi.group(1)
          and mdoc_frame.group(1) == mframe.group(1))

    static_inputs = [
        "LICENSE",
        "LICENSES/GPL-2.0-only.txt", "LICENSES/GPL-2.0-or-later.txt",
        "tools/package", "tools/package_notices.py",
        "tools/package_manifest.py",
        "examples/tracepoint/main.mojo",
        "examples/tracepoint/probe.bpf.c",
        "examples/tracepoint/event.h",
        "tests/package/test_package.py",
        "tests/package/consumer_main.mojo",
        "tests/package/Dockerfile.clean",
        "tests/package/clean-check.sh",
        "toolchain.lock.json",
    ]
    missing = [rel for rel in static_inputs
               if not os.path.isfile(os.path.join(ROOT, rel))]
    check("package-static-inputs", not missing, "; ".join(missing))
    for rel in ("native/src", "native/include", "src/libbpf_mojo"):
        check("package-dir-%s" % rel.replace("/", "-"),
              os.path.isdir(os.path.join(ROOT, rel)))

    print("provenance: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
