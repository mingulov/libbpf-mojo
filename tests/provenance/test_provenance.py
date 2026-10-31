#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Provenance gate: licenses, pins, versions, and packager inputs.

Every first-party source file carries an SPDX identifier from a
known set with its license text staged; upstream notice texts stay
verbatim and untagged; the toolchain lock pins libbpf by hash with
no unknown origins and agrees with the pixi manifest; the package
version, native ABI version, and wire framing version stay
distinct; the support envelope carries the ratified floor
sentence; every released version the policy names resolves
to a git tag; and every static input tools/package needs
from this tree exists. Exits nonzero on the first failure.
Standard library only.
"""

import glob
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import provenance  # noqa: E402

KNOWN_IDS = {
    "Apache-2.0 WITH LLVM-exception": (
        "LICENSE",
        "LICENSES/LLVM-exception.txt",
    ),
    "GPL-2.0-only": ("LICENSES/GPL-2.0-only.txt",),
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


def git_tags():
    """Tag set, or None when ROOT owns no git tree."""
    if not provenance.owns_git_root(ROOT):
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", ROOT, "tag", "--list"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return set(proc.stdout.split())


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
    # The identifier is a full SPDX expression, which may
    # contain spaces ("Apache-2.0 WITH LLVM-exception"), so
    # capture to end of line and strip the comment closer.
    match = re.search(r"SPDX-License-Identifier:\s*(.+)", head)
    if not match:
        return None
    found = match.group(1).strip()
    for closer in ("*/", "-->"):
        if found.endswith(closer):
            found = found[:-len(closer)].strip()
    return found


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
        for staged_rel in KNOWN_IDS[ident]:
            staged = os.path.join(ROOT, staged_rel)
            check("license-text-%s" % ident,
                  os.path.isfile(staged), staged)
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
    # The pixi release pin names the upstream x86-64 musl asset,
    # whose target triple legitimately contains "unknown" as the
    # vendor field; redact the authenticated pin before scanning
    # for placeholder text so the gate keeps its meaning.
    redacted = json.dumps(lock)
    for key in ("release_url", "release_asset"):
        redacted = redacted.replace(
            lock["toolchain"]["pixi"].get(key, ""), "")
    dumped = redacted.lower()
    check("lock-no-unknown",
          "unknown" not in dumped and "tbd" not in dumped)

    pixi_pin = lock["toolchain"]["pixi"]
    pixi_asset_ok = (
        pixi_pin.get("release_asset", "").startswith("pixi-")
        and pixi_pin.get("release_asset", "").endswith(".tar.gz"))
    pixi_url_ok = (pixi_pin.get("release_url")
                   == "https://github.com/prefix-dev/pixi/releases/"
                   "download/v%s/%s"
                   % (pixi_pin.get("version", ""),
                      pixi_pin.get("release_asset", "")))
    check("lock-pixi-release-pin",
          bool(pixi_pin.get("version"))
          and pixi_asset_ok and pixi_url_ok
          and HEX64.match(pixi_pin.get("release_sha256", "")),
          json.dumps(pixi_pin, sort_keys=True)[:160])

    workflows = sorted(glob.glob(os.path.join(
        ROOT, ".github", "workflows", "*.yml")))
    check("ci-workflows-present", len(workflows) >= 1,
          "found %d" % len(workflows))
    uses_pattern = re.compile(
        r"^\s*(?:-\s*)?uses:\s*(\S+)(?:\s+#\s*(.*?))?\s*$")
    ref_pattern = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
    tag_pattern = re.compile(r"^v\d+\.\d+\.\d+$")
    for path in workflows:
        base = os.path.basename(path)
        with open(path) as handle:
            text = handle.read()
        refs = []
        for lineno, line in enumerate(text.splitlines(), 1):
            match = uses_pattern.match(line)
            if match:
                refs.append((lineno, match.group(1),
                             (match.group(2) or "").strip()))
        check("ci-actions-pinned-%s" % base,
              len(refs) >= 1
              and all(ref_pattern.match(ref) for _, ref, _ in refs)
              and all(tag_pattern.match(tag) for _, _, tag in refs),
              "; ".join("line %d: %s%s" % (lineno, ref,
                                           " #%s" % tag if tag else "")
                        for lineno, ref, tag in refs)[:200])
        piped_shell = re.search(r"\|\s*(bash|sh)(\s|$|;|&)", text)
        check("ci-no-piped-installers-%s" % base,
              not piped_shell
              and "pixi.sh/install.sh" not in text,
              piped_shell.group(0).strip() if piped_shell else "")
        check("ci-pixi-bootstrap-%s" % base,
              "tools/install-pixi" in text)
        runners = re.findall(r"^\s*runs-on:\s*(.+?)\s*$",
                             text, re.M)
        check("ci-runners-known-%s" % base,
              len(runners) >= 1
              and all(run == "ubuntu-26.04" for run in runners),
              "; ".join(runners)[:120])

    with open(os.path.join(
            ROOT, "tests", "package", "Dockerfile.clean")) as handle:
        docker_from = [line.split("#", 1)[0].strip()
                       for line in handle
                       if line.split("#", 1)[0].strip().startswith(
                           "FROM ")]
    check("clean-image-pinned",
          len(docker_from) == 1 and re.fullmatch(
              r"FROM ubuntu:26\.04@sha256:[0-9a-f]{64}",
              docker_from[0]) is not None,
          "; ".join(docker_from)[:120])

    with open(os.path.join(ROOT, "pixi.toml")) as handle:
        pixi = handle.read()
    mver = re.search(r'^version\s*=\s*"([^"]+)"', pixi, re.M)
    mmojo = re.search(r'^mojo\s*=\s*"==([^"]+)"', pixi, re.M)
    check("pixi-manifest", bool(mver) and bool(mmojo))
    check("lock-mojo-agrees-pixi",
          lock["toolchain"]["mojo"]["version"] == mmojo.group(1))
    check("pixi-license-declared",
          'license = "Apache-2.0 WITH LLVM-exception"' in pixi)

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
    support_doc = os.path.join(ROOT, "docs", "support.md")
    check("support-doc-present", os.path.isfile(support_doc))
    with open(support_doc) as handle:
        support_norm = re.sub(r"\s+", " ",
                              handle.read()).lower()
    # The ratified floor sentence, normalized: the support
    # envelope must carry it verbatim so the floor cannot
    # drift from the product and spec statements.
    check("support-floor-sentence",
          "live bridge primitives (ratified 2026-10-31): "
          "linux 6.0 or later, btf required; this "
          "repository's privileged suite qualifies "
          "7.0.0-38-generic, and memveil's booted matrix "
          "qualifies the 6.0 through 6.10 attempt rows."
          in support_norm)
    policy_doc = os.path.join(ROOT, "docs", "policy.md")
    check("policy-doc-present", os.path.isfile(policy_doc))
    changelog = os.path.join(ROOT, "CHANGELOG.md")
    check("changelog-present", os.path.isfile(changelog))
    versions = set()
    for path in (policy_doc, changelog):
        with open(path) as handle:
            versions.update(re.findall(r"v\d+\.\d+\.\d+",
                                       handle.read()))
    versions = sorted(versions)
    check("policy-names-versions", len(versions) >= 1,
          "no vX.Y.Z named")
    tags = git_tags()
    if tags is None:
        print("ok policy-tags-resolve "
              "(not an owning checkout; skipped)")
    else:
        missing = [v for v in versions if v not in tags]
        check("policy-tags-resolve", not missing,
              "; ".join(missing))

    static_inputs = [
        "LICENSE",
        "LICENSES/GPL-2.0-only.txt", "LICENSES/LLVM-exception.txt",
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
