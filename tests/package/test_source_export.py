#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Build complete HEAD source exports and consume their runtime bundles.

No borrowed build outputs or receipts. Test standalone and ignored exports
under an unrelated clean/dirty Git parent. LMB_SOURCE_EXPORT_OUT optionally
preserves source/runtime archives, receipts and full command logs.
--host-only uses the four installed consumers with guarded native leaves.
--cached-libbpf-archive PATH seeds verified source bytes before each build;
an invalid supplied cache fails before any build and never falls back.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import tarfile
import tempfile

import test_package as tp
import test_consumer_lane as consumers

ROOT = Path(tp.ROOT)
OUT = Path(os.environ["LMB_SOURCE_EXPORT_OUT"]).resolve() \
    if os.environ.get("LMB_SOURCE_EXPORT_OUT") else None


def run(root, *args, env=None, label=None):
    proc = subprocess.run(args, cwd=root, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, timeout=1500)
    print("+ %s [exit %s]" % (" ".join(map(str, args)), proc.returncode), flush=True)
    if OUT and label:
        (OUT / (label + ".log")).write_text(proc.stdout)
    if proc.returncode:
        raise tp.Fail(proc.stdout[-4000:])
    return proc.stdout.strip()


def cached_archive(root, archive):
    """Match both independent declarations before using cached source bytes."""
    try:
        pin = json.loads((root / "toolchain.lock.json").read_text())["toolchain"]["libbpf_source"]
        cmake = (root / "native/CMakeLists.txt").read_text()
        url = re.search(r'set\(LIBBPF_URL\s+"([^"]+)"\)', cmake)
        sha = re.search(r'set\(LIBBPF_SHA256\s+"([0-9a-f]{64})"\)', cmake)
        if not url or not sha or url[1] != pin["tarball_url"] or sha[1] != pin["tarball_sha256"]:
            raise tp.Fail("cached libbpf archive: native pin differs from toolchain lock")
        data = archive.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha[1]:
            raise tp.Fail("cached libbpf archive: hash mismatch")
        return data, Path(url[1]).name, sha[1]
    except (OSError, KeyError, ValueError) as exc:
        raise tp.Fail("cached libbpf archive: " + str(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-only", action="store_true")
    parser.add_argument("--cached-libbpf-archive", type=Path)
    options = parser.parse_args(argv)
    if options.cached_libbpf_archive:
        options.cached_libbpf_archive = options.cached_libbpf_archive.resolve()
        cached_archive(ROOT, options.cached_libbpf_archive)
    if OUT:
        OUT.mkdir(parents=True, exist_ok=True)
    source = subprocess.check_output(["git", "archive", "HEAD"], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(source)) as tar:
        inputs = {m.name for m in tar.getmembers() if m.isfile()}
    source_gz = gzip.compress(source, mtime=0)
    if OUT:
        (OUT / "libbpf-mojo-source.tar.gz").write_bytes(source_gz)
    for case in ("standalone", "unrelated-parent"):
        with tempfile.TemporaryDirectory(prefix="lmb-source-") as temp:
            parent = Path(temp)
            if case == "unrelated-parent":
                run(parent, "git", "init", "-q")
                (parent / ".gitignore").write_text("export/\n")
                run(parent, "git", "add", ".gitignore")
                run(parent, "git", "-c", "user.name=Test", "-c",
                    "user.email=test@example.invalid", "commit", "-qm", "unrelated")
            tree = parent / "export"
            tree.mkdir()
            with tarfile.open(fileobj=io.BytesIO(source)) as tar:
                tar.extractall(tree, filter="data")
            if options.cached_libbpf_archive:
                data, name, digest = cached_archive(tree, options.cached_libbpf_archive)
                # This is ExternalProject's normal download file, not a
                # compiled archive or a borrowed dependency installation.
                download = tree / "build/libbpf_external-prefix/src" / name
                download.parent.mkdir(parents=True, exist_ok=True)
                download.write_bytes(data)
                print("cached libbpf source: %s sha256 %s" % (options.cached_libbpf_archive, digest), flush=True)
            env = dict(os.environ)
            env.pop("SOURCE_DATE_EPOCH", None)
            run(tree, "./tools/build", env=env, label=case + "-build")
            receipt = json.loads((tree / "build/build-receipt.json").read_text())
            if receipt["git"] != "unknown" or receipt["sources"]["mode"] != "archive":
                raise tp.Fail("source export borrowed Git identity/inventory")
            if inputs != set(receipt["sources"]["files"]):
                raise tp.Fail("source seal differs from complete export inventory")
            if OUT:
                shutil.copyfile(tree / "build/build-receipt.json",
                                OUT / (case + "-build-receipt.json"))
            run(tree, "./tools/package", env=env, label=case + "-package")
            ball = tree / "dist/libbpf-mojo-0.1.0.tar.gz"
            first = ball.read_bytes()
            tp.verify_manifest(str(ball), "0.1.0")
            previous_root = tp.ROOT
            tp.ROOT = str(tree)
            try:
                if options.host_only:
                    consumers.object_consumer_check(str(ball), "0.1.0", host_only=True)
                else:
                    tp.consumer_check(str(ball), "0.1.0")
            finally:
                tp.ROOT = previous_root
            if case == "unrelated-parent":
                (parent / "unrelated-dirty.txt").write_text("dirty parent\n")
            run(tree, "./tools/package", env=env, label=case + "-repeat")
            if first != ball.read_bytes():
                raise tp.Fail("same sealed build produced different archive bytes")
            for bad in ("", "-1", "1.5", " 1", "4294967296"):
                invalid = dict(env, SOURCE_DATE_EPOCH=bad)
                proc = subprocess.run(["./tools/package"], cwd=tree, env=invalid,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      text=True, timeout=60)
                if proc.returncode == 0 or "archive timestamp" not in proc.stdout:
                    raise tp.Fail("invalid SOURCE_DATE_EPOCH accepted/wrong refusal")
                if ball.read_bytes() != first:
                    raise tp.Fail("timestamp refusal changed sealed archive")
            if OUT:
                shutil.copyfile(ball, OUT / (case + "-runtime.tar.gz"))
            print("PASS %s: real source build, sealed inventory, consumer, "
                  "deterministic runtime, invalid timestamps" % case, flush=True)
    if options.host_only:
        print("NOT_RUN source-export: successful kernel maps and XDP test-run")


if __name__ == "__main__":
    try:
        main()
    except tp.Fail as exc:
        raise SystemExit("FAIL source-export: %s" % exc)
