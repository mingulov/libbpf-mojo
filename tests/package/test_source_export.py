#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Build complete HEAD source exports and consume their runtime bundles.

No borrowed build outputs or receipts. Test standalone and ignored exports
under an unrelated clean/dirty Git parent. LMB_SOURCE_EXPORT_OUT optionally
preserves source/runtime archives, receipts and full command logs.
"""

import gzip
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

import test_package as tp

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


def main():
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


if __name__ == "__main__":
    try:
        main()
    except tp.Fail as exc:
        raise SystemExit("FAIL source-export: %s" % exc)
