#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Resolve the shipped collector without entering it or issuing BPF calls."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

import test_package as tp


def inspect_elf(path):
    result = tp.run(["readelf", "-dW", str(path)])
    if result.returncode:
        raise tp.Fail("cannot inspect ELF: " + result.stdout)
    needed = re.findall(r"\(NEEDED\).*\[([^]]+)\]", result.stdout)
    paths = re.findall(r"\((?:RPATH|RUNPATH)\).*\[([^]]*)\]", result.stdout)
    return needed, paths


def loader_check(tarball, version):
    temporary, original = tp.extract_top(tarball, version, "pkg-loader-")
    temporary = Path(temporary)
    top = temporary / "relocated package"
    shutil.move(original, top)
    failures = []
    try:
        manifest = json.loads((top / "MANIFEST.json").read_text())
        observed = manifest["build"]["receipt"]["toolchain_observed"]
        if not re.fullmatch(r"patchelf \d+(?:\.\d+)+", observed.get("patchelf", "")):
            failures.append("normalizer tool identity missing from build receipt")
        shipped = top / "examples/tracepoint_main"
        result = tp.run(["readelf", "-lW", str(shipped)])
        match = re.search(r"Requesting program interpreter: ([^]]+)\]", result.stdout)
        if result.returncode or not match:
            raise tp.Fail("cannot determine shipped collector interpreter")
        loader = match.group(1)
        env = {"PATH": "/nonexistent", "LC_ALL": "C"}
        for row in manifest["files"]:
            path = top / row["path"]
            if path.read_bytes()[:4] != b"\x7fELF":
                continue
            needed, paths = inspect_elf(path)
            print("ELF", row["path"], json.dumps({"needed": needed, "paths": paths}))
            for search in paths:
                for entry in search.split(":"):
                    if not (entry == "$ORIGIN" or entry.startswith("$ORIGIN/")):
                        failures.append("nonrelative search path in " + row["path"])
                        continue
                    resolved = path.parent / entry.replace("$ORIGIN/", "", 1)
                    if entry == "$ORIGIN":
                        resolved = path.parent
                    if not resolved.resolve().is_relative_to(top.resolve()):
                        failures.append("escaping search path in " + row["path"])

        def resolve(label, target=shipped):
            result = tp.run([loader, "--inhibit-cache", "--list", str(target)],
                            cwd=temporary, env=env, timeout=30)
            print(label, "exit", result.returncode, "\n" + result.stdout, flush=True)
            return result

        result = resolve("relocated-clean")
        if result.returncode:
            failures.append("clean relocated resolution failed")
        # zlib belongs to the lazily opened bridge, outside collector startup.
        bundled = sorted(set(manifest["runtime"]["verified"]) - {"libz.so.1"})
        for name in bundled:
            match = re.search(r"^\s*" + re.escape(name) + r" => (\S.*) \(0x", result.stdout, re.M)
            if not match or Path(match.group(1)).resolve() != (top / "lib" / name).resolve():
                failures.append("dependency did not resolve from package: " + name)
        for name in bundled:
            path = top / "lib" / name
            saved = path.read_bytes()
            if name in {"libKGENCompilerRTShared.so", "libMSupportGlobals.so", "libAsyncRTRuntimeGlobals.so"}:
                path.unlink()
                try:
                    result = resolve("missing-" + name)
                    if result.returncode != 127 or name not in result.stdout or "cannot open shared object file" not in result.stdout:
                        failures.append("missing dependency did not refuse: " + name)
                finally:
                    path.write_bytes(saved)
            path.write_bytes(b"incompatible dependency\n")
            try:
                result = resolve("incompatible-" + name)
                match = re.search(r"error while loading shared libraries: (.*): file too short", result.stdout)
                if result.returncode != 127 or not match or Path(match.group(1)).resolve() != path.resolve():
                    failures.append("incompatible dependency did not refuse: " + name)
            finally:
                path.write_bytes(saved)
        if failures:
            raise tp.Fail("; ".join(failures))
    finally:
        shutil.rmtree(temporary)
    print("loader: shipped collector relocated, package resolution, missing/incompatible refusal; no program entry")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", help="inspect an existing package without rebuilding")
    args = parser.parse_args()
    version = tp.package_version()
    loader_check(args.archive or tp.build_package(version), version)


if __name__ == "__main__":
    try:
        main()
    except (tp.Fail, OSError, subprocess.SubprocessError) as exc:
        print("FAIL:", exc)
        sys.exit(1)
    print("PASS")
