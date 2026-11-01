#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Check development collector startup without entering collector code."""

import os
from pathlib import Path
import re
import sys

import test_package as tp


def main():
    root = Path(tp.ROOT)
    binary = root / os.environ.get("LMB_BUILD_DIR", "build") / "examples/tracepoint_main"
    result = tp.run(["readelf", "-lW", str(binary)])
    match = re.search(r"Requesting program interpreter: ([^]]+)\]", result.stdout)
    if result.returncode or not match:
        raise tp.Fail("cannot inspect development collector interpreter")
    result = tp.run([match.group(1), "--inhibit-cache", "--list", str(binary)],
                    cwd=root, env={"PATH": "/nonexistent", "LC_ALL": "C"}, timeout=30)
    print(result.stdout, end="")
    if result.returncode:
        raise tp.Fail("development collector startup resolution failed: exit %d" % result.returncode)
    for name in ("libKGENCompilerRTShared.so", "libMSupportGlobals.so",
                 "libAsyncRTRuntimeGlobals.so", "libgcc_s.so.1", "libstdc++.so.6"):
        match = re.search(r"^\s*" + re.escape(name) + r" => (\S.*) \(0x", result.stdout, re.M)
        expected = root / ".pixi/envs/default/lib" / name
        if not match or Path(match.group(1)).resolve() != expected.resolve():
            raise tp.Fail("development dependency did not resolve from its SDK: " + name)
    print("PASS development loader: SDK startup resolution without overrides or program entry")


if __name__ == "__main__":
    try:
        main()
    except (tp.Fail, OSError) as exc:
        print("FAIL:", exc)
        sys.exit(1)
