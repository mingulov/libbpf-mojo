#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Prepare the collector's development-only runtime library directory."""

import os
from pathlib import Path
import sys


def prepare(build, runtime):
    build = Path(build).resolve(strict=True)
    runtime = Path(runtime).resolve(strict=True)
    if not build.is_dir() or not runtime.is_dir():
        raise ValueError("build and SDK runtime must be directories")
    link = build / "lib"
    target = os.path.relpath(runtime, build)
    try:
        link.symlink_to(target, target_is_directory=True)
    except FileExistsError:
        if not link.is_symlink() or link.resolve() != runtime:
            raise ValueError("refusing existing development runtime entry: " + str(link))
    print("build runtime: lib -> " + target)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: build_runtime.py <build-dir> <SDK-runtime-dir>")
    try:
        prepare(sys.argv[1], sys.argv[2])
    except (OSError, ValueError) as exc:
        sys.exit("build runtime: " + str(exc))
