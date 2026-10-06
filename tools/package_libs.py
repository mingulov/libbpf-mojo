#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Resolve runtime libraries for packaging. Invoked by tools/package.

Usage: package_libs.py <pixi-lib-dir> <elf> [<elf> ...]

Traverses DT_NEEDED recursively from EVERY packaged ELF and prints
one line per dependency: "B <soname> <source-path>" for libraries
bundled from the pixi environment, "S <soname>" for libraries left
to the target system. Resolution is static (readelf), so it works
wherever the checkout exists.

Fails closed: an unresolvable dependency, or any sanitizer runtime
need (sanitizer trees are test-only, never releasable), aborts
packaging. Well-known system libraries are never bundled even if a
same-named file exists. Standard library only.
"""

import os
import re
import subprocess
import sys

SYSTEM = frozenset((
    "libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0",
    "libresolv.so.2", "librt.so.1", "libutil.so.1", "libxnet.so.1",
    "ld-linux-x86-64.so.2",
))

SANITIZER = re.compile(r"asan|ubsan|tsan", re.IGNORECASE)


def needed(path):
    out = subprocess.run(["readelf", "-d", path],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    if out.returncode != 0:
        sys.exit("package_libs: readelf failed on %s" % path)
    names = []
    for line in out.stdout.splitlines():
        if "(NEEDED)" not in line:
            continue
        name = line.rsplit("[", 1)[-1].rstrip("]")
        if name and name not in names:
            names.append(name)
    return names


def ldconfig_names():
    try:
        out = subprocess.run(["ldconfig", "-p"],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
    except OSError:
        sys.exit("package_libs: ldconfig is required and missing")
    if out.returncode != 0:
        sys.exit("package_libs: ldconfig -p failed")
    found = set()
    for line in out.stdout.splitlines():
        match = re.match(r"\s*(\S+)\s+\(", line)
        if match:
            found.add(match.group(1))
    return found


def main(argv):
    if len(argv) < 3:
        sys.exit("usage: package_libs.py <pixi-lib-dir> <elf> [...]")
    pixi_lib, elfs = argv[1], argv[2:]
    for elf in elfs:
        if not os.path.isfile(elf):
            sys.exit("package_libs: missing ELF: %s" % elf)
    system_known = ldconfig_names()
    bundled = {}
    system = set()
    seen = set()
    queue = list(elfs)
    while queue:
        current = queue.pop(0)
        for name in needed(current):
            if SANITIZER.search(name):
                sys.exit(
                    "package_libs: %s needs sanitizer runtime %s; "
                    "sanitizer trees are test-only and not releasable"
                    % (current, name))
            if name in SYSTEM:
                system.add(name)
                continue
            if name in seen:
                continue
            seen.add(name)
            candidate = os.path.join(pixi_lib, name)
            if os.path.isfile(candidate):
                real = os.path.realpath(candidate)
                bundled[name] = real
                queue.append(real)
            elif name in system_known:
                system.add(name)
            else:
                sys.exit(
                    "package_libs: unresolved %s (needed by %s); "
                    "neither pixi nor system provides it"
                    % (name, current))
    for name in sorted(bundled):
        print("B %s %s" % (name, bundled[name]))
    for name in sorted(system):
        print("S %s" % name)


if __name__ == "__main__":
    main(sys.argv)
