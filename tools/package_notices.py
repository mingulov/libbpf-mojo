#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Stage redistribution notices and render THIRD-PARTY-NOTICES.md.

Usage: package_notices.py <pixi-lib> <stage> <libbpf-src>
                         <libbpf-ver> <pkg-version>

Invoked by tools/package after the runtime libraries are staged.
Every staged lib/*.so* except the bridge is traced to its exact
conda package via conda-meta (file lists, not name guesses) and
bound to that package's recorded per-file hashes, the matching
canonical texts are staged under licenses/, and the notices
file records per-component origins: the exact binary (channel
URL plus sha256) and the upstream source pointer. Proprietary
runtimes additionally stage their provider license files,
mapped by an explicit table.

Fails closed: an untraceable library, altered bytes, an unknown
package, missing provider licenses, or a live exception text
that differs from the vendored copy aborts packaging. Shares
tools/package_runtime.py. Standard library only.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import package_runtime  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
NOTICES = os.path.join(HERE, "notices")

# Conda package name to upstream source pointer. Unknown packages
# fail packaging: a new bundled component needs a human-written
# source entry, never a silent omission.
UPSTREAM = {
    "libgcc": ("GCC {v} source",
               "https://ftp.gnu.org/gnu/gcc/gcc-{v}/gcc-{v}.tar.xz",
               "Build recipe: https://github.com/conda-forge/"
               "ctng-compilers-feedstock"),
    "libstdcxx": ("GCC {v} source",
                  "https://ftp.gnu.org/gnu/gcc/gcc-{v}/gcc-{v}.tar.xz",
                  "Build recipe: https://github.com/conda-forge/"
                  "ctng-compilers-feedstock"),
    "libzlib": ("zlib {v} upstream releases", "https://zlib.net/", None),
}


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def stage_file(src, stage_rel, stage):
    with open(os.path.join(stage, stage_rel), "wb") as out:
        out.write(read_bytes(src))


def main(argv):
    if len(argv) != 6:
        sys.exit("usage: package_notices.py <pixi-lib> <stage> "
                 "<libbpf-src> <libbpf-ver> <pkg-version>")
    pixi_lib, stage, libbpf_src, libbpf_ver, version = argv[1:6]

    vendored_rle = os.path.join(
        NOTICES, "GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt")
    live_dirs = [os.path.join(pixi_lib, "..", "share", "licenses", name)
                 for name in ("gcc-libs", "libstdc++")]
    live_texts = []
    for live_dir in live_dirs:
        live = os.path.join(live_dir, "RUNTIME.LIBRARY.EXCEPTION")
        if not os.path.isfile(live):
            sys.exit("package_notices: missing live text: %s" % live)
        live_texts.append(read_bytes(live))
    want = read_bytes(vendored_rle)
    if any(text != want for text in live_texts):
        sys.exit("package_notices: live exception text differs from "
                 "tools/notices copy; toolchain changed, update the "
                 "vendored text before packaging")
    if not os.path.isfile(
            os.path.join(libbpf_src, "LICENSE.BSD-2-Clause")):
        sys.exit("package_notices: missing libbpf license in build tree")

    os.makedirs(os.path.join(stage, "licenses"), exist_ok=True)
    stage_file(os.path.join(libbpf_src, "LICENSE.BSD-2-Clause"),
               "licenses/LICENSE.BSD-2-Clause.libbpf", stage)
    stage_file(os.path.join(NOTICES, "GPL-3.0.txt"),
               "licenses/GPL-3.0.txt", stage)
    stage_file(vendored_rle, "licenses/RUNTIME.LIBRARY.EXCEPTION", stage)
    stage_file(os.path.join(NOTICES, "ZLIB.txt"),
               "licenses/LICENSE.zlib", stage)

    # Trace every staged library to its exact conda package
    # (pixi_lib is <env>/lib, so one dirname reaches the env
    # root that owns conda-meta/) and bind its bytes to the
    # package's recorded hashes: a filename attribution alone
    # would still ship altered bytes.
    prefix = os.path.dirname(os.path.abspath(pixi_lib.rstrip("/")))
    try:
        by_file = package_runtime.load_file_index(prefix)
        staged_libs = package_runtime.staged_runtime_libs(stage)
        if not staged_libs:
            raise package_runtime.AttributionError(
                "no staged runtime libraries")
        verified = package_runtime.verify_staged_runtime(
            pixi_lib, stage)
    except package_runtime.AttributionError as exc:
        sys.exit("package_notices: %s" % exc)
    origins = {}
    for soname in staged_libs:
        meta = package_runtime.trace_owner(
            by_file, prefix, pixi_lib, soname)
        if meta is None:  # Unreachable: verified above.
            sys.exit("package_notices: %s lost its attribution"
                     % soname)
        origins.setdefault(meta["name"], {"meta": meta, "libs": []})
        origins[meta["name"]]["libs"].append(soname)

    # Proprietary runtimes stage their provider license files
    # plus a pointer stating the redistribution terms plainly.
    proprietary = sorted(
        name for name, origin in origins.items()
        if origin["meta"].get("license", "").startswith("LicenseRef"))
    for name in proprietary:
        mapping = package_runtime.PROPRIETARY_LICENSES.get(name)
        if mapping is None:
            sys.exit("package_notices: no license mapping for "
                     "proprietary package %s; update the table" % name)
        meta = origins[name]["meta"]
        pkgdir = package_runtime.package_dir(
            meta["name"], meta["version"], meta["build"])
        if pkgdir is None:
            sys.exit("package_notices: package %s %s (%s) has no "
                     "extracted cache dir" % (
                         meta["name"], meta["version"], meta["build"]))
        try:
            found = package_runtime.package_license_files(
                prefix, pkgdir, meta["name"], meta["version"],
                meta["build"])
        except package_runtime.AttributionError as exc:
            sys.exit("package_notices: %s" % exc)
        if set(found) != set(mapping):
            sys.exit("package_notices: package %s %s (%s) license "
                     "set changed (have %s, mapped %s); update the "
                     "table" % (meta["name"], meta["version"],
                                meta["build"], sorted(found),
                                sorted(mapping)))
        for base, staged_rel in sorted(mapping.items()):
            stage_file(found[base], staged_rel, stage)
    if proprietary:
        lines = ["# Mojo runtime provenance (libbpf-mojo %s)\n" % version,
                 "The bundled Mojo runtime libraries ship under",
                 "LicenseRef-Modular-Proprietary. The provider",
                 "license and third-party notices are staged",
                 "alongside this file; redistribution terms come",
                 "from the Modular MAX SDK license. Confirm",
                 "redistribution before republishing.\n"]
        for name in proprietary:
            meta = origins[name]["meta"]
            lines.append("- `%s` from conda package %s %s (%s):" % (
                "`, `".join(sorted(origins[name]["libs"])),
                meta["name"], meta["version"], meta["build"]))
            lines.append("  %s" % meta.get("url", meta.get("channel")))
            for staged_rel in sorted(
                    package_runtime.PROPRIETARY_LICENSES[name].values()):
                lines.append("  staged license: `%s`" % staged_rel)
        lines.append("")
        with open(os.path.join(
                stage, "licenses", "NOTICE.mojo-runtime.md"),
                "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))

    entries = []
    entries.append(
        "- libbpf %s, statically linked into\n"
        "  `lib/libbpf_mojo.so.1`. BSD 2-Clause; full text in\n"
        "  `licenses/LICENSE.BSD-2-Clause.libbpf`. Upstream:\n"
        "  https://github.com/libbpf/libbpf (tag v%s; the exact\n"
        "  source is the libbpf subtree of the build tree named in\n"
        "  `MANIFEST.json`)." % (libbpf_ver, libbpf_ver))
    for name in sorted(origins):
        meta = origins[name]["meta"]
        libs = ", ".join("`lib/%s`" % lib
                         for lib in sorted(origins[name]["libs"]))
        if name in proprietary:
            staged = ", ".join(
                "`%s`" % staged_rel for staged_rel in sorted(
                    package_runtime.PROPRIETARY_LICENSES[
                        name].values()))
            entries.append(
                "- %s from conda package %s %s (%s).\n"
                "  %s; provider license texts in %s;\n"
                "  provenance and the redistribution warning in\n"
                "  `licenses/NOTICE.mojo-runtime.md`.\n"
                "  Binary: %s\n"
                "  sha256: %s" % (
                    libs, meta["name"], meta["version"],
                    meta["build"], meta.get("license"), staged,
                    meta.get("url", meta.get("channel")),
                    meta.get("sha256")))
            continue
        if name not in UPSTREAM:
            sys.exit("package_notices: no upstream source pointer for "
                     "conda package %s; update the table" % name)
        label, url, recipe = UPSTREAM[name]
        block = ("- %s from conda package %s %s (%s).\n"
                 "  %s; full texts in `licenses/` (see below).\n"
                 "  Binary: %s\n"
                 "  sha256: %s\n"
                 "  Source: %s\n"
                 "  %s" % (
                     libs, meta["name"], meta["version"],
                     meta["build"], meta.get("license"),
                     meta.get("url", meta.get("channel")),
                     meta.get("sha256"),
                     label.format(v=meta["version"]),
                     url.format(v=meta["version"])))
        if recipe:
            block += "\n  %s" % recipe
        entries.append(block)
    footer = (
        "License texts: `licenses/LICENSE.BSD-2-Clause.libbpf`\n"
        "(libbpf), `licenses/GPL-3.0.txt` plus\n"
        "`licenses/RUNTIME.LIBRARY.EXCEPTION` (GCC runtimes),\n"
        "`licenses/LICENSE.zlib` (zlib)")
    if proprietary:
        staged = ", ".join(
            "`%s`" % staged_rel
            for name in proprietary
            for staged_rel in sorted(
                package_runtime.PROPRIETARY_LICENSES[name].values()))
        footer += ",\n%s (Mojo runtimes)" % staged
    entries.append(footer + ".")

    with open(os.path.join(stage, "THIRD-PARTY-NOTICES.md"), "w",
              encoding="utf-8") as handle:
        handle.write("# Third-party notices (libbpf-mojo %s)\n\n" % version)
        handle.write("This package redistributes the following "
                     "third-party components.\n\n")
        handle.write("\n\n".join(entries))
        handle.write("\n")


if __name__ == "__main__":
    main(sys.argv)
