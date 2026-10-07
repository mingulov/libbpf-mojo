#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Docker-free consumer gate: the exact tarball serves a consumer.

Rebuilds the tarball with tools/package, verifies the manifest
hashes against the extracted files (including tamper negatives),
then compiles and runs the packaged example consumer against
the packaged tree only. Determinism and the privileged
clean-room check stay in the package lane.
Exit 0 on pass, 77 on explicit skip, 1 on failure.
Standard library only.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_package as tp


def main():
    version = tp.package_version()
    tarball = tp.build_package(version)
    tp.verify_manifest(tarball, version)
    tp.consumer_check(tarball, version)


if __name__ == "__main__":
    try:
        main()
    except tp.Skip as exc:
        print("SKIP: %s" % exc)
        sys.exit(tp.SKIP)
    except tp.Fail as exc:
        print("FAIL: %s" % exc)
        sys.exit(1)
    print("PASS")
