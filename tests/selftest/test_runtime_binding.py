#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unprivileged probes for tools/package_runtime.py.

Builds a fake conda environment plus a fake package cache and
checks the byte binding: attributed bytes pass, tampered bytes
fail, relocated files bind to the environment source, missing
caches fail closed, links resolve inside the payload, and
license discovery prefers the environment over the cache. The
real cache is never touched (LMB_CONDA_PKGS override). Standard
library only; exit 0 on pass, 1 on failure.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "..", "..", "tools"))
import package_runtime  # noqa: E402


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def digest(data):
    return hashlib.sha256(data).hexdigest()


BYTES_A = b"fake-soname-a-contents"
BYTES_B = b"fake-soname-b-contents"
BYTES_C = b"fake-relocated-contents"


def layout(tmp):
    """Create the fake env, stage, and cache; return the paths."""
    env = os.path.join(tmp, "env")
    pkgs = os.path.join(tmp, "pkgs")
    stage = os.path.join(tmp, "stage")
    meta_a = {"name": "pkg-a", "version": "1.0", "build": "b0",
              "license": "MIT", "url": "https://example.invalid/a",
              "sha256": "0" * 64, "files": ["lib/liba.so"]}
    meta_b = {"name": "pkg-b", "version": "2.0", "build": "b1",
              "license": "LicenseRef-X",
              "url": "https://example.invalid/b",
              "sha256": "1" * 64,
              "files": ["lib/libb.so", "lib/libc.so"]}
    write(os.path.join(env, "conda-meta", "pkg-a.json"),
          json.dumps(meta_a).encode())
    write(os.path.join(env, "conda-meta", "pkg-b.json"),
          json.dumps(meta_b).encode())
    write(os.path.join(env, "lib", "liba.so"), BYTES_A)
    write(os.path.join(env, "lib", "libb.so"), BYTES_B)
    write(os.path.join(env, "lib", "libc.so"), BYTES_C)
    paths_a = {"paths_version": 1, "paths": [
        {"_path": "lib/liba.so", "path_type": "hardlink",
         "sha256": digest(BYTES_A)}]}
    write(os.path.join(pkgs, "pkg-a-1.0-b0", "info", "paths.json"),
          json.dumps(paths_a).encode())
    paths_b = {"paths_version": 1, "paths": [
        {"_path": "lib/libb.so", "path_type": "hardlink",
         "sha256": digest(BYTES_B)},
        {"_path": "lib/libc.so", "path_type": "hardlink",
         # Relocated: the recorded hash is the pre-relocation
         # one, so staged bytes can only bind to the env.
         "sha256": digest(b"pre-relocation-bytes"),
         "prefix_placeholder": "/placeholder/prefix"},
        {"_path": "lib/link.so", "path_type": "softlink"},
        {"_path": "lib/real.so", "path_type": "hardlink",
         "sha256": digest(BYTES_A)}]}
    pkg_b = os.path.join(pkgs, "pkg-b-2.0-b1")
    write(os.path.join(pkg_b, "info", "paths.json"),
          json.dumps(paths_b).encode())
    write(os.path.join(pkg_b, "lib", "real.so"), BYTES_A)
    os.symlink(os.path.join(pkg_b, "lib", "real.so"),
               os.path.join(pkg_b, "lib", "link.so"))
    write(os.path.join(pkg_b, "info", "licenses", "FROMCACHE"),
          b"cache-license\n")
    write(os.path.join(env, "share", "licenses", "pkg-b", "FROMENV"),
          b"env-license\n")
    write(os.path.join(stage, "lib", "liba.so"), BYTES_A)
    write(os.path.join(stage, "lib", "libb.so"), BYTES_B)
    write(os.path.join(stage, "lib", "libc.so"), BYTES_C)
    write(os.path.join(stage, "lib", "libbpf_mojo.so.1"), b"bridge")
    return env, pkgs, stage


def expect_error(label, func, *args):
    try:
        func(*args)
    except package_runtime.AttributionError:
        return None
    return "%s: want AttributionError" % label


def main():
    tmp = tempfile.mkdtemp(prefix="runtime-binding-")
    old_override = os.environ.get(package_runtime.CACHE_ENV_OVERRIDE)
    os.environ[package_runtime.CACHE_ENV_OVERRIDE] = os.path.join(
        tmp, "pkgs")
    try:
        env, pkgs, stage = layout(tmp)
        pixi_lib = os.path.join(env, "lib")
        prefix = env

        # 1. Positive: all three bound; the relocated one flags.
        verified = package_runtime.verify_staged_runtime(
            pixi_lib, stage)
        if sorted(verified) != ["liba.so", "libb.so", "libc.so"]:
            return "positive: bound %r" % sorted(verified)
        if verified["liba.so"]["sha256"] != digest(BYTES_A):
            return "positive: wrong recorded hash"
        if verified["libc.so"]["relocated"] is not True:
            return "positive: relocated flag missing"
        if verified["liba.so"]["relocated"] is not False:
            return "positive: plain file flagged relocated"

        # 2. Tampered staged bytes fail, plain and relocated.
        write(os.path.join(stage, "lib", "liba.so"), b"tampered")
        error = expect_error(
            "tampered plain lib",
            package_runtime.verify_staged_runtime, pixi_lib, stage)
        if error:
            return error
        write(os.path.join(stage, "lib", "liba.so"), BYTES_A)
        write(os.path.join(stage, "lib", "libc.so"), b"tampered")
        error = expect_error(
            "tampered relocated lib",
            package_runtime.verify_staged_runtime, pixi_lib, stage)
        if error:
            return error
        write(os.path.join(stage, "lib", "libc.so"), BYTES_C)

        # 3. Missing cache fails closed and names the override.
        shutil.rmtree(os.path.join(pkgs, "pkg-a-1.0-b0"))
        try:
            package_runtime.verify_staged_runtime(pixi_lib, stage)
        except package_runtime.AttributionError as exc:
            if package_runtime.CACHE_ENV_OVERRIDE not in str(exc):
                return "missing cache: override not named: %s" % exc
        else:
            return "missing cache: want AttributionError"

        # 4. Unattributed sonames fail.
        write(os.path.join(stage, "lib", "libmystery.so"), b"?")
        error = expect_error(
            "unattributed lib",
            package_runtime.verify_staged_runtime, pixi_lib, stage)
        if error:
            return error
        os.unlink(os.path.join(stage, "lib", "libmystery.so"))
        by_file = package_runtime.load_file_index(prefix)
        if package_runtime.trace_owner(
                by_file, prefix, pixi_lib, "libmystery.so") is not None:
            return "trace_owner finds a phantom package"

        # 5. Links without a recorded hash resolve in-payload.
        pkg_b = os.path.join(pkgs, "pkg-b-2.0-b1")
        got = package_runtime.recorded_hash(pkg_b, "lib/link.so")
        if got != (digest(BYTES_A), False):
            return "link resolution: got %r" % (got,)
        if package_runtime.recorded_hash(
                pkg_b, "lib/absent.so") is not None:
            return "phantom path resolves"

        # 6. License discovery prefers env, falls back to cache.
        found = package_runtime.package_license_files(
            prefix, pkg_b, "pkg-b", "2.0", "b1")
        if sorted(found) != ["FROMENV"]:
            return "license env preference: %r" % sorted(found)
        shutil.rmtree(os.path.join(env, "share"))
        found = package_runtime.package_license_files(
            prefix, pkg_b, "pkg-b", "2.0", "b1")
        if sorted(found) != ["FROMCACHE"]:
            return "license cache fallback: %r" % sorted(found)
        shutil.rmtree(os.path.join(pkg_b, "info", "licenses"))
        error = expect_error(
            "no licenses anywhere",
            package_runtime.package_license_files,
            prefix, pkg_b, "pkg-b", "2.0", "b1")
        if error:
            return error

        # 7. Malformed metadata fails closed.
        write(os.path.join(env, "conda-meta", "broken.json"), b"{")
        error = expect_error(
            "malformed conda-meta",
            package_runtime.load_file_index, prefix)
        if error:
            return error
    finally:
        if old_override is None:
            os.environ.pop(package_runtime.CACHE_ENV_OVERRIDE, None)
        else:
            os.environ[package_runtime.CACHE_ENV_OVERRIDE] = old_override
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_runtime_binding: positive, tamper, cache, "
          "attribution, links, licenses, malformed")
    return None


if __name__ == "__main__":
    error = main()
    if error is not None:
        print("FAIL test_runtime_binding: %s" % error, file=sys.stderr)
        sys.exit(1)
