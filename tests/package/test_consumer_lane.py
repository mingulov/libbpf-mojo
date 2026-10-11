#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
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
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_package as tp


def object_consumer_check(tarball, version):
    """Only packaged imports and runtime inputs survive relocation."""
    if shutil.which("pixi") is None:
        raise tp.Skip("no pixi for the object consumer")
    tmp, top = tp.extract_top(tarball, version, "pkg-object-")
    try:
        isolated = os.path.join(tmp, "external")
        os.mkdir(isolated)
        source = os.path.join(isolated, "consumer.mojo")
        shutil.copyfile(os.path.join(HERE, "consumer_object.mojo"), source)
        binary = os.path.join(isolated, "consumer")
        compiler = ["pixi", "run", "--frozen", "mojo", "build", "--target-cpu", "x86-64-v2"]
        result = tp.run(compiler + ["-I", os.path.join(top, "mojo"), "-o", binary, source],
                        cwd=tp.ROOT, timeout=600)
        if result.returncode:
            raise tp.Fail("object package consumer build failed:\n" + result.stdout)
        empty = os.path.join(tmp, "empty")
        os.mkdir(empty)
        result = tp.run(compiler + ["-I", empty, "-o", binary + ".control", source],
                        cwd=tp.ROOT, timeout=600)
        if not result.returncode or "unable to locate module 'libbpf_mojo'" not in result.stdout:
            raise tp.Fail("object consumer missing-import control failed:\n" + result.stdout)
        with open(os.path.join(isolated, "abi.c"), "w", encoding="utf-8") as out:
            out.write('#include "libbpf_mojo_generic.h"\n'
                      'int main(void) { struct lmb_object *o = 0; return lmb_object_close_v1(&o); }\n')
        result = tp.run(["clang", "-I", os.path.join(top, "include"),
                         os.path.join(isolated, "abi.c"), "-L", os.path.join(top, "lib"),
                         "-l:libbpf_mojo.so.1", "-o", os.path.join(isolated, "abi")], timeout=120)
        if result.returncode:
            raise tp.Fail("packaged generic C header failed:\n" + result.stdout)
        relocated = os.path.join(tmp, "relocated package")
        shutil.move(top, relocated)
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = os.path.join(relocated, "lib")
        env["LMB_NATIVE_LIB"] = os.path.join(relocated, "lib", "libbpf_mojo.so.1")
        fixture = os.path.join(relocated, "examples", "probe.bpf.o")
        result = tp.run([binary, fixture], cwd=isolated, env=env, timeout=120)
        if result.returncode or "OBJECT-CONSUMER-OK" not in result.stdout:
            raise tp.Fail("relocated object consumer failed:\n" + result.stdout)
        result = tp.run([os.path.join(isolated, "abi")], cwd=isolated, env=env, timeout=120)
        if result.returncode:
            raise tp.Fail("relocated native object consumer failed:\n" + result.stdout)
        for library, code in [(os.path.join(tmp, "missing.so"), -2), ("libc.so.6", -38)]:
            env["LMB_NATIVE_LIB"] = library
            result = tp.run([binary, fixture], cwd=isolated, env=env, timeout=120)
            if result.returncode != 3 or "OBJECT-ERROR 4 %d" % code not in result.stdout:
                raise tp.Fail("object consumer library refusal failed:\n" + result.stdout)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("object consumer: packaged-only imports, relocation, native header, missing/incompatible libraries")


def main():
    version = tp.package_version()
    tarball = tp.build_package(version)
    tp.verify_manifest(tarball, version)
    tp.consumer_check(tarball, version)
    object_consumer_check(tarball, version)


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
