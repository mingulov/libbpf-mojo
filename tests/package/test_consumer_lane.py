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

import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_package as tp


def object_consumer_check(tarball, version, host_only=False):
    """Only extracted public modules and runtime inputs serve each consumer."""
    if shutil.which("pixi") is None:
        raise tp.Skip("no pixi for the generic consumers")
    tmp, top = tp.extract_top(tarball, version, "pkg-generic-")
    try:
        with open(os.path.join(top, "MANIFEST.json"), encoding="utf-8") as src:
            manifest = json.load(src)
        sealed = manifest["build"]["receipt"]["sources"]["files"]
        for module in ("object", "maps", "program"):
            rel = "src/libbpf_mojo/%s.mojo" % module
            installed = os.path.join(top, "mojo", "libbpf_mojo", module + ".mojo")
            if not os.path.isfile(installed) or tp.sha256_of(installed) != sealed[rel]["sha256"]:
                raise tp.Fail("installed %s module differs from its build source" % module)
            print("installed %s sha256 %s" % (module, tp.sha256_of(installed)))
        isolated = os.path.join(tmp, "external")
        os.mkdir(isolated)
        empty = os.path.join(tmp, "empty")
        os.mkdir(empty)
        compiler = ["pixi", "run", "--frozen", "mojo", "build",
                    "--num-threads", "2", "--target-cpu", "x86-64-v2"]
        consumers = []
        for name in ("main", "object", "maps", "testrun"):
            source = os.path.join(isolated, "consumer_%s.mojo" % name)
            shutil.copyfile(os.path.join(HERE, "consumer_%s.mojo" % name), source)
            binary = os.path.join(isolated, "consumer_%s" % name)
            result = tp.run(compiler + ["-I", os.path.join(top, "mojo"), "-o", binary, source],
                            cwd=tp.ROOT, timeout=600)
            if result.returncode:
                raise tp.Fail("%s package consumer build failed:\n%s" % (name, result.stdout))
            result = tp.run(compiler + ["-I", empty, "-o", binary + ".control", source],
                            cwd=tp.ROOT, timeout=600)
            if not result.returncode or "unable to locate module 'libbpf_mojo'" not in result.stdout:
                raise tp.Fail("%s consumer missing-import control failed:\n%s" % (name, result.stdout))
            consumers.append((name, binary))
            print("compiled %s sha256 %s" % (name, tp.sha256_of(binary)))
            os.remove(source)
        abi_source = os.path.join(isolated, "abi.c")
        with open(abi_source, "w", encoding="utf-8") as out:
            out.write('#include "libbpf_mojo_generic.h"\n'
                      'int main(void) { struct lmb_object *o = 0; return lmb_object_close_v1(&o); }\n')
        result = tp.run(["clang", "-I", os.path.join(top, "include"), abi_source,
                         "-L", os.path.join(top, "lib"), "-l:libbpf_mojo.so.1",
                         "-o", os.path.join(isolated, "abi")], timeout=120)
        if result.returncode:
            raise tp.Fail("packaged generic C header failed:\n" + result.stdout)
        os.remove(abi_source)
        # Remove import sources after compilation. Runtime has neither an
        # import tree nor a compiler on PATH, and uses the relocated package.
        shutil.rmtree(os.path.join(top, "mojo"))
        relocated = os.path.join(tmp, "relocated package")
        shutil.move(top, relocated)
        env = dict(os.environ)
        env["PATH"] = empty
        env["LD_LIBRARY_PATH"] = os.path.join(relocated, "lib")
        env["LMB_NATIVE_LIB"] = os.path.join(relocated, "lib", "libbpf_mojo.so.1")
        if host_only or env.get("LMB_HOST_ONLY") == "1":
            guard = os.path.join(tp.ROOT, env.get("LMB_BUILD_DIR", "build"), "liblmb_host_guard.so")
            if not os.path.isfile(guard):
                raise tp.Fail("missing native host guard: " + guard)
            env["LD_PRELOAD"] = guard
        fixture = os.path.join(relocated, "examples", "probe.bpf.o")
        for name, binary in consumers:
            result = tp.run([binary, fixture], cwd=isolated, env=env, timeout=120)
            token = "CONSUMER-OK" if name == "main" else name.upper() + "-CONSUMER-OK"
            if result.returncode or token not in result.stdout:
                raise tp.Fail("relocated %s consumer failed:\n%s" % (name, result.stdout))
            print(result.stdout.strip())
        result = tp.run([os.path.join(isolated, "abi")], cwd=isolated, env=env, timeout=120)
        if result.returncode:
            raise tp.Fail("relocated native object consumer failed:\n" + result.stdout)
        for library, code in [(os.path.join(tmp, "missing.so"), -2), ("libc.so.6", -38)]:
            env["LMB_NATIVE_LIB"] = library
            for name, binary in consumers:
                if name == "main":
                    continue
                result = tp.run([binary, fixture], cwd=isolated, env=env, timeout=120)
                token = "%s-ERROR 4 %d" % (name.upper(), code)
                if result.returncode != 3 or token not in result.stdout:
                    raise tp.Fail("%s consumer library refusal failed:\n%s" % (name, result.stdout))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("generic consumers: packaged-only imports, relocation, native header, missing/incompatible libraries")
    print("NOT_RUN package: successful kernel maps and XDP test-run")


def main():
    version = tp.package_version()
    tarball = tp.build_package(version)
    tp.verify_manifest(tarball, version)
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
