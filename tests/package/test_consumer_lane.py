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
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_package as tp


class Retention:
    """Keep every attempted command and consumer binary before cleanup."""
    def __init__(self, output, tarball):
        self.root = None
        self.count = 0
        if output:
            path = Path(output).resolve()
            path.mkdir(parents=True, exist_ok=True)
            self.root = Path(tempfile.mkdtemp(prefix="attempt-", dir=path))
            (self.root / "inputs").mkdir()
            (self.root / "identity.json").write_text(json.dumps({
                "tarball": str(Path(tarball).resolve()), "tarball_sha256": tp.sha256_of(tarball)
            }, indent=2) + "\n")

    def source(self, path):
        if self.root:
            shutil.copyfile(path, self.root / "inputs" / Path(path).name)

    def run(self, argv, **kwargs):
        self.count += 1
        folder = self.root / ("command-%03d" % self.count) if self.root else None
        if folder:
            folder.mkdir()
            env = kwargs.get("env", os.environ)
            selected = {k: v for k, v in env.items() if k in
                        {"PATH", "LD_LIBRARY_PATH", "LD_PRELOAD"} or k.startswith(("PIXI_", "LMB_"))}
            executable = shutil.which(argv[0], path=env.get("PATH"))
            record = {"argv": list(argv), "cwd": kwargs.get("cwd", os.getcwd()),
                      "environment": selected, "timeout": kwargs.get("timeout"),
                      "executable": executable,
                      "executable_sha256": tp.sha256_of(executable) if executable else None}
            (folder / "command.json").write_text(json.dumps(record, indent=2) + "\n")
        try:
            result = tp.run(argv, **kwargs)
        except Exception as exc:
            if folder:
                (folder / "exception.txt").write_text(str(exc))
                if isinstance(exc, subprocess.TimeoutExpired) and exc.output:
                    output = exc.output.decode(errors="replace") if isinstance(exc.output, bytes) else exc.output
                    (folder / "output.log").write_text(output)
            raise
        if folder:
            (folder / "output.log").write_text(result.stdout)
            record["exit_code"] = result.returncode
            (folder / "command.json").write_text(json.dumps(record, indent=2) + "\n")
        return result

    def finish(self, temporary, status):
        if not self.root:
            return
        external = Path(temporary) / "external"
        if external.exists():
            shutil.copytree(external, self.root / "compiled")
        hashes = {str(path.relative_to(self.root)): tp.sha256_of(path)
                  for path in sorted(self.root.rglob("*")) if path.is_file()}
        (self.root / "retained.json").write_text(json.dumps({
            "status": status, "commands": self.count, "files": hashes,
        }, indent=2) + "\n")
        print("consumer attempt retained:", self.root)


def verify_public_modules(top, manifest):
    sealed = manifest["build"]["receipt"]["sources"]["files"]
    for module in ("object", "maps", "program", "link", "buffer"):
        rel = "src/libbpf_mojo/%s.mojo" % module
        installed = os.path.join(top, "mojo", "libbpf_mojo", module + ".mojo")
        if not os.path.isfile(installed) or tp.sha256_of(installed) != sealed[rel]["sha256"]:
            raise tp.Fail("installed %s module differs from its build source" % module)
        print("installed %s sha256 %s" % (module, tp.sha256_of(installed)))


def object_consumer_check(tarball, version, host_only=False, retention_out=None,
                          events_test_lib=None, events_fixture=None):
    """Only extracted public modules and runtime inputs serve each consumer."""
    if shutil.which("pixi") is None:
        raise tp.Skip("no pixi for the generic consumers")
    tmp, top = tp.extract_top(tarball, version, "pkg-generic-")
    retained = Retention(retention_out or os.environ.get("LMB_PACKAGE_CONSUMER_OUT"), tarball)
    status = "FAIL"
    try:
        with open(os.path.join(top, "MANIFEST.json"), encoding="utf-8") as src:
            manifest = json.load(src)
        retained.source(os.path.join(top, "MANIFEST.json"))
        verify_public_modules(top, manifest)
        for module in ("link", "buffer"):
            installed = Path(top) / "mojo/libbpf_mojo" / (module + ".mojo")
            original = installed.read_bytes()
            installed.write_bytes(original + b"\n# deliberate module tamper\n")
            try:
                verify_public_modules(top, manifest)
            except tp.Fail:
                pass
            else:
                raise tp.Fail("%s module tamper was accepted" % module)
            finally:
                installed.write_bytes(original)
        isolated = os.path.join(tmp, "external")
        os.mkdir(isolated)
        empty = os.path.join(tmp, "empty")
        os.mkdir(empty)
        compiler = ["pixi", "run", "--frozen", "mojo", "build",
                    "--num-threads", "2", "--target-cpu", "x86-64-v2"]
        consumers = []
        for name in ("main", "object", "maps", "testrun", "link", "buffer"):
            source = os.path.join(isolated, "consumer_%s.mojo" % name)
            shutil.copyfile(os.path.join(HERE, "consumer_%s.mojo" % name), source)
            retained.source(source)
            binary = os.path.join(isolated, "consumer_%s" % name)
            result = retained.run(compiler + ["-I", os.path.join(top, "mojo"), "-o", binary, source],
                            cwd=tp.ROOT, timeout=600)
            if result.returncode:
                raise tp.Fail("%s package consumer build failed:\n%s" % (name, result.stdout))
            result = retained.run(compiler + ["-I", empty, "-o", binary + ".control", source],
                            cwd=tp.ROOT, timeout=600)
            if not result.returncode or "unable to locate module 'libbpf_mojo'" not in result.stdout:
                raise tp.Fail("%s consumer missing-import control failed:\n%s" % (name, result.stdout))
            if name in ("link", "buffer"):
                incomplete = os.path.join(tmp, "missing-" + name)
                shutil.copytree(os.path.join(top, "mojo"), incomplete)
                os.remove(os.path.join(incomplete, "libbpf_mojo", name + ".mojo"))
                result = retained.run(compiler + ["-I", incomplete, "-o", binary + ".slice-control", source],
                                      cwd=tp.ROOT, timeout=600)
                if not result.returncode or "unable to locate module '%s'" % name not in result.stdout:
                    raise tp.Fail("%s consumer missing-module control failed:\n%s" % (name, result.stdout))
            consumers.append((name, binary))
            print("compiled %s sha256 %s" % (name, tp.sha256_of(binary)))
            os.remove(source)
        abi_source = os.path.join(isolated, "abi.c")
        with open(abi_source, "w", encoding="utf-8") as out:
            out.write('#include "libbpf_mojo_generic.h"\n'
                      'int main(void) { struct lmb_object *o = 0; struct lmb_link *l = 0; struct lmb_buffer *b = 0;\n'
                      'struct lmb_attach_options_v1 a = {.abi_version=1,.struct_size=sizeof(a)};\n'
                      'struct lmb_buffer_options_v1 r = {.abi_version=1,.struct_size=sizeof(r),.max_raw_bytes=4096,.stage_slots=1};\n'
                      'if (a.struct_size != 72 || r.struct_size != 40) return 1;\n'
                      'return lmb_link_close_v1(&l) || lmb_buffer_close_v1(&b) || lmb_object_close_v1(&o); }\n')
        retained.source(abi_source)
        result = retained.run(["clang", "-I", os.path.join(top, "include"), abi_source,
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
            result = retained.run([binary, fixture], cwd=isolated, env=env, timeout=120)
            token = "CONSUMER-OK" if name == "main" else name.upper() + "-CONSUMER-OK"
            if result.returncode or token not in result.stdout:
                raise tp.Fail("relocated %s consumer failed:\n%s" % (name, result.stdout))
            print(result.stdout.strip())
        result = retained.run([os.path.join(isolated, "abi")], cwd=isolated, env=env, timeout=120)
        if result.returncode:
            raise tp.Fail("relocated native object consumer failed:\n" + result.stdout)
        for library, code in [(os.path.join(tmp, "missing.so"), -2), ("libc.so.6", -38)]:
            env["LMB_NATIVE_LIB"] = library
            for name, binary in consumers:
                if name == "main":
                    continue
                result = retained.run([binary, fixture], cwd=isolated, env=env, timeout=120)
                token = "%s-ERROR 4 %d" % (name.upper(), code)
                if result.returncode != 3 or token not in result.stdout:
                    raise tp.Fail("%s consumer library refusal failed:\n%s" % (name, result.stdout))
        for name, binary in consumers:
            if name not in ("link", "buffer"):
                continue
            env["LMB_NATIVE_LIB"] = os.path.join(tmp, "no-native-library.so")
            result = retained.run([binary, "--import-only"], cwd=isolated, env=env, timeout=120)
            if result.returncode or name.upper() + "-IMPORT-OK" not in result.stdout:
                raise tp.Fail(name + " import initialized the native library:\n" + result.stdout)
        test_library = events_test_lib or os.environ.get("LMB_PACKAGE_EVENTS_TEST_LIB")
        test_fixture = events_fixture or os.environ.get("LMB_PACKAGE_EVENTS_FIXTURE")
        if bool(test_library) != bool(test_fixture):
            raise tp.Fail("external events library and fixture must be supplied together")
        if test_library:
            test_library, test_fixture = map(os.path.abspath, (test_library, test_fixture))
            identities = {path: tp.sha256_of(path) for path in (test_library, test_fixture)}
            retained.source(test_library)
            retained.source(test_fixture)
            print("external events inputs:", json.dumps(identities, sort_keys=True))
            if retained.root:
                (retained.root / "external-events.json").write_text(json.dumps(identities, indent=2) + "\n")
            env["LMB_NATIVE_LIB"] = test_library
            for name, binary in consumers:
                if name not in ("link", "buffer"):
                    continue
                result = retained.run([binary, test_fixture, "--host-test"], cwd=isolated, env=env, timeout=120)
                if result.returncode or name.upper() + "-HOST-HARNESS-OK" not in result.stdout:
                    raise tp.Fail(name + " external host-harness consumer failed:\n" + result.stdout)
            print("external events mode: actual-reader host evidence; no product-library kernel success")
        status = "PASS"
    finally:
        try:
            retained.finish(tmp, status)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("generic consumers: packaged-only imports, relocation, native header, missing/incompatible libraries")
    print("NOT_RUN package: successful kernel maps, XDP test-run, attachment and event production")


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
