#!/usr/bin/env python3
"""Package proof: the exact tarball works in a clean room.

Rebuilds the tarball with tools/package, verifies the manifest
hashes against the extracted files, then runs the packaged example
plus missing/incompatible-library negatives inside a fresh
privileged container that has neither compiler nor Pixi (see
Dockerfile.clean and clean-check.sh).

Exit 0 on pass, 77 on explicit skip (no docker), 1 on failure.
Standard library only.
"""

import glob
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SKIP = 77
IMAGE = "libbpf-mojo-clean:20261005"


class Skip(Exception):
    pass


class Fail(Exception):
    pass


def package_version():
    with open(os.path.join(ROOT, "pixi.toml"), "rb") as handle:
        data = tomllib.load(handle)
    for section in ("workspace", "project"):
        if isinstance(data.get(section), dict) and "version" in data[section]:
            return data[section]["version"]
    raise Fail("no version in pixi.toml")


def run(cmd, **kwargs):
    return subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, **kwargs)


def build_package(version):
    proc = run([os.path.join(ROOT, "tools/package")], cwd=ROOT)
    if proc.returncode != 0:
        raise Fail("tools/package failed:\n%s" % proc.stdout)
    balls = sorted(glob.glob(os.path.join(
        ROOT, "dist", "libbpf-mojo-%s.tar.gz" % version)))
    if not balls:
        raise Fail("tools/package produced no tarball")
    print("tarball: %s" % balls[0])
    return balls[0]


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_manifest(tarball, version):
    tmp = tempfile.mkdtemp(prefix="pkg-verify-")
    try:
        root = "libbpf-mojo-%s" % version
        with tarfile.open(tarball, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.startswith(("/", "..")) \
                        or "/../" in member.name:
                    raise Fail("unsafe tar member: %r" % member.name)
                # Verification and execution must select the same
                # root: reject anything outside exactly one expected
                # root instead of silently ignoring it.
                if member.name != root \
                        and not member.name.startswith(root + "/"):
                    raise Fail("member outside expected root: %r"
                               % member.name)
            tar.extractall(tmp, filter="data")
        top = os.path.join(tmp, "libbpf-mojo-%s" % version)
        manifest_path = os.path.join(top, "MANIFEST.json")
        if not os.path.isfile(manifest_path):
            raise Fail("MANIFEST.json missing from package")
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        if manifest.get("package") != "libbpf-mojo" \
                or manifest.get("version") != version:
            raise Fail("manifest identity mismatch: %r"
                       % manifest.get("version"))
        expect = {
            "lib/libbpf_mojo.so.1",
            "examples/tracepoint_main",
            "examples/tracepoint_trigger",
            "examples/probe.bpf.o",
            "examples/reference_consumer",
            "include/libbpf_mojo.h",
            "run-tracepoint.sh",
            "README.md",
            "MANIFEST.json",
            "THIRD-PARTY-NOTICES.md",
            "licenses/LICENSE.BSD-2-Clause.libbpf",
            "licenses/GPL-3.0.txt",
            "licenses/RUNTIME.LIBRARY.EXCEPTION",
            "licenses/LICENSE.zlib",
            "licenses/NOTICE.mojo-runtime.md",
            "licenses/LICENSE.mojo-compiler",
            "licenses/Third-Party-Notices.mojo-compiler",
        }
        on_disk = set()
        for dirpath, _dirnames, filenames in os.walk(top):
            for name in filenames:
                on_disk.add(os.path.relpath(
                    os.path.join(dirpath, name), top))
        if not expect.issubset(on_disk):
            raise Fail("package missing files: %r"
                       % sorted(expect - on_disk))
        hashed = {row["path"]: row["sha256"]
                  for row in manifest.get("files", [])}
        for path in sorted(hashed):
            if path not in on_disk:
                raise Fail("manifest lists missing file: %s" % path)
        for path in sorted(on_disk):
            if path == "MANIFEST.json":
                continue
            if hashed.get(path) != sha256_of(os.path.join(top, path)):
                raise Fail("hash mismatch: %s" % path)
        if manifest["bridge"]["sha256"] != hashed.get(
                "lib/libbpf_mojo.so.1"):
            raise Fail("bridge identity mismatch")
        if manifest["bpf"]["sha256"] != hashed.get(
                "examples/probe.bpf.o"):
            raise Fail("bpf identity mismatch")
        coverage = manifest.get("licenses")
        if not isinstance(coverage, dict) or not coverage:
            raise Fail("manifest has no license coverage map")
        for path in sorted(coverage):
            if path not in on_disk:
                raise Fail("coverage lists phantom %s" % path)
        for path in sorted(on_disk):
            if not path.startswith("lib/") \
                    or path == "lib/libbpf_mojo.so.1":
                continue
            notices = coverage.get(path)
            if not notices:
                raise Fail("bundled %s has no notice coverage"
                           % path)
            for notice in notices:
                if notice not in on_disk:
                    raise Fail("coverage lists missing %s for %s"
                               % (notice, path))
        verified = manifest.get("runtime", {}).get("verified", {})
        if not isinstance(verified, dict) or not verified:
            raise Fail("manifest has no runtime byte verification")
        for path in sorted(on_disk):
            if not path.startswith("lib/") \
                    or path == "lib/libbpf_mojo.so.1":
                continue
            entry = verified.get(os.path.basename(path))
            if not isinstance(entry, dict):
                raise Fail("bundled %s has no byte verification"
                           % path)
            if entry.get("sha256") != hashed.get(path):
                raise Fail("byte verification mismatch: %s" % path)
            if "package" not in entry or "relocated" not in entry:
                raise Fail("byte verification incomplete: %s" % path)
        notices_path = os.path.join(top, "THIRD-PARTY-NOTICES.md")
        with open(notices_path, "r", encoding="utf-8") as handle:
            notices_text = handle.read()
        for staged in ("licenses/LICENSE.mojo-compiler",
                       "licenses/Third-Party-Notices.mojo-compiler"):
            if staged not in notices_text:
                raise Fail("notices do not reference %s" % staged)
        tag = re.search(r"tag (v[0-9.]+)", notices_text)
        if tag is None or not re.fullmatch(
                r"v\d+\.\d+\.\d+", tag.group(1)):
            raise Fail("libbpf tag malformed: %r" % (
                tag.group(1) if tag else None,))
        claimed = re.search(r"libbpf ([0-9.]+),", notices_text)
        if claimed is None or not re.fullmatch(
                r"\d+\.\d+\.\d+", claimed.group(1)):
            raise Fail("libbpf version malformed: %r" % (
                claimed.group(1) if claimed else None,))
        print("manifest: %d files verified, bridge %s, bpf %s, "
              "%d libs covered, %d libs byte-bound" % (
                  len(hashed), manifest["bridge"]["sha256"][:16],
                  manifest["bpf"]["sha256"][:16], len(coverage),
                  len(verified)))
        tamper_negatives(top, version)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def tamper_negatives(top, version):
    """Altered staged bytes must fail the packaging gates.

    Copies the verified tree once per probe, tampers a single
    staged file, and requires the notices or manifest step to
    reject it. The gates under test are the repo's own tools.
    """
    build_dir = os.path.join(
        ROOT, os.environ.get("LMB_BUILD_DIR", "build"))
    receipt = os.path.join(build_dir, "build-receipt.json")
    pixi_lib = os.path.join(ROOT, ".pixi", "envs", "default", "lib")
    libbpf_src = os.path.join(
        build_dir, "libbpf_external-prefix", "src", "libbpf_external")
    lock = os.path.join(ROOT, "toolchain.lock.json")
    sysneeds = os.path.join(tempfile.mkdtemp(prefix="pkg-neg-"),
                            "sysneeds.txt")
    with open(sysneeds, "w", encoding="utf-8") as handle:
        handle.write("dummy\n")
    probes = [
        ("header", "include/libbpf_mojo.h", "manifest"),
        ("runner", "run-tracepoint.sh", "manifest"),
        ("runtime-lib", "lib/libz.so.1", "manifest"),
        ("runtime-lib", "lib/libz.so.1", "notices"),
        ("mojo-license", "licenses/LICENSE.mojo-compiler", "manifest"),
        ("libbpf-license", "licenses/LICENSE.BSD-2-Clause.libbpf",
         "manifest"),
    ]
    try:
        for label, rel, gate in probes:
            stage = tempfile.mkdtemp(prefix="pkg-neg-")
            shutil.copytree(top, os.path.join(stage, "pkg"),
                            symlinks=True)
            pkg = os.path.join(stage, "pkg")
            with open(os.path.join(pkg, rel), "ab") as handle:
                handle.write(b"\n# tampered\n")
            if gate == "manifest":
                cmd = [sys.executable,
                       os.path.join(ROOT, "tools", "package_manifest.py"),
                       version, pkg, lock, receipt, build_dir,
                       sysneeds, pixi_lib, libbpf_src]
            else:
                cmd = [sys.executable,
                       os.path.join(ROOT, "tools", "package_notices.py"),
                       pixi_lib, pkg, libbpf_src, "0.0.0-test", version]
            proc = run(cmd, cwd=ROOT)
            shutil.rmtree(stage, ignore_errors=True)
            if proc.returncode == 0:
                raise Fail("tamper negative passed: %s via %s"
                           % (label, gate))
    finally:
        shutil.rmtree(os.path.dirname(sysneeds), ignore_errors=True)
    print("tamper negatives: %d rejected" % len(probes))


def remove_owned_container(name):
    """Remove the owned clean-room container and verify absence.

    Removal is bounded and absence is verified: an already-absent
    container is fine (`--rm` got there first), but a surviving
    container or an unverifiable daemon state fails loudly. A
    privileged container must never be left behind unverified.
    """
    try:
        subprocess.run(["docker", "rm", "-f", name],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60)
    except subprocess.TimeoutExpired:
        raise Fail("removal of %s timed out" % name)
    try:
        inspect = subprocess.run(
            ["docker", "inspect", "--format={{.State.Running}}", name],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=60)
    except subprocess.TimeoutExpired:
        raise Fail("cannot verify removal of %s: inspect timed out"
                   % name)
    if inspect.returncode == 0:
        raise Fail("owned container %s survived removal (running=%s)"
                   % (name, inspect.stdout.strip()))
    # Absent wording varies by Docker version ("No such container"
    # vs "No such object"); anything else is unverifiable.
    lowered = inspect.stdout.lower()
    if "no such container" in lowered or "no such object" in lowered:
        return
    raise Fail("cannot verify removal of %s: %s"
               % (name, inspect.stdout.strip()[-300:]))


def clean_room(tarball, version):
    if shutil.which("docker") is None:
        raise Skip("no docker; cannot run the clean-room check")
    proc = run(["docker", "build", "-f", "Dockerfile.clean",
                "-t", IMAGE, "."],
               cwd=HERE, timeout=600)
    if proc.returncode != 0:
        raise Fail("clean image build failed:\n%s" % proc.stdout[-3000:])
    proc = run(["docker", "inspect", "--format={{.Id}}", IMAGE])
    print("clean image: %s" % proc.stdout.strip())
    check = os.path.join(HERE, "clean-check.sh")
    # A unique owned name: killing the local client on timeout does
    # not stop the container, so the name is removed in a finally
    # on every path, including timeouts and interruption.
    name = "lmb-clean-%d-%d" % (os.getpid(), random.randrange(1 << 30))
    proc = None
    try:
        try:
            proc = run([
                "docker", "run", "--rm", "--name", name, "--privileged",
                "-v", "/sys/kernel/tracing:/sys/kernel/tracing",
                "-v", "%s:/pkg.tgz:ro" % tarball,
                "-v", "%s:/clean-check.sh:ro" % check,
                IMAGE, "sh", "/clean-check.sh",
                "libbpf-mojo-%s" % version,
            ], timeout=600)
        except subprocess.TimeoutExpired:
            # The finally below removes before this propagates.
            raise Fail("clean-room check timed out; container removed")
    finally:
        remove_owned_container(name)
    print(proc.stdout[-3000:])
    if proc.returncode == SKIP or "CLEAN-SKIP" in proc.stdout:
        raise Skip("clean room reports no privilege")
    if proc.returncode != 0 or "CLEAN-PASS" not in proc.stdout:
        raise Fail("clean-room check failed (exit %d)" % proc.returncode)
    print("clean room: CLEAN-PASS")


def main():
    version = package_version()
    tarball = build_package(version)
    verify_manifest(tarball, version)
    clean_room(tarball, version)


if __name__ == "__main__":
    try:
        main()
    except Skip as exc:
        print("SKIP: %s" % exc)
        sys.exit(SKIP)
    except Fail as exc:
        print("FAIL: %s" % exc)
        sys.exit(1)
    print("PASS")
