#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Offline acquisition of independently pinned test schema data only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

TRUSTED_CANONICAL_SHA256 = "f26344f33e5efd863ece1ce59d8e19bf26daaae0c82b97074afd176ae7011ad7"
LOCK = Path(__file__).with_name("bundle-lock.json")


class BundleError(ValueError):
    pass


def canonical_digest(data):
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BundleError("duplicate manifest key")
        result[key] = value
    return result


def ordinary_path(path, directory=False):
    path = Path(path).absolute()
    try:
        if path.resolve(strict=True) != path:
            raise BundleError("symlink paths are refused")
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
            raise BundleError("an ordinary directory or file is required")
    except OSError as exc:
        raise BundleError("missing or inaccessible bundle input") from exc
    return path


def read_file(path):
    path = ordinary_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise BundleError("input is not an ordinary file")
            return source.read()
    except OSError as exc:
        raise BundleError("bundle input could not be read") from exc


def verified_bytes(source):
    root = ordinary_path(source, directory=True)
    try:
        lock = json.loads(read_file(LOCK), object_pairs_hook=unique_keys)
        expected = lock["manifest"]
        if lock["canonical_sha256"] != TRUSTED_CANONICAL_SHA256 or canonical_digest(expected) != TRUSTED_CANONICAL_SHA256:
            raise BundleError("trusted lock differs from the independent pin")
        files = {"bundle.json": read_file(root / "bundle.json")}
        manifest = json.loads(files["bundle.json"], object_pairs_hook=unique_keys)
        if not isinstance(manifest, dict) or type(manifest.get("version")) is not int or manifest["version"] != 1:
            raise BundleError("bundle version must be integer 1")
        schemas = manifest.get("schemas")
        if not isinstance(schemas, dict) or set(schemas) != set(expected["schemas"]):
            raise BundleError("schema set differs from the trusted set")
        for name in expected["schemas"]:
            entry = schemas[name]
            if not isinstance(entry, dict) or type(entry.get("version")) is not int or entry["version"] != 1:
                raise BundleError("schema version must be integer 1")
        if canonical_digest(manifest) != TRUSTED_CANONICAL_SHA256:
            raise BundleError("manifest differs from the independent canonical pin")
        for name, entry in expected["schemas"].items():
            files[name] = read_file(root / name)
            if hashlib.sha256(files[name]).hexdigest() != entry["sha256"]:
                raise BundleError("schema bytes differ from the trusted pin: " + name)
        return files
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise BundleError("malformed bundle manifest or trusted lock") from exc


def verify_bundle(source):
    files = verified_bytes(source)
    return {"canonical_sha256": TRUSTED_CANONICAL_SHA256,
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}


def acquire_bundle(source, destination):
    files = verified_bytes(source)
    output = Path(destination).absolute()
    ordinary_path(output.parent, directory=True)
    if output.exists() or output.is_symlink():
        raise BundleError("output must be a new owned directory")
    created = False
    try:
        output.mkdir()
        created = True
        for name, data in files.items():
            with (output / name).open("xb") as target:
                target.write(data)
        report = verify_bundle(output)
        if any((output / name).read_bytes() != data for name, data in files.items()):
            raise BundleError("copied bundle differs from the verified input bytes")
        return report
    except (OSError, BundleError) as exc:
        if created:
            shutil.rmtree(output)
        raise BundleError("schema acquisition failed: " + str(exc)) from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(acquire_bundle(args.source, args.destination), sort_keys=True))
    except BundleError as exc:
        raise SystemExit("FAIL contracts: " + str(exc)) from exc


if __name__ == "__main__":
    main()
