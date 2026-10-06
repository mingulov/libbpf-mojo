#!/usr/bin/env python3
"""Shared provenance sealing for build receipts and packaging.

`source_manifest` seals every build input file — mode plus
content hash — into a tree digest, so a receipt names the exact
sources compiled, not just HEAD plus "-dirty". Imported by
build_receipt.py and package_manifest.py (the invoking wrappers
run them as `python3 tools/...`, which puts this directory on
sys.path). As a script it seals one manifest to stdout:
`provenance.py seal <root> [git|archive]`. Standard library
only.
"""

import hashlib
import json
import os
import subprocess
import sys

# Archive inventory excludes: the declared source-input list for
# trees without git metadata. Mirrors .gitignore's generated and
# environment entries (plus git's own directory), so a checkout
# and a source archive of the same tree seal the same file set.
# Directory names apply at any depth.
ARCHIVE_SKIP_DIRS = frozenset({
    ".git", ".pixi", "build", "build-san", "dist",
    "__pycache__", ".pytest_cache", ".mypy_cache",
})
ARCHIVE_SKIP_FILES = frozenset({".DS_Store"})


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_skip(rel):
    """True when rel is a generated/environment path, not input."""
    parts = rel.split(os.sep)
    # Directory names match enclosing components only: a file
    # merely named like one (tools/build) is still an input,
    # exactly as a trailing-slash .gitignore entry behaves.
    if any(part in ARCHIVE_SKIP_DIRS for part in parts[:-1]):
        return True
    base = parts[-1]
    if base in ARCHIVE_SKIP_FILES or base.endswith("~"):
        return True
    if base.endswith((".o", ".a", ".pyc", ".pyo", ".so")):
        return True
    return ".so." in base


def git_files(root):
    """Tracked plus untracked paths via git, or None without git."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-c", "-o", "--exclude-standard", "-z"],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return [rel for rel in
            out.stdout.decode("utf-8", "surrogateescape").split("\0")
            if rel]


def archive_files(root):
    """Declared source inputs by tree walk. Fails closed."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in ARCHIVE_SKIP_DIRS)
        for name in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            if not archive_skip(rel):
                found.append(rel)
    return found


def source_manifest(root, mode="auto"):
    """Seal {path: {mode, sha256}} plus a tree digest.

    Mode "git" lists `git ls-files` tracked plus untracked
    files under the standard excludes, so ignored outputs never
    enter the seal while every real input — including
    uncommitted sources — does. Mode "archive" walks the tree
    under the declared ARCHIVE_SKIP excludes instead, so a
    source archive without git metadata seals the same way;
    "auto" (the default) prefers git and falls back to archive.
    The used mode is recorded in the manifest. Fails closed
    (SystemExit) when the tree cannot be listed or a file
    cannot be hashed.
    """
    if mode not in ("auto", "git", "archive"):
        sys.exit("provenance: unknown inventory mode: %s" % mode)
    rels = None
    if mode in ("auto", "git"):
        rels = git_files(root)
        if rels is None and mode == "git":
            sys.exit("provenance: git inventory unavailable for %s "
                     "(not a checkout?)" % root)
    used = "git" if rels is not None else "archive"
    if rels is None:
        rels = archive_files(root)
    files = {}
    for rel in rels:
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            sys.exit("provenance: not a regular file: %s" % rel)
        try:
            filemode = "%06o" % (os.stat(full).st_mode & 0o7777)
            files[rel] = {"mode": filemode, "sha256": sha256_of(full)}
        except OSError as exc:
            sys.exit("provenance: cannot hash %s: %s" % (rel, exc))
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(("%s %s %s\n"
                       % (files[rel]["mode"], files[rel]["sha256"],
                          rel)).encode("utf-8", "surrogateescape"))
    return {"mode": used, "files": files, "digest": digest.hexdigest()}


def check_manifest(root, sealed, where):
    """Recompute the seal in its recorded mode; reject drift.

    Receipts sealed before modes existed verify as git. A git
    seal cannot be re-listed without git metadata and fails
    closed rather than comparing across inventory modes.
    """
    if not isinstance(sealed, dict) or "digest" not in sealed \
            or not isinstance(sealed.get("files"), dict):
        sys.exit("%s: receipt seals no source manifest; rebuild "
                 "with current tools/build" % where)
    mode = sealed.get("mode", "git")
    if mode not in ("git", "archive"):
        sys.exit("%s: receipt seals unknown inventory mode %r; "
                 "rebuild with current tools/build" % (where, mode))
    fresh = source_manifest(root, mode)
    if fresh["digest"] == sealed["digest"]:
        return
    old, new = sealed["files"], fresh["files"]
    diff = sorted(set(old) | set(new))
    diff = [p for p in diff if old.get(p) != new.get(p)]
    sys.exit("%s: worktree differs from receipt (%d file(s), e.g. "
             "%s); rebuild before packaging"
             % (where, len(diff), ", ".join(diff[:5])))


def main(argv):
    if len(argv) not in (3, 4) or argv[1] != "seal":
        sys.exit("usage: provenance.py seal <root> [git|archive]")
    mode = argv[3] if len(argv) == 4 else "auto"
    manifest = source_manifest(argv[2], mode)
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)
