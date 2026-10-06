#!/usr/bin/env python3
"""Shared conda-package attribution for packaging.

Binds every staged runtime library to the exact pinned conda
package that owns it (conda-meta file lists) and to that
package's recorded per-file hashes (info/paths.json in the
package cache), so altered bytes cannot ship under an original
attribution. Also locates a package's license files for notice
staging. Imported by package_notices.py and
package_manifest.py. Standard library only.
"""

import glob
import hashlib
import json
import os

# Environment override for the package cache: a direct path to a
# `pkgs` directory holding extracted `<name>-<version>-<build>/`
# trees. Otherwise the well-known pixi/rattler locations are
# searched.
CACHE_ENV_OVERRIDE = "LMB_CONDA_PKGS"

# Proprietary package name to the license files it must provide:
# cache/env basename to staged path. A proprietary bundle
# without an entry, or with a different file set, fails
# packaging: new terms need human review, never silent
# omission.
PROPRIETARY_LICENSES = {
    "mojo-compiler": {
        "LICENSE": "licenses/LICENSE.mojo-compiler",
        "Third-Party-Notices":
            "licenses/Third-Party-Notices.mojo-compiler",
    },
}


class AttributionError(Exception):
    """A binding that must fail packaging, with the detail."""


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cache_roots():
    """Candidate package-cache roots, most specific first."""
    roots = []
    override = os.environ.get(CACHE_ENV_OVERRIDE)
    if override:
        roots.append(override)
    pixi_cache = os.environ.get("PIXI_CACHE_DIR")
    if pixi_cache:
        roots.append(os.path.join(pixi_cache, "pkgs"))
        roots.append(os.path.join(pixi_cache, "cache", "pkgs"))
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        roots.append(os.path.join(xdg, "rattler", "cache", "pkgs"))
    roots.append(os.path.expanduser("~/.cache/rattler/cache/pkgs"))
    seen = set()
    ordered = []
    for root in roots:
        if root not in seen:
            seen.add(root)
            ordered.append(root)
    return ordered


def package_dir(name, version, build):
    """Extracted cache dir for an exact package, or None."""
    leaf = "%s-%s-%s" % (name, version, build)
    for root in cache_roots():
        cand = os.path.join(root, leaf)
        if os.path.isdir(os.path.join(cand, "info")):
            return cand
    return None


def load_file_index(prefix):
    """Map conda-owned relative paths to their package metadata."""
    metas = glob.glob(os.path.join(prefix, "conda-meta", "*.json"))
    if not metas:
        raise AttributionError("no conda-meta under %s" % prefix)
    by_file = {}
    for meta_path in sorted(metas):
        with open(meta_path, "r", encoding="utf-8") as handle:
            try:
                meta = json.load(handle)
            except ValueError as exc:
                raise AttributionError("bad conda-meta %s: %s"
                                       % (meta_path, exc))
        for key in ("name", "version", "build"):
            if not meta.get(key):
                raise AttributionError("malformed conda-meta: %s"
                                       % meta_path)
        for owned in meta.get("files", []):
            by_file.setdefault(owned, meta)
    return by_file


def trace_owner(by_file, prefix, pixi_lib, soname):
    """Conda metadata owning soname, or None if unattributed."""
    rels = ["lib/" + soname]
    real = os.path.realpath(os.path.join(pixi_lib, soname))
    base = os.path.abspath(prefix) + os.sep
    if real.startswith(base):
        rels.append(os.path.relpath(real, prefix))
    for rel in rels:
        if rel in by_file:
            return by_file[rel]
    return None


def staged_runtime_libs(stage, bridge="libbpf_mojo.so.1"):
    """Staged lib/*.so* names except the bridge, sorted."""
    libdir = os.path.join(stage, "lib")
    return sorted(
        name for name in os.listdir(libdir)
        if name != bridge
        and os.path.isfile(os.path.join(libdir, name)))


def recorded_hash(pkgdir, rel):
    """(sha256, relocated) recorded for rel, or None if absent.

    Relocated files carry a prefix placeholder: their installed
    bytes legitimately differ from the recorded hash, so the
    caller must bind them to the environment source instead.
    """
    paths_path = os.path.join(pkgdir, "info", "paths.json")
    if not os.path.isfile(paths_path):
        raise AttributionError("no info/paths.json in %s" % pkgdir)
    with open(paths_path, "r", encoding="utf-8") as handle:
        try:
            entries = json.load(handle)["paths"]
        except (ValueError, KeyError) as exc:
            raise AttributionError("bad paths.json in %s: %s"
                                   % (pkgdir, exc))
    by_path = {entry.get("_path"): entry for entry in entries}
    entry = by_path.get(rel)
    if entry is not None and entry.get("sha256"):
        return entry["sha256"], bool(entry.get("prefix_placeholder"))
    # A link without a recorded hash resolves inside the
    # payload; anything escaping the package is not our file.
    target = os.path.realpath(os.path.join(pkgdir, rel))
    base = os.path.abspath(pkgdir) + os.sep
    if target.startswith(base):
        entry = by_path.get(os.path.relpath(target, pkgdir))
        if entry is not None and entry.get("sha256"):
            return entry["sha256"], bool(entry.get("prefix_placeholder"))
    return None


def verify_staged_runtime(pixi_lib, stage, bridge="libbpf_mojo.so.1"):
    """Bind every staged runtime lib to its pinned bytes.

    Returns {soname: {"package", "sha256", "relocated"}}. The
    sha256 is the staged bytes' hash; for relocated files it is
    bound to the environment source (whose bytes the install
    legitimately rewrote), for the rest to the package's
    recorded hash. Raises AttributionError on anything
    unattributed, unlocatable, or mismatched.
    """
    prefix = os.path.dirname(os.path.abspath(pixi_lib.rstrip("/")))
    by_file = load_file_index(prefix)
    libs = staged_runtime_libs(stage, bridge)
    if not libs:
        raise AttributionError("no staged runtime libraries")
    verified = {}
    for soname in libs:
        meta = trace_owner(by_file, prefix, pixi_lib, soname)
        if meta is None:
            raise AttributionError(
                "%s traces to no conda package; refusing to ship "
                "an unattributed binary" % soname)
        name, version, build = (meta["name"], meta["version"],
                                meta["build"])
        pkgdir = package_dir(name, version, build)
        if pkgdir is None:
            raise AttributionError(
                "%s: package %s %s (%s) has no extracted cache "
                "dir; searched %s (override with %s)" % (
                    soname, name, version, build,
                    ", ".join(cache_roots()), CACHE_ENV_OVERRIDE))
        staged = os.path.join(stage, "lib", soname)
        staged_hash = sha256_of(staged)
        rels = ["lib/" + soname]
        real = os.path.realpath(os.path.join(pixi_lib, soname))
        base = os.path.abspath(prefix) + os.sep
        if real.startswith(base):
            rels.append(os.path.relpath(real, prefix))
        recorded = None
        for rel in rels:
            recorded = recorded_hash(pkgdir, rel)
            if recorded is not None:
                break
        if recorded is None:
            raise AttributionError(
                "%s: no recorded hash in package %s %s (%s)"
                % (soname, name, version, build))
        want, relocated = recorded
        if relocated:
            env_src = os.path.join(pixi_lib, soname)
            if not os.path.isfile(env_src):
                raise AttributionError(
                    "%s: relocated file with no environment "
                    "source %s" % (soname, env_src))
            if sha256_of(env_src) != staged_hash:
                raise AttributionError(
                    "staged %s does not match its environment "
                    "source (relocated file, torn copy?)"
                    % soname)
        elif staged_hash != want:
            raise AttributionError(
                "staged %s does not match package %s %s (%s) "
                "recorded hash" % (soname, name, version, build))
        verified[soname] = {
            "package": "%s %s (%s)" % (name, version, build),
            "sha256": staged_hash,
            "relocated": relocated,
        }
    return verified


def package_license_files(prefix, pkgdir, name, version, build):
    """{basename: full path} of a package's license files.

    Prefers the installed environment's license directory,
    then the package cache's. Raises AttributionError when
    neither provides any file.
    """
    candidates = [
        os.path.join(prefix, "share", "licenses", name),
        os.path.join(prefix, "share", "licenses",
                     "%s-%s-%s" % (name, version, build)),
        os.path.join(pkgdir, "info", "licenses"),
    ]
    for directory in candidates:
        if not os.path.isdir(directory):
            continue
        found = {}
        for base in sorted(os.listdir(directory)):
            full = os.path.join(directory, base)
            if os.path.isfile(full):
                found[base] = full
        if found:
            return found
    raise AttributionError(
        "package %s %s (%s) provides no license files; searched %s"
        % (name, version, build, ", ".join(candidates)))
