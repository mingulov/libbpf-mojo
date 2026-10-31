<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Releasing

Releases are cut by tag from a clean tree.
The `release` workflow (`.github/workflows/release.yml`)
does the rest; this file states the order so a
human can follow and audit it.

## Tag and publish

1. Set the new version across the package
   manifest, docs, and test pins (the
   previous version-set commit lists the
   files), commit, tag `vX.Y.Z`, and push
   the tag. `v0.*` and hyphenated tags
   publish as prereleases.
2. The workflow provisions the locked
   toolchain, runs the offline gate suites
   plus the clean-room package lane, and
   builds `dist/libbpf-mojo-<version>.tar.gz`
   from the clean tag tree.
3. It writes `SHA256SUMS.txt`, attests
   Sigstore build provenance, and uploads
   the tarball plus checksums to the tag's
   GitHub Release with generated notes. A
   rerun of the same tag fails instead of
   replacing uploaded files; rollback is a
   new tag.

Consumers pin the exact version plus
tarball hash, so a release never changes a
consumer until that pin moves deliberately.

## Dry run

Dispatch the workflow manually to build
everything without publishing; the set is
kept as a `release-dry-run` workflow
artifact.
