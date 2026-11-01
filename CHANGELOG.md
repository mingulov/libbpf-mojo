<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Changelog

Releases are `vX.Y.Z` git tags with GitHub
Releases carrying the tarball plus checksums
(see [releasing](RELEASING.md)). Consumers
pin the exact version plus tarball hash.
Entries name user-visible changes only;
commit history has the rest.

## 0.3.0 development candidate

- Add explicit entry/return kernel probes to the session and generic link APIs,
  with move-only Mojo ownership and declarative capability requirements.
- Detach session links in reverse attachment order, including implicit close;
  retain all-or-none attachment rollback and signed error preservation.
- Preserve ABI major 1 layouts, signatures, existing discriminants and soname.
  New functionality is unqualified pending exact-artifact live tests.

## 0.2.3 candidate

- Deterministic reviewed source-seal refresh
  preserves frozen API meanings.

- Qualification results route through
  self-sufficient receipts.
- Privileged environment lookup refused;
  allocation bounded and hardened.
- One aligned error contract; top-level
  surface published.
- Prerelease publishing without overwrite,
  dry-run artifacts, and signed build
  provenance.
- Ratified live-collection floor (Linux 6.0,
  BTF required) with split evidence, and the
  evolution and support policy.

## v0.2.2 -- 2026-10-30

Pinned toolchain moves to pixi 0.83.0 and
Mojo 1.2.0.

## v0.2.1 -- 2026-10-21

Generic live surfaces (retained map deletion
and key iteration, ring-adapter conformance
with buffer stats snapshot, log-buffer fix),
source-bound libbpf API inventory with
coverage contract, verified executable build
inputs, and the tag-triggered release
pipeline.

## v0.2.0 -- 2026-10-12

Second release: ABI v1 session surface
(object loading, explicit attachment,
bounded event batches, map access, errors,
owned cleanup).
