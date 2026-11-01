<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Evolution and support policy

This policy covers releases from v0.2.0. It states how
the ABI, the bridge library, the kernel floor, and the
tarball evolve, and how to report a vulnerability.
Every `vX.Y.Z` named here must exist as a git tag
(pinned by the provenance gate); future releases are
named without the `v` prefix until they are tagged.

The 0.3.0 development candidate keeps both ABI major 1 contracts and the
existing soname. Its version does not qualify new kernel environments or
replace historical runtime evidence. Consumers bind its clean source revision,
runtime archive digest, corresponding source archive digest and dependency
source/license identities before admitting the exact artifact.

## ABI and framing windows

The native ABI major 1 ([abi-v1](abi-v1.md)) and the
generic ABI 1 ([generic-abi-v1](generic-abi-v1.md))
are frozen: every top-level parameter struct begins
with `abi_version` and `struct_size`, and unknown
majors or short structs are rejected, never
reinterpreted. Batch framing version 1 and the BPF
payload layout version independently of the ABI
major. A new ABI major ships as new structs and new
`lmb_*` entry points beside the old ones; the old
major stays accepted until a later release removes
it, announced in the release notes one minor
version ahead and never silently. The consumer
schema (`schemas/api-coverage.schema.json`) versions
with the release that changes it.

## Bridge library versioning

`libbpf_mojo.so.1` carries the ABI major in its
soname. Compatible fixes keep `.so.1`; an ABI
break ships `.so.2` with the old library still
shipped until the window above expires. Clients
that dlopen by soname keep working across
compatible releases; clients that pin the tarball
hash (as MemVeil does) are unaffected by any
compatible change.

## Kernel floor

Live bridge primitives work from Linux 6.0 with
BTF ([support envelope](support.md)): this
repository's privileged suite qualifies
7.0.0-38-generic, and MemVeil's booted matrix
qualifies the 6.0 through 6.10 attempt rows.
The floor moves only with new live evidence
plus the accompanying doc update, in either
repository.

## Tarball upgrade, rollback, end of life

- Upgrade re-pins the consumer to the new exact
  version plus tarball hash; a libbpf-mojo
  release never changes a consumer until that
  pin moves deliberately.
- Rollback re-pins to the previous version and
  hash; a rerun of a release tag never replaces
  published files (rollback is a new tag).
- A release is supported until the next minor
  release supersedes it; 0.2.x versions are
  development prereleases with no long-term
  branch. End of life is announced in the
  release notes of the superseding release.

## Security response

Report vulnerabilities privately to the
maintainer (Denis Mingulov
<denis@mingulov.com>). Do not file public
issues for unpatched disclosures. Each report
gets a private fix with a regression test, a
release-notes entry crediting the reporter
unless they decline, and a new release; the
advisory states affected versions and the
upgrade path. Response-time promises start
with the first stable release; until then
this route is best-effort.

## Surface homes

Every shipped surface's contract is its doc
plus its header or schema; anything without
a home is removed, not shipped.

| Surface | Contract | Home |
| --- | --- | --- |
| session ABI | `native/include/libbpf_mojo.h` | [abi-v1](abi-v1.md) |
| generic ABI | `native/include/libbpf_mojo_generic.h` | [generic-abi-v1](generic-abi-v1.md) |
| Mojo wrappers | `src/libbpf_mojo/` | [ownership](ownership.md), [links-and-ring](links-and-ring.md) |
| API coverage schema | `schemas/api-coverage.schema.json` | the schema (self-describing) |
| maps/test-run | bridge calls | [maps-and-test-run](maps-and-test-run.md) |

## Shipped licences

First-party code is Apache-2.0 WITH
LLVM-exception (`LICENSE` plus
`LICENSES/LLVM-exception.txt`). The BPF
example object is GPL-2.0-only
(`LICENSES/GPL-2.0-only.txt`). The statically
linked libbpf 1.7.0 is BSD-2-Clause (text
required from its source tree at pack time).
This section, `LICENSE`, `LICENSES/`, and the
packaged notices together are the licence
answer; if they disagree, the staged texts
win.
