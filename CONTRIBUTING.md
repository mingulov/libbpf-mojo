<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Contributing

## Prerequisites

Pinned Mojo toolchain via pixi plus system C
tooling for the native bridge; see
[build](docs/build.md) and
`toolchain.lock.json`.

## Build and test

```sh
./tools/build                    # build everything
./tools/test --help              # list suites
./tools/test native              # one suite
```

Run the suites that cover a change; run the
full gate before declaring green. Do not
invent a Mojo test command: `tools/test` is
the only runner. Privileged fixtures belong
in the designated isolated environment.

## Style and scope

- Keep changes scoped to this repository.
  The native ABI is owned here: layout
  changes need matching C static assertions
  and Mojo layout assertions plus version
  handling, never silent reinterpretation.
- Every first-party source file carries an
  SPDX header. Keep application probes,
  event meanings, correlation, and reporting
  out: they belong to the consumer.
- Documentation edits need link, accuracy,
  scope, and whitespace checks, not new
  runtime tests. Behavior changes need
  behavior-focused tests for the affected
  contracts.
- All writing must stand alone: no
  references to private plans, sibling
  checkouts, or internal workflow.

## Licence acceptance

Contributions are accepted under the
repository licence (Apache-2.0 WITH
LLVM-exception; BPF example object
GPL-2.0-only). Only contribute material you
have the right to license this way, and
preserve source attribution.
