<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# libbpf-mojo

Small Mojo interface to libbpf, using one C compatibility layer and clang-built C eBPF objects.

The initial scope is object loading, explicit attachment, bounded event batches, map access, errors, and owned cleanup. MemVeil is the first intended consumer. Application-specific probes, event meanings, correlation, and reporting belong to the application.

Status: 0.1.0 supports ABI v1 (object loading, explicit attachment, bounded event batches, map access, errors, owned cleanup) with importable Mojo wrappers. MemVeil is the first consumer. This is not an upstream libbpf project or a Mojo-to-eBPF compiler.

## Build, test, and package

Pinned Mojo 1.1.0 toolchain via pixi plus system C tooling;
see `docs/build.md` and `toolchain.lock.json`.

    ./tools/build                                    # everything
    ./tools/test --help                              # list suites
    ./tools/test native                              # C contracts
    ./tools/test mojo                                # Mojo ownership
    ./tools/test package-consumer                    # tarball serves a consumer
    ./tools/package                                  # release tarball + MANIFEST

`docs/abi-v1.md` is the normative C boundary contract;
`docs/ownership.md` states lifetimes, errors, and transport in
prose; `docs/support.md` states the tested envelope;
`examples/tracepoint/` is a small real collection through the
whole stack.

## Licensing

First-party sources are Apache-2.0 WITH LLVM-exception by default
(`LICENSE` plus `LICENSES/LLVM-exception.txt`; per-file
`SPDX-License-Identifier` tags govern). eBPF-only sources
(`examples/tracepoint/probe.bpf.c`,
`tests/fixtures/bpf/ring_test.bpf.c`) are GPL-2.0-only and keep
the kernel `SEC("license") = "GPL"` tag their helpers require;
the wire header shared by BPF and userspace
(`examples/tracepoint/event.h`) carries the default id, whose
exception permits the GPLv2 combination in the built object.
Third-party redistribution notices ship in release tarballs
under `licenses/` with `THIRD-PARTY-NOTICES.md`.
