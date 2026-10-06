<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# libbpf-mojo

Proposed small Mojo interface to libbpf, using one C compatibility layer and clang-built C eBPF objects.

The initial scope is object loading, explicit attachment, bounded event batches, map access, errors, and owned cleanup. MemVeil is the first intended consumer. Application-specific probes, event meanings, correlation, and reporting belong to the application.

Status: 0.2.x supports ABI v1 (object loading, explicit attachment, bounded event batches, map access, errors, owned cleanup) with importable Mojo wrappers. MemVeil is the first consumer. This is not an upstream libbpf project or a Mojo-to-eBPF compiler.

## Licensing

First-party sources are GPL-3.0-or-later by default (`LICENSE`;
per-file `SPDX-License-Identifier` tags govern). eBPF-only sources
(`examples/tracepoint/probe.bpf.c`,
`tests/fixtures/bpf/ring_test.bpf.c`) are GPL-2.0-only; the wire
header shared by BPF and userspace
(`examples/tracepoint/event.h`) is GPL-2.0-or-later. License
texts live in `LICENSES/`. Third-party redistribution notices
ship in release tarballs under `licenses/` with
`THIRD-PARTY-NOTICES.md`.
