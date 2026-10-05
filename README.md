# libbpf-mojo

Proposed small Mojo interface to libbpf, using one C compatibility layer and clang-built C eBPF objects.

The initial scope is object loading, explicit attachment, bounded event batches, map access, errors, and owned cleanup. MemVeil is the first intended consumer. Application-specific probes, event meanings, correlation, and reporting belong to the application.

Status: repository initialized for a feasibility experiment; no implementation or supported API is available yet. This is not an upstream libbpf project or a Mojo-to-eBPF compiler.
