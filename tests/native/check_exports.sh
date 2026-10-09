#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# check_exports.sh <lib.so>: the shared library must export exactly the
# eleven original lmb_* operations at LIBBPF_MOJO_1, plus only
# allowlisted generic lmb_*_v1 symbols at LIBBPF_MOJO_GENERIC_1.
# Rejects missing old symbols, reassigned versions, leaked bpf_*
# symbols, and any other global. Generic entries are permitted, not
# required: the allowlist holds before and after their
# implementation lands. Uses only POSIX grep/sort/cut so it runs on
# minimal toolchains. Fails closed when nm is missing or the
# object cannot be read.
set -u
if [ $# -ne 1 ]; then
    echo "usage: check_exports.sh <lib.so>" >&2
    exit 2
fi
if ! command -v nm >/dev/null 2>&1; then
    echo "check_exports: nm not found" >&2
    exit 1
fi
if ! defs=$(nm -D --defined-only "$1" 2>/dev/null); then
    echo "check_exports: cannot read $1" >&2
    exit 1
fi
if [ -z "$defs" ]; then
    echo "check_exports: no dynamic symbols in $1" >&2
    exit 1
fi
old="lmb_open@@LIBBPF_MOJO_1
lmb_load@@LIBBPF_MOJO_1
lmb_attach@@LIBBPF_MOJO_1
lmb_poll@@LIBBPF_MOJO_1
lmb_map_info@@LIBBPF_MOJO_1
lmb_map_read@@LIBBPF_MOJO_1
lmb_map_write@@LIBBPF_MOJO_1
lmb_stats@@LIBBPF_MOJO_1
lmb_last_error@@LIBBPF_MOJO_1
lmb_detach@@LIBBPF_MOJO_1
lmb_close@@LIBBPF_MOJO_1"
generic="lmb_object_open_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_configure_program_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_load_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_program_info_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_map_info_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_close_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_release_v1@@LIBBPF_MOJO_GENERIC_1
lmb_generic_last_error_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_map_lookup_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_map_update_v1@@LIBBPF_MOJO_GENERIC_1
lmb_program_test_run_v1@@LIBBPF_MOJO_GENERIC_1
lmb_object_attach_v1@@LIBBPF_MOJO_GENERIC_1
lmb_link_close_v1@@LIBBPF_MOJO_GENERIC_1
lmb_buffer_open_v1@@LIBBPF_MOJO_GENERIC_1
lmb_buffer_poll_v1@@LIBBPF_MOJO_GENERIC_1
lmb_buffer_close_v1@@LIBBPF_MOJO_GENERIC_1"
funcs=$(printf '%s\n' "$defs" | grep ' T ' | tr -s ' ' | cut -d' ' -f3)
if [ -z "$funcs" ]; then
    echo "exports BAD: no exported text symbols" >&2
    exit 1
fi
# Every old symbol exactly once at its original version node.
bad=0
for sym in $(printf '%s\n' "$old"); do
    n=$(printf '%s\n' "$funcs" | grep -c -x -F "$sym")
    if [ "$n" -ne 1 ]; then
        echo "exports BAD: $sym present $n times, want 1" >&2
        bad=1
    fi
done
# Every exported function is either an old symbol or an allowlisted
# generic symbol at its node. Anything else (reassigned version,
# unversioned duplicate, foreign prefix, unintended global) fails.
allow=$(printf '%s\n%s' "$old" "$generic")
for sym in $(printf '%s\n' "$funcs" | sort); do
    if ! printf '%s\n' "$allow" | grep -q -x -F "$sym"; then
        echo "exports BAD: unexpected exported function: $sym" >&2
        bad=1
    fi
done
dups=$(printf '%s\n' "$funcs" | sort | uniq -d)
if [ -n "$dups" ]; then
    echo "exports BAD: duplicated exported functions: $dups" >&2
    bad=1
fi
# The bundled implementation stays hidden: no bpf_* dynamic symbol
# of any type may be defined.
leaked=$(printf '%s\n' "$defs" | tr -s ' ' | cut -d' ' -f3 | grep '^bpf_' || true)
if [ -n "$leaked" ]; then
    echo "exports BAD: leaked upstream symbols: $leaked" >&2
    bad=1
fi
# Only the linker's own version nodes may appear as non-text globals.
other=$(printf '%s\n' "$defs" | grep ' [A-Z] ' | grep -v ' T ' | tr -s ' ' | cut -d' ' -f3 || true)
for sym in $(printf '%s\n' "$other" | sort -u); do
    if [ -z "$sym" ]; then
        continue
    fi
    if [ "$sym" != "LIBBPF_MOJO_1" ] && [ "$sym" != "LIBBPF_MOJO_GENERIC_1" ]; then
        echo "exports BAD: unexpected non-text global: $sym" >&2
        bad=1
    fi
done
if [ "$bad" -ne 0 ]; then
    exit 1
fi
ngen=$(printf '%s\n' "$funcs" | grep -c '_v1@@LIBBPF_MOJO_GENERIC_1' || true)
echo "exports ok: 11 lmb_* at LIBBPF_MOJO_1, $ngen generic at LIBBPF_MOJO_GENERIC_1, nothing else global"
