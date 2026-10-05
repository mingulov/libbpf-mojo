#!/bin/sh
# check_exports.sh <lib.so>: the shared library must export exactly the
# eleven public lmb_* operations as global text symbols. The only other
# global symbol allowed is the linker's own version node. Uses only
# POSIX grep/sort/cut so it runs on minimal toolchains. Fails closed
# when nm is missing.
set -u
if [ $# -ne 1 ]; then
    echo "usage: check_exports.sh <lib.so>" >&2
    exit 2
fi
if ! command -v nm >/dev/null 2>&1; then
    echo "check_exports: nm not found" >&2
    exit 1
fi
defs=$(nm -D --defined-only "$1")
funcs=$(printf '%s\n' "$defs" | grep ' T ' | tr -s ' ' | cut -d' ' -f3 | sort)
count=$(printf '%s\n' "$funcs" | grep -c '^lmb_')
foreign=$(printf '%s\n' "$funcs" | grep -vc '^lmb_')
other=$(printf '%s\n' "$defs" | grep ' [A-Z] ' | grep -v ' T ' | tr -s ' ' | cut -d' ' -f3)
if [ "$count" -ne 11 ] || [ "$foreign" -ne 0 ]; then
    echo "exports BAD: lmb funcs=$count foreign funcs=$foreign" >&2
    exit 1
fi
if [ -n "$other" ] && [ "$other" != "LIBBPF_MOJO_1" ]; then
    echo "exports BAD: unexpected non-text globals: $other" >&2
    exit 1
fi
echo "exports ok: 11 lmb_* functions, nothing else global"
