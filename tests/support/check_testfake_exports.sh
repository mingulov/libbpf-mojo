#!/bin/sh
# check_testfake_exports.sh <lib.so>: the test-support library must
# export exactly the four lmb_test_* helpers as global text symbols
# and nothing else. Fails closed when nm is missing.
set -u
if [ $# -ne 1 ]; then
    echo "usage: check_testfake_exports.sh <lib.so>" >&2
    exit 2
fi
if ! command -v nm >/dev/null 2>&1; then
    echo "check_testfake_exports: nm not found" >&2
    exit 1
fi
defs=$(nm -D --defined-only "$1")
funcs=$(printf '%s\n' "$defs" | grep ' T ' | tr -s ' ' | cut -d' ' -f3 | sort)
count=$(printf '%s\n' "$funcs" | grep -c '^lmb_test_')
foreign=$(printf '%s\n' "$funcs" | grep -vc '^lmb_test_')
other=$(printf '%s\n' "$defs" | grep ' [A-Z] ' | grep -v ' T ' | tr -s ' ' | cut -d' ' -f3)
if [ "$count" -ne 4 ] || [ "$foreign" -ne 0 ]; then
    echo "testfake exports BAD: helpers=$count foreign=$foreign" >&2
    exit 1
fi
if [ -n "$other" ]; then
    echo "testfake exports BAD: non-text globals: $other" >&2
    exit 1
fi
echo "testfake exports ok: 4 lmb_test_* functions, nothing else global"
