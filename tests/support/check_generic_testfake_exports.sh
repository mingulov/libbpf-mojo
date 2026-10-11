#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: check_generic_testfake_exports.sh LIB [object-only]" >&2
    exit 2
fi
python3 - "$@" <<'PY'
import subprocess, sys
old = 'open load attach poll map_info map_read map_write stats last_error detach close'.split()
generic = ('object_open object_configure_program object_load object_program_info '
           'object_map_info object_close object_release generic_last_error '
           'object_ref object_unref object_gen object_gen_check').split()
if len(sys.argv) == 2:
    generic += ['object_map_lookup', 'object_map_update', 'program_test_run']
elif sys.argv[2] != 'object-only':
    sys.exit('invalid variant')
controls = ['reset', 'scenario', 'call_count', 'close_count']
expected = {'lmb_' + x + '@@LIBBPF_MOJO_1' for x in old}
expected |= {'lmb_' + x + '_v1@@LIBBPF_MOJO_GENERIC_1' for x in generic}
expected |= {'lmb_test_generic_' + x + '@@LMB_GENERIC_TEST_1' for x in controls}
result = subprocess.run(['nm', '-D', '--defined-only', sys.argv[1]],
                        capture_output=True, text=True, check=True)
functions, other = set(), set()
for line in result.stdout.splitlines():
    _, kind, name = line.split()
    if kind == 'T': functions.add(name)
    elif kind != 'A' or name not in {'LIBBPF_MOJO_1', 'LIBBPF_MOJO_GENERIC_1', 'LMB_GENERIC_TEST_1'}:
        other.add((kind, name))
if functions != expected or other:
    sys.exit('generic testfake exports BAD: missing=%s extra=%s other=%s' %
             (sorted(expected-functions), sorted(functions-expected), sorted(other)))
print('generic testfake exports ok: 11 old + %d generic + exactly 4 scalar controls; no other globals' % len(generic))
PY
