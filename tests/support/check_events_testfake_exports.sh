#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set -eu
python3 - "$@" <<'PY'
import subprocess, sys
if len(sys.argv) != 3:
    sys.exit('usage: check_events_testfake_exports.sh LIB VARIANT')
old = 'open load attach poll map_info map_read map_write stats last_error detach close'.split()
generic = ('object_open object_configure_program object_load object_program_info '
           'object_map_info object_close object_release generic_last_error '
           'object_map_lookup object_map_update program_test_run '
           'object_attach link_close buffer_open buffer_poll buffer_close buffer_stats '
           'object_ref object_unref object_gen object_gen_check').split()
missing = {'testfake': [], 'no_events': ['object_attach','link_close','buffer_open','buffer_poll','buffer_close','buffer_stats'],
           'no_attach': ['object_attach'], 'no_link_close': ['link_close'],
           'no_buffer_open': ['buffer_open'], 'no_buffer_poll': ['buffer_poll'],
           'no_buffer_close': ['buffer_close'], 'no_buffer_stats': ['buffer_stats']}
if sys.argv[2] not in missing:
    sys.exit('invalid variant')
generic = [name for name in generic if name not in missing[sys.argv[2]]]
expected = {'lmb_' + x + '@@LIBBPF_MOJO_1' for x in old}
expected |= {'lmb_' + x + '_v1@@LIBBPF_MOJO_GENERIC_1' for x in generic}
expected |= {'lmb_events_' + x + '@@LMB_EVENTS_TEST_1' for x in ['reset','scenario','call_count','close_count']}
result = subprocess.run(['nm','-D','--defined-only',sys.argv[1]], capture_output=True, text=True, check=True)
functions, other = set(), set()
for line in result.stdout.splitlines():
    _, kind, name = line.split()
    if kind == 'T':
        functions.add(name)
    elif kind != 'A' or name not in {'LIBBPF_MOJO_1','LIBBPF_MOJO_GENERIC_1','LMB_EVENTS_TEST_1'}:
        other.add((kind,name))
if functions != expected or other:
    sys.exit('events exports BAD: missing=%s extra=%s other=%s' %
             (sorted(expected-functions), sorted(functions-expected), sorted(other)))
print('events %s exports ok: 11 old + %d generic + exactly 4 scalar controls' % (sys.argv[2],len(generic)))
PY
