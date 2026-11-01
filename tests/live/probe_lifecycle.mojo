# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Live probe pair with independently triggered syscall and map counters."""
from std.ffi import external_call
from std.pathlib import Path
from std.sys import argv
from std.testing import assert_equal
from libbpf_mojo.object import Object
from libbpf_mojo.link import attach_kprobe, attach_kretprobe
from libbpf_mojo.maps import update_u64, lookup_u64


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: probe_lifecycle <object> <bridge>")
    var bytes = Path(args[1]).read_bytes()
    var object = Object.open_with_lib(Span(bytes), args[2])
    object.load()
    var counts = object.map("counts")
    var pid = external_call["getpid", Int32]()
    var tid = external_call["syscall", Int64](Int64(186))
    var entry_program = object.program("probe_entry")
    var exit_program = object.program("probe_return")
    var exit_link = attach_kretprobe(exit_program, "__x64_sys_getpid")
    var entry_link = attach_kprobe(entry_program, "__x64_sys_getpid")
    update_u64(counts, UInt32(3), UInt64(tid))
    for _ in range(257):
        assert_equal(external_call["syscall", Int64](Int64(39)), Int64(pid))
    update_u64(counts, UInt32(3), UInt64(0))
    entry_link.close()
    exit_link.close()
    assert_equal(lookup_u64(counts, UInt32(0)), UInt64(257))
    assert_equal(lookup_u64(counts, UInt32(1)), UInt64(257))
    counts.close()
    entry_program.close()
    exit_program.close()
    object.close()
    print("PROBE-LIVE-OK entry=257 return=257")
