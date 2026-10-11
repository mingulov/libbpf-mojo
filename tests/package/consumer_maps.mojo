# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Installed typed map imports, ownership and host rejection paths."""
from std.pathlib import Path
from std.sys import argv, exit
from libbpf_mojo.maps import lookup, update, lookup_u64, update_u64
from libbpf_mojo.object import Object


def main() raises:
    var args = argv()
    if len(args) != 2:
        exit(2)
    var elf = Path(args[1]).read_bytes()
    try:
        var obj = Object.open(Span(elf))
        var view = obj.map("events")
        var owner = obj^
        var moved = view^
        owner.release()
        var key = List[UInt8](length=4, fill=0)
        var value = List[UInt8](length=8, fill=0)
        for operation in [UInt32(7), UInt32(8), UInt32(70), UInt32(80)]:
            var refused = False
            try:
                if operation == 7:
                    var bytes = lookup(moved, Span(key))
                    _ = bytes^
                elif operation == 8:
                    update(moved, Span(key), Span(value))
                elif operation == 70:
                    _ = lookup_u64(moved, UInt32(0))
                else:
                    update_u64(moved, UInt32(0), UInt64(0xffffffffffffffff))
            except e:
                var expected = UInt32(5)
                if operation == 8:
                    expected = 8
                if e.domain != 4 or e.code != -22 or e.operation != expected:
                    raise e^
                refused = True
            if not refused:
                exit(1)
        moved.close()
        moved.close()
        var refused = False
        try:
            update(moved, Span(key), Span(value))
        except e:
            if e.operation != 17 or e.domain != 4 or e.code != -22:
                raise e^
            refused = True
        if not refused:
            exit(1)
        owner.close()
    except e:
        print("MAPS-ERROR", e.domain, e.code)
        exit(3)
    print("MAPS-CONSUMER-OK")
