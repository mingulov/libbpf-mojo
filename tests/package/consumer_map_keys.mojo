# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Installed key imports and retained ownership with host load-gated refusals."""
from std.pathlib import Path
from std.sys import argv, exit
from libbpf_mojo.maps import delete, first_key, next_key
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
        for operation in [UInt32(18), UInt32(19), UInt32(190)]:
            var refused = False
            try:
                if operation == 18:
                    delete(moved, Span(key))
                elif operation == 19:
                    var unexpected = first_key(moved)
                    _ = unexpected^
                else:
                    var unexpected = next_key(moved, Span(key))
                    _ = unexpected^
            except e:
                var expected = UInt32(18) if operation == 18 else UInt32(5)
                if e.domain != 4 or e.code != -22 or e.operation != expected:
                    raise e^
                refused = True
            if not refused:
                exit(1)
        moved.close()
        moved.close()
        for operation in [UInt32(18), UInt32(19)]:
            var refused = False
            try:
                if operation == 18:
                    delete(moved, Span(key))
                else:
                    var unexpected = first_key(moved)
                    _ = unexpected^
            except e:
                if e.operation != 17 or e.domain != 4 or e.code != -22:
                    raise e^
                refused = True
            if not refused:
                exit(1)
        owner.close()
    except e:
        print("MAP_KEYS-ERROR", e.domain, e.code)
        exit(3)
    print("MAP_KEYS-CONSUMER-OK")
