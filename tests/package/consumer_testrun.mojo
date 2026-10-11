# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Installed typed test-run imports and retained-view rejection paths."""
from std.pathlib import Path
from std.sys import argv, exit
from libbpf_mojo._ffi import AUTOLOAD_DISABLE
from libbpf_mojo.object import Object
from libbpf_mojo.program import ProgramTestResult, test_run


def main() raises:
    var args = argv()
    if len(args) != 2:
        exit(2)
    var elf = Path(args[1]).read_bytes()
    try:
        var obj = Object.open(Span(elf))
        var stale = obj.program("trace_probe")
        obj.configure_program("trace_probe", AUTOLOAD_DISABLE)
        var input = List[UInt8]()
        var packet_out = List[UInt8](length=9, fill=0xa5)
        var context_out = List[UInt8](length=7, fill=0xa5)
        var refused = False
        try:
            var result = test_run(stale, Span(input), Span(input), Span(packet_out), Span(context_out))
            _ = result
        except e:
            if e.operation != 17 or e.domain != 4 or e.code != -116:
                raise e^
            refused = True
        if not refused:
            exit(1)
        stale.close()
        var view = obj.program("trace_probe")
        var owner = obj^
        var moved = view^
        refused = False
        try:
            owner.close()
        except e:
            if e.domain != 4 or e.code != -16:
                raise e^
            refused = True
        if not refused:
            exit(1)
        owner.release()
        for closed in [False, True]:
            if closed:
                moved.close()
            refused = False
            try:
                var result = test_run(moved, Span(input), Span(input), Span(packet_out), Span(context_out))
                _ = result
            except e:
                var expected = UInt32(9)
                if closed:
                    expected = 17
                if e.operation != expected or e.domain != 4 or e.code != -22:
                    raise e^
                refused = True
            if not refused:
                exit(1)
            for i in range(len(packet_out)):
                if packet_out[i] != 0xa5:
                    exit(1)
            for i in range(len(context_out)):
                if context_out[i] != 0xa5:
                    exit(1)
        moved.close()
        owner.close()
    except e:
        print("TESTRUN-ERROR", e.domain, e.code)
        exit(3)
    print("TESTRUN-CONSUMER-OK")
