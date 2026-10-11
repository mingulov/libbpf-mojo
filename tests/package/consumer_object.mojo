# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""A standalone packaged object consumer: open and view, without loading."""
from std.pathlib import Path
from std.sys import argv, exit
from libbpf_mojo.object import Object


def main() raises:
    var args = argv()
    if len(args) != 2:
        exit(2)
    var elf = Path(args[1]).read_bytes()
    try:
        var obj = Object.open(Span(elf))
        var view = obj.program(String("trace_probe"))
        var moved = obj^
        moved.release()
        var info = view.info()
        if info.prog_type != 5 or info.insn_count == 0:
            exit(1)
        view.close()
    except e:
        print("OBJECT-ERROR", e.domain, e.code)
        exit(3)
    print("OBJECT-CONSUMER-OK")
