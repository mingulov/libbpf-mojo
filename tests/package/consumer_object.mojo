# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""A standalone packaged object consumer: open and view, without loading."""
from std.os import getenv
from std.pathlib import Path
from std.sys import argv, exit
from libbpf_mojo.object import Object


def packaged_lib() raises -> String:
    # The harness sets LMB_NATIVE_LIB to the packaged bridge;
    # the consumer resolves it explicitly instead of relying
    # on environment lookup.
    return getenv("LMB_NATIVE_LIB")


def main() raises:
    var args = argv()
    if len(args) != 2:
        exit(2)
    var elf = Path(args[1]).read_bytes()
    var lib_path = packaged_lib()
    try:
        var obj = Object.open_with_lib(Span(elf), lib_path)
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
