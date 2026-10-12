# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Installed link ownership/refusals; explicit external host-harness mode."""
from std.pathlib import Path
from std.sys import argv, exit
from libbpf_mojo.link import Link, attach_tracepoint
from libbpf_mojo.object import Object


def from_parent_scope(elf: Span[UInt8, _]) raises -> Link:
    var object = Object.open(elf)
    var reset = object._lib[]._handle.get_function[NoneType]("lmb_events_reset")
    reset()
    object.load()
    var program = object.program("on_getpid")
    return attach_tracepoint(program, "syscalls", "sys_enter_getpid")


def harness(elf: Span[UInt8, _]) raises:
    var original = from_parent_scope(elf)
    var link = original^
    var count = link._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
    if count(UInt32(1)) != 1 or count(UInt32(8)) != 0:
        exit(1)
    link.close()
    link.close()
    if not link.is_closed() or count(UInt32(2)) != 1 or count(UInt32(8)) != 1 or count(UInt32(19)) != 0:
        exit(1)
    print("LINK-HOST-HARNESS-OK")


def main() raises:
    var args = argv()
    if len(args) == 2 and args[1] == "--import-only":
        print("LINK-IMPORT-OK")
        return
    if len(args) != 2 and len(args) != 3:
        exit(2)
    var elf = Path(args[1]).read_bytes()
    if len(args) == 3:
        if args[2] != "--host-test":
            exit(2)
        harness(Span(elf))
        return
    try:
        var object = Object.open(Span(elf))
        var original = object.program("trace_probe")
        var owner = object^
        var program = original^
        owner.release()
        for flags in [UInt32(0), UInt32(1)]:
            var refused = False
            try:
                var absent = attach_tracepoint(program, "syscalls", "sys_enter_getpid", flags)
                _ = absent^
            except e:
                if e.operation != 10 or e.domain != 4 or e.code != -22:
                    raise e^
                refused = True
            if not refused:
                exit(1)
        program.close()
        var refused = False
        try:
            var absent = attach_tracepoint(program, "syscalls", "sys_enter_getpid")
            _ = absent^
        except e:
            if e.operation != 17 or e.domain != 4 or e.code != -22:
                raise e^
            refused = True
        if not refused:
            exit(1)
        owner.close()
    except e:
        print("LINK-ERROR", e.domain, e.code)
        exit(3)
    print("LINK-CONSUMER-OK")
