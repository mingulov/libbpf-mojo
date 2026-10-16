# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Installed ring imports/refusals and explicit actual-reader host mode."""
from std.pathlib import Path
from std.sys import argv, exit
from libbpf_mojo.buffer import Buffer, BufferPollResult, open_ring
from libbpf_mojo.object import Object


def from_parent_scope(elf: Span[UInt8, _]) raises -> Buffer:
    var object = Object.open(elf)
    var reset = object._lib[]._handle.get_function[NoneType]("lmb_events_reset")
    reset()
    var scenario = object._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    scenario(UInt32(2))
    object.load()
    var ring = object.map("events")
    return open_ring(ring)


def harness(elf: Span[UInt8, _]) raises:
    var original = from_parent_scope(elf)
    var buffer = original^
    var scenario = buffer._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    var count = buffer._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
    scenario(UInt32(5))
    var output = List[UInt8](length=26, fill=0xa5)
    var zone = Span(output)
    var held = buffer.poll(zone[1:24])
    if not held.is_short() or held.used != 0 or held.needed != 24:
        exit(1)
    if held.error.operation != 13 or held.error.domain != 4 or held.error.code != -28:
        exit(1)
    for byte in output:
        if byte != 0xa5:
            exit(1)
    var frame = buffer.poll(zone[1:25])
    if not frame.is_frame() or frame.used != 24 or frame.needed != 0:
        exit(1)
    var literal = [UInt8(0x10), UInt8(0), UInt8(0), UInt8(0),
                   UInt8(1), UInt8(0), UInt8(0), UInt8(0),
                   UInt8(0x08), UInt8(0x07), UInt8(0x06), UInt8(0x05),
                   UInt8(0x04), UInt8(0x03), UInt8(0x02), UInt8(0x01),
                   UInt8(0xf7), UInt8(0xf8), UInt8(0xf9), UInt8(0xfa),
                   UInt8(0xfb), UInt8(0xfc), UInt8(0xfd), UInt8(0xfe)]
    for i in range(24):
        if output[i + 1] != literal[i]:
            exit(1)
    if output[0] != 0xa5 or output[25] != 0xa5:
        exit(1)
    var empty = buffer.poll(zone)
    if not empty.is_empty() or empty.used != 0 or empty.needed != 0:
        exit(1)
    var counters = buffer.stats()
    if counters.received != 1 or counters.delivered != 1 or counters.staged != 0:
        exit(1)
    if counters.malformed != 0 or counters.dropped != 0:
        exit(1)
    if counters.received != counters.delivered + counters.staged + counters.malformed + counters.dropped:
        exit(1)
    if held.error.operation != 13 or held.error.domain != 4 or held.error.code != -28:
        exit(1)
    if count(UInt32(12)) != 1 or count(UInt32(13)) != 1 or count(UInt32(14)) != 0:
        exit(1)
    buffer.close()
    buffer.close()
    var closed = buffer.poll(zone)
    if not closed.is_error() or closed.error.operation != 13 or closed.error.code != -22:
        exit(1)
    var stats_refused = False
    try:
        _ = buffer.stats()
    except e:
        if e.operation != 20 or e.domain != 4 or e.code != -22:
            exit(1)
        stats_refused = True
    if not stats_refused:
        exit(1)
    if count(UInt32(7)) != 0 or count(UInt32(8)) != 1 or count(UInt32(11)) != 1:
        exit(1)
    scenario(UInt32(10))
    if count(UInt32(21)) != 0 or count(UInt32(22)) != 0 or count(UInt32(19)) != 0:
        exit(1)
    print("BUFFER-HOST-HARNESS-OK")


def main() raises:
    var args = argv()
    if len(args) == 2 and args[1] == "--import-only":
        print("BUFFER-IMPORT-OK")
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
        var original = object.map("events")
        var owner = object^
        var ring = original^
        owner.release()
        for maximum, slots, flags in [(UInt32(4096), UInt32(1), UInt32(0)),
                                      (UInt32(0), UInt32(1), UInt32(0)),
                                      (UInt32(4096), UInt32(2), UInt32(0)),
                                      (UInt32(4096), UInt32(1), UInt32(1))]:
            var refused = False
            try:
                var absent = open_ring(ring, maximum, slots, flags)
                _ = absent^
            except e:
                if e.operation != 12 or e.domain != 4 or e.code != -22:
                    raise e^
                refused = True
            if not refused:
                exit(1)
        ring.close()
        var refused = False
        try:
            var absent = open_ring(ring)
            _ = absent^
        except e:
            if e.operation != 17 or e.domain != 4 or e.code != -22:
                raise e^
            refused = True
        if not refused:
            exit(1)
        owner.close()
    except e:
        print("BUFFER-ERROR", e.domain, e.code)
        exit(3)
    print("BUFFER-CONSUMER-OK")
