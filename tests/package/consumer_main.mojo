"""Packaged-consumer proof for libbpf-mojo.

Build ONLY with `-I <package>/mojo`: it must import
`libbpf_mojo` from the package alone (no sibling source
path), decode one known frame without the native library,
then open the packaged example object through the packaged
bridge, read stats, and close. Unprivileged-safe: open and
stats need no BPF privilege.

Usage: consumer_main <elf-path>; LMB_NATIVE_LIB must point
at the packaged bridge. Exit 0 prints CONSUMER-OK.
"""
from std.pathlib import Path
from std.sys import argv, exit

from libbpf_mojo.batch import decode_frame
from libbpf_mojo.session import Session


def main() raises:
    var args = argv()
    if len(args) != 2:
        print("usage: consumer_main <elf-path>")
        exit(2)
    # One frame: payload-length 1, version 1, reserved 0,
    # payload [0x41].
    var raw = List[UInt8]()
    raw.append(UInt8(1))
    raw.append(UInt8(0))
    raw.append(UInt8(0))
    raw.append(UInt8(0))
    raw.append(UInt8(1))
    raw.append(UInt8(0))
    raw.append(UInt8(0))
    raw.append(UInt8(0))
    raw.append(UInt8(0x41))
    var frame = decode_frame(Span(raw), 0, UInt32(9))
    if frame.version != UInt16(1) or len(frame.payload) != 1:
        print("pure decode mismatch")
        exit(1)
    if frame.payload[0] != UInt8(0x41):
        print("pure payload mismatch")
        exit(1)
    var elf = Path(args[1]).read_bytes()
    var session = Session.open(
        Span(elf), String("events"), UInt32(64)
    )
    var stats = session.stats()
    if stats.received != UInt64(0):
        print("fresh session not quiescent")
        exit(1)
    if stats.last_error != Int32(0):
        print("fresh session carries an error")
        exit(1)
    print("CONSUMER-OK")
