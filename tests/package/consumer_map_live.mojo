# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Installed typed map workflow; only the controller decides live acceptance."""
from std.ffi import external_call
from std.os import getenv, listdir
from std.pathlib import Path
from std.sys import argv, exit
from libbpf_mojo.object import Object, ObjectOptions, MapView
from libbpf_mojo.maps import delete, first_key, next_key, lookup_u64, update_u64
from libbpf_mojo.program import test_run


@fieldwise_init
struct Timespec(Copyable):
    var seconds: Int64
    var nanoseconds: Int64


def now_ns() raises -> Int64:
    var value = Timespec(0, 0)
    if external_call["clock_gettime", Int32](Int32(1), Pointer(to=value)) != 0:
        raise Error("monotonic clock failed")
    return value.seconds * 1000000000 + value.nanoseconds


def c_string(text: String) -> List[UInt8]:
    var result = List[UInt8]()
    for byte in text.as_bytes():
        result.append(byte)
    result.append(0)
    return result^


def publish_bytes(directory: String, name: String, bytes: Span[mut=False, UInt8, _]) raises:
    var tmp = c_string(directory + "/" + name + ".tmp")
    var final = c_string(directory + "/" + name)
    # Owned output leaf, exclusive temporary creation, atomic publication.
    var fd = external_call["open", Int32](Span(tmp).unsafe_ptr(), Int32(193), Int32(0o600))
    if fd < 0:
        raise Error("exclusive output open failed")
    var count = external_call["write", Int64](fd, bytes.unsafe_ptr(), UInt64(len(bytes)))
    var synced = external_call["fsync", Int32](fd)
    var closed = external_call["close", Int32](fd)
    if count != Int64(len(bytes)) or synced != 0 or closed != 0:
        raise Error("output write failed")
    if external_call["rename", Int32](Span(tmp).unsafe_ptr(), Span(final).unsafe_ptr()) != 0:
        raise Error("output publication failed")


def publish(directory: String, name: String, text: String) raises:
    publish_bytes(directory, name, text.as_bytes())


def barrier(directory: String, phase: String, text: String, deadline: Int64) raises:
    publish(directory, phase + ".json", text)
    var limit = min(now_ns() + 15000000000, deadline)
    var name = directory + "/" + phase + ".ack"
    var native = c_string(name)
    while now_ns() < limit:
        if external_call["access", Int32](Span(native).unsafe_ptr(), Int32(0)) == 0:
            var bytes = Path(name).read_bytes()
            var expected = String("continue\n").as_bytes()
            if len(bytes) != len(expected):
                raise Error("controller requested cleanup")
            for i in range(len(expected)):
                if bytes[i] != expected[i]:
                    raise Error("controller requested cleanup")
            return
        _ = external_call["usleep", Int32](UInt32(5000))
    raise Error("phase/external deadline expired")


def key_bytes(value: UInt32) -> List[UInt8]:
    var result = List[UInt8](length=4, fill=0)
    var pointer = Pointer(to=value).unsafe_bitcast[UInt8]()
    for i in range(4):
        result[i] = pointer.unsafe_offset(i).unsafe_load()
    return result^


def hex_key(bytes: List[UInt8]) raises -> String:
    if len(bytes) != 4:
        raise Error("key extent")
    var digits = String("0123456789abcdef")
    var result = String()
    for byte in bytes:
        result += digits[byte=Int(byte >> 4)]
        result += digits[byte=Int(byte & 15)]
    return result^


def optional_key(var value: Optional[List[UInt8]]) raises -> String:
    if not value:
        return "null"
    var bytes = value.take()
    return '"' + hex_key(bytes) + '"'


def walk(mut view: MapView) raises -> Tuple[String, Int]:
    var current = first_key(view)
    var calls = 1
    var output = String()
    while current:
        if calls >= 4:
            raise Error("bounded iteration exceeded")
        var bytes = current.take()
        if output.byte_length() != 0:
            output += ","
        output += '"' + hex_key(bytes) + '"'
        current = next_key(view, Span(bytes))
        calls += 1
    return (output^, calls)


def missing_delete(mut view: MapView, bytes: List[UInt8]) raises -> String:
    try:
        delete(view, Span(bytes), UInt64(0))
    except e:
        return '{"operation":' + String(e.operation) + ',"domain":' + String(e.domain) + ',"code":' + String(e.code) + '}'
    raise Error("missing key deletion unexpectedly succeeded")


def missing_lookup(mut view: MapView) raises -> String:
    try:
        _ = lookup_u64(view, UInt32(7))
    except e:
        return '{"operation":' + String(e.operation) + ',"domain":' + String(e.domain) + ',"code":' + String(e.code) + '}'
    raise Error("missing key lookup unexpectedly succeeded")


def array_refusal(mut view: MapView, bytes: List[UInt8]) raises -> Int32:
    try:
        delete(view, Span(bytes), UInt64(0))
    except e:
        if e.operation != 18 or e.domain != 3 or e.code >= 0:
            raise e^
        return e.code
    raise Error("ARRAY deletion unexpectedly succeeded")


def workflow(object_path: String, directory: String, deadline: Int64) raises:
    var elf = Path(object_path).read_bytes()
    var owner = Object.open(Span(elf), ObjectOptions(log_level=UInt32(2), log_capacity=UInt64(1048576)))
    var program = owner.program("lmb_map_live")
    try:
        owner.load()
    except e:
        var metadata = program.info(1048576)
        publish_bytes(directory, "verifier-log.bin", Span(metadata.log))
        publish(directory, "verifier-log-info.txt", '{"actual":' + String(metadata.log_actual) + ',"truncated":' + String(metadata.log_truncated) + '}')
        raise e^
    var counter = owner.map("counter")
    var values = owner.map("values")
    var metadata = program.info(1048576)
    publish_bytes(directory, "verifier-log.bin", Span(metadata.log))
    publish(directory, "verifier-log-info.txt", '{"actual":' + String(metadata.log_actual) + ',"truncated":' + String(metadata.log_truncated) + '}')
    if metadata.log_truncated:
        raise Error("verifier log exceeded retained capacity")
    barrier(directory, "loaded", "{}", deadline)
    update_u64(counter, UInt32(0), UInt64(41))
    var initial = lookup_u64(counter, UInt32(0))
    barrier(directory, "initialized", '{"counter":' + String(initial) + '}', deadline)
    var packet = List[UInt8](length=60, fill=0)
    packet[12] = 8
    packet[14] = 0x45
    packet[17] = 46
    var output = List[UInt8](length=60, fill=0)
    var context = List[UInt8]()
    var context_out = List[UInt8]()
    var result = test_run(program, Span(packet), Span(context), Span(output), Span(context_out), UInt64(1))
    var actual = lookup_u64(counter, UInt32(0))
    barrier(directory, "executed", '{"counter":' + String(actual) + ',"retval":' + String(result.retval) + ',"data_actual":' + String(result.data_actual) + ',"ctx_actual":' + String(result.ctx_actual) + ',"duration_ns":' + String(result.duration_ns) + '}', deadline)
    if actual != 42:
        raise Error("executed counter differs from 42")
    var empty = optional_key(first_key(values))
    update_u64(values, UInt32(0), UInt64(0x0123456789abcdef))
    var zero_first = optional_key(first_key(values))
    var zero = key_bytes(UInt32(0))
    var zero_next = optional_key(next_key(values, Span(zero)))
    update_u64(values, UInt32(7), UInt64(0xfedcba9876543210))
    update_u64(values, UInt32(0xffffffff), UInt64(0x1122334455667788))
    var seeded, calls = walk(values)
    var first = optional_key(first_key(values))
    var absent = key_bytes(UInt32(99))
    var restart = optional_key(next_key(values, Span(absent)))
    # None has already passed the public wrapper's exact terminal predicate.
    barrier(directory, "keys-seeded", '{"empty_first":' + empty + ',"zero_first":' + zero_first + ',"zero_next":' + zero_next + ',"seeded":[' + seeded + '],"calls":' + String(calls) + ',"terminal":{"kind":"typed_none"},"first":' + first + ',"restart":' + restart + '}', deadline)
    var seven = key_bytes(UInt32(7))
    delete(values, Span(seven), UInt64(0))
    var remaining, after_calls = walk(values)
    var missing_del = missing_delete(values, seven)
    var missing_read = missing_lookup(values)
    barrier(directory, "key-deleted", '{"after_delete":[' + remaining + '],"after_calls":' + String(after_calls) + ',"after_terminal":{"kind":"typed_none"},"missing_delete":' + missing_del + ',"missing_lookup":' + missing_read + '}', deadline)
    delete(values, Span(zero), UInt64(0))
    var high = key_bytes(UInt32(0xffffffff))
    delete(values, Span(high), UInt64(0))
    var empty_final = optional_key(first_key(values))
    var array_first = optional_key(first_key(counter))
    var array_next = optional_key(next_key(counter, Span(zero)))
    var array_restart = optional_key(next_key(counter, Span(absent)))
    var array_delete = array_refusal(counter, zero)
    barrier(directory, "keys-empty", '{"empty_final":' + empty_final + ',"array_first":' + array_first + ',"array_next":' + array_next + ',"array_restart":' + array_restart + ',"array_delete":' + String(array_delete) + '}', deadline)
    owner.release()
    var retained = lookup_u64(counter, UInt32(0))
    var retained_first = optional_key(first_key(values))
    barrier(directory, "owner-released", '{"counter":' + String(retained) + ',"first":' + retained_first + '}', deadline)
    program.close()
    counter.close()
    values.close()
    owner.close()
    publish(directory, "closed.json", "{}")


def main() raises:
    var args = argv()
    if len(args) != 4:
        exit(2)
    # The controller supplies canonical owned paths and a shared absolute clock.
    if args[3] != args[2] + "/result.json" or args[2].byte_length() == 0:
        exit(2)
    if not Path(args[2]).exists() or len(listdir(args[2])) != 0:
        exit(2)
    var deadline = Int64(Int(getenv("LMB_LIVE_DEADLINE_MONOTONIC_NS")))
    if deadline <= now_ns():
        exit(2)
    try:
        workflow(args[1], args[2], deadline)
    except e:
        publish(args[2], "result.json", '{"status":"failed"}')
        print("map live failure:", e)
        exit(3)
    publish(args[2], "result.json", '{"status":"closed"}')
