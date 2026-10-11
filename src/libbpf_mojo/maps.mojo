# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Checked byte and native-endian scalar map calls over retained views."""
from std.sys import size_of
from libbpf_mojo._ffi import (
    GENERIC_DOMAIN_BRIDGE, GENERIC_OP_MAP_LOOKUP, GENERIC_OP_MAP_UPDATE,
    GENERIC_OP_VIEW_CHECK, MapInfoV1,
)
from libbpf_mojo.error import EINVAL, EOVERFLOW, LmbError
from libbpf_mojo.object import MapView, _query_name, capture_generic_error


def _percpu(kind: UInt32) -> Bool:
    return kind == 5 or kind == 6 or kind == 10 or kind == 21


def _extent(info: MapInfoV1) raises LmbError -> Int:
    var bytes = UInt64(info.value_size)
    if _percpu(info.map_type):
        if info.num_cpus == 0 or info.stride < info.value_size or info.stride % 8 != 0:
            raise LmbError(GENERIC_OP_MAP_LOOKUP, GENERIC_DOMAIN_BRIDGE,
                           EINVAL, "invalid per-CPU map geometry")
        bytes = UInt64(info.stride) * UInt64(info.num_cpus)
    # The native spread is bounded to u32; this also fits LP64 List indices.
    if bytes > 0xffffffff:
        raise LmbError(GENERIC_OP_MAP_LOOKUP, GENERIC_DOMAIN_BRIDGE,
                       EOVERFLOW, "map extent exceeds the native bound")
    return Int(bytes)


def _lookup(
    mut view: MapView, key: Span[mut=False, UInt8, _], info: MapInfoV1
) raises LmbError -> List[UInt8]:
    var extent = _extent(info)
    if UInt64(len(key)) != UInt64(info.key_size):
        raise LmbError(GENERIC_OP_MAP_LOOKUP, GENERIC_DOMAIN_BRIDGE,
                       EINVAL, "map key has the wrong extent")
    var result = List[UInt8](length=extent, fill=0)
    var destination = Span(result)
    var query = _query_name(view._name, GENERIC_OP_MAP_LOOKUP)
    var needed = UInt64(0)
    var rc = view._lib[].object_map_lookup(
        view._handle, Pointer(to=query), key.unsafe_ptr(), UInt64(len(key)),
        destination.unsafe_ptr(), UInt64(extent), Pointer(to=needed),
    )
    if rc != 0:
        raise capture_generic_error(view._lib[], GENERIC_OP_MAP_LOOKUP, rc)
    return result^


def lookup(mut view: MapView, key: Span[mut=False, UInt8, _]) raises LmbError -> List[UInt8]:
    """Return every value/per-CPU byte, including padding, in one owned list."""
    var info = view.info()
    return _lookup(view, key, info)


def update(
    mut view: MapView, key: Span[mut=False, UInt8, _], value: Span[mut=False, UInt8, _], flags: UInt64 = 0
) raises LmbError:
    """Update once with exact byte extents and the unchanged native flags."""
    var rc = view._lib[].object_generation_check(view._handle, view._generation)
    if rc != 0:
        raise capture_generic_error(view._lib[], GENERIC_OP_VIEW_CHECK, rc)
    var query = _query_name(view._name, GENERIC_OP_MAP_UPDATE)
    rc = view._lib[].object_map_update(
        view._handle, Pointer(to=query), key.unsafe_ptr(), UInt64(len(key)),
        value.unsafe_ptr(), UInt64(len(value)), flags,
    )
    if rc != 0:
        raise capture_generic_error(view._lib[], GENERIC_OP_MAP_UPDATE, rc)


def _scalar_geometry(info: MapInfoV1, operation: UInt32) raises LmbError:
    if info.key_size != 4 or info.value_size != 8 or info.stride != 0 or _percpu(info.map_type):
        raise LmbError(operation, GENERIC_DOMAIN_BRIDGE, EINVAL,
                       "u64 helpers require an ordinary u32-key/u64-value map")


def _native_bytes[T: AnyType](value: T) -> List[UInt8]:
    var bytes = List[UInt8](length=size_of[T](), fill=0)
    var pointer = Pointer(to=value).unsafe_bitcast[UInt8]()
    for i in range(size_of[T]()):
        bytes[i] = pointer.unsafe_offset(i).unsafe_load()
    return bytes^


def lookup_u64(mut view: MapView, key: UInt32) raises LmbError -> UInt64:
    """Read an ordinary u64 value without narrowing or unaligned casts."""
    var info = view.info()
    _scalar_geometry(info, GENERIC_OP_MAP_LOOKUP)
    var key_bytes = _native_bytes(key)
    var bytes = _lookup(view, Span(key_bytes), info)
    var value = UInt64(0)
    var pointer = Pointer(to=value).unsafe_bitcast[UInt8]()
    for i in range(8):
        pointer.unsafe_offset(i).unsafe_store(bytes[i])
    return value


def update_u64(
    mut view: MapView, key: UInt32, value: UInt64, flags: UInt64 = 0
) raises LmbError:
    """Write a full native-endian u64; per-CPU maps require raw byte calls."""
    var info = view.info()
    _scalar_geometry(info, GENERIC_OP_MAP_UPDATE)
    var key_bytes = _native_bytes(key)
    var value_bytes = _native_bytes(value)
    update(view, Span(key_bytes), Span(value_bytes), flags)
