# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Checked byte and native-endian scalar map calls over retained views."""
from std.sys import size_of
from libbpf_mojo._ffi import (
    GENERIC_DOMAIN_BRIDGE, GENERIC_OP_MAP_LOOKUP, GENERIC_OP_MAP_UPDATE,
    GENERIC_OP_VIEW_CHECK, GENERIC_OP_MAP_DELETE, GENERIC_OP_MAP_NEXT_KEY,
    GENERIC_DOMAIN_KERNEL, MapInfoV1,
)
from libbpf_mojo.error import EINVAL, ENOENT, EOVERFLOW, LmbError
from libbpf_mojo.object import MapView, _query_name, capture_generic_error


comptime MAP_TYPE_PERCPU_HASH = UInt32(5)
comptime MAP_TYPE_PERCPU_ARRAY = UInt32(6)
comptime MAP_TYPE_LRU_PERCPU_HASH = UInt32(10)
comptime MAP_TYPE_PERCPU_CGROUP_STORAGE = UInt32(21)


def _percpu(kind: UInt32) -> Bool:
    return (
        kind == MAP_TYPE_PERCPU_HASH
        or kind == MAP_TYPE_PERCPU_ARRAY
        or kind == MAP_TYPE_LRU_PERCPU_HASH
        or kind == MAP_TYPE_PERCPU_CGROUP_STORAGE
    )


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


def _key_error(mut view: MapView, operation: UInt32, rc: Int32) -> LmbError:
    var error = capture_generic_error(view._lib[], operation, rc)
    if error.operation != operation or error.code != rc:
        return LmbError(operation, GENERIC_DOMAIN_BRIDGE, rc,
                        "map key diagnostic does not match the native result")
    return error^


def delete(
    mut view: MapView, key: Span[mut=False, UInt8, _], flags: UInt64 = 0
) raises LmbError:
    """Delete once with exact flags; an absent key raises the native error."""
    var rc = view._lib[].object_generation_check(view._handle, view._generation)
    if rc != 0:
        raise capture_generic_error(view._lib[], GENERIC_OP_VIEW_CHECK, rc)
    var query = _query_name(view._name, GENERIC_OP_MAP_DELETE)
    rc = view._lib[].object_map_delete(
        view._handle, Pointer(to=query), key.unsafe_ptr(), UInt64(len(key)), flags,
    )
    if rc != 0:
        raise _key_error(view, GENERIC_OP_MAP_DELETE, rc)


def _key(
    mut view: MapView, has_current: UInt32,
    current: ImmPointer[UInt8, _], current_bytes: UInt64,
) raises LmbError -> Optional[List[UInt8]]:
    var info = view.info()
    if info.key_size == 0:
        raise LmbError(GENERIC_OP_MAP_NEXT_KEY, GENERIC_DOMAIN_BRIDGE,
                       Int32(-95), "map has no key")
    if has_current == 1 and current_bytes != UInt64(info.key_size):
        raise LmbError(GENERIC_OP_MAP_NEXT_KEY, GENERIC_DOMAIN_BRIDGE,
                       EINVAL, "current key has the wrong extent")
    var result = List[UInt8](length=Int(info.key_size), fill=0)
    var destination = Span(result)
    var query = _query_name(view._name, GENERIC_OP_MAP_NEXT_KEY)
    var needed = UInt64(0)
    var rc = view._lib[].object_map_next_key(
        view._handle, Pointer(to=query), has_current, current, current_bytes,
        destination.unsafe_ptr(), UInt64(info.key_size), Pointer(to=needed),
    )
    if rc != 0:
        var error = _key_error(view, GENERIC_OP_MAP_NEXT_KEY, rc)
        if rc == ENOENT and error.operation == GENERIC_OP_MAP_NEXT_KEY and error.domain == GENERIC_DOMAIN_KERNEL and error.code == ENOENT:
            return None
        raise error^
    if needed != UInt64(info.key_size):
        raise LmbError(GENERIC_OP_MAP_NEXT_KEY, GENERIC_DOMAIN_BRIDGE,
                       EINVAL, "native key result has the wrong extent")
    return result^


def first_key(mut view: MapView) raises LmbError -> Optional[List[UInt8]]:
    """Return an owned first key, or None only for native terminal ENOENT."""
    var dummy = UInt8(0)
    return _key(view, UInt32(0), Pointer(to=dummy), UInt64(0))


def next_key(
    mut view: MapView, current: Span[mut=False, UInt8, _]
) raises LmbError -> Optional[List[UInt8]]:
    """Return one owned next key without retries or snapshot guarantees."""
    return _key(view, UInt32(1), current.unsafe_ptr(), UInt64(len(current)))
