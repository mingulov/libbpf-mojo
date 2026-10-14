<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Typed maps and explicit test-run

Import `Object` from `libbpf_mojo.object`, map functions from
`libbpf_mojo.maps`, and `test_run` and `ProgramTestResult` from
`libbpf_mojo.program`. These module functions borrow the existing
move-only `MapView` or `ProgramView`; they do not create another owner.
The [generic ABI](generic-abi-v1.md) specifies the native boundary.

The following calls require an object already loaded in an appropriate
runtime. The names and bytes belong to the consumer's ELF and map ABI:

```mojo
from libbpf_mojo.maps import lookup, update, lookup_u64, update_u64
from libbpf_mojo.program import test_run

var counter = obj.map("counter")
update_u64(counter, UInt32(0), UInt64(41))
var value = lookup_u64(counter, UInt32(0))

var key = List[UInt8](length=4, fill=0)
var bytes = lookup(counter, Span(key))
update(counter, Span(key), Span(bytes), UInt64(0))

var program = obj.program("packet_control")
var packet = List[UInt8](length=64, fill=0)
var context = List[UInt8]()
var packet_out = List[UInt8](length=128, fill=0)
var context_out = List[UInt8]()
var result = test_run(program, Span(packet), Span(context),
                      Span(packet_out), Span(context_out), UInt64(1))
```

This illustrates signatures, not a valid packet/context for every XDP
program or kernel. Supply the native context and packet format required
by the target. Host tests have not qualified successful kernel map
access or XDP execution. A returned XDP action does not prove packet
delivery.

## Maps

`lookup(view, key)` returns an owned `List[UInt8]` containing exactly the
value extent. The key is an immutable byte span and must match `key_size`.
`update(view, key, value, flags=0)` borrows immutable spans and forwards
one native update. Ordinary values match `value_size`. Per-CPU values
contain `stride * num_cpus` bytes, including all slot padding; stride is
rounded up to eight and the count describes possible CPUs, including
offline CPUs. The complete spread must fit u32. Use metadata from
`view.info()` to construct an update. Multiple reads are not an atomic
snapshot. Bloom-filter lookup is refused with
`BRIDGE`/`-EOPNOTSUPP`: a bloom value carries the membership item
inward, so there is no output value to read. Insertion through
`update` keeps working; metadata from `view.info()` is unaffected.

The scalar helpers take an exact `UInt32` key and `UInt64` value. They
require an ordinary map with key size four and value size eight, and
reject per-CPU maps. They encode native-endian bytes without unaligned
integer casts and preserve high bits. Raw byte calls impose no scalar
interpretation on a consumer's schema.

Permitted update flags are exactly 0, 1, 2, 4, 5 and 6 (ANY, NOEXIST,
EXIST and their LOCK combinations). Flags are forwarded unchanged;
LOCK does not promise that a particular map supports a spin lock.
Invalid flags fail before a syscall. A kernel refusal keeps its signed
code and does not trigger a retry.

## Test-run buffers and result

`test_run(view, packet, context, packet_out, context_out, repeat=1)`
borrows immutable packet/context spans and mutable output spans. Each
extent is independently limited to 1,048,576 bytes. Repeat is an exact
`UInt64` in 1..2,147,483,647; flags are zero in this API. The initial
native profile accepts loaded XDP programs only. Other validated program
types fail with `BRIDGE/-EOPNOTSUPP` before execution.

Use distinct empty output lists to request no copy. A zero-length span
forwards a null native pointer regardless of its span pointer. The
copyable result has four independent fields: `retval: UInt32`,
`data_actual: UInt64`, `ctx_actual: UInt64`, and `duration_ns: UInt64`.
For an omitted output, its native actual length can be nonzero and is
not proof that bytes were copied; an omitted context's native actual
can remain zero.

The native adapter snapshots inputs before any caller output commit.
It permits input/output aliases; safe Mojo origins ordinarily reject
simultaneous immutable/mutable borrows of the same storage. An advanced
caller constructing unsafe overlapping spans must keep their backing
storage alive and unmoved throughout the call. The two nonempty outputs
must be disjoint, though adjacent intervals are legal. Ordinary use with
separate input and output lists needs no origin cast.

On native success, each nonempty output receives exactly its reported
actual extent and retains its tail. A reported size beyond a nonempty
capacity fails with `BRIDGE/-EOVERFLOW`. Every failure preserves both
outputs and returns no `ProgramTestResult`. Native errors, including
ENOSPC and EINTR, keep their signed KERNEL code; the adapter makes one
call and never retries. Output preservation cannot undo kernel side
effects.

## Lifetime, errors and installed use

Each typed call checks the view's captured generation before allocating
large buffers or invoking the map/test-run operation. Configuration
invalidates older views (`BRIDGE/-ESTALE`); a closed view reports
`BRIDGE/-EINVAL`. A view retains the native object and dynamic library
after its parent moves, releases, or leaves scope. Explicit parent close
is BUSY while a view exists. Close views when finished; the last reference
destroys native state exactly once. See [ownership](ownership.md).

Failures raise `LmbError` with operation, domain, original signed code
and bounded message, captured immediately from the generic diagnostic
record. A missing new operation reports its own `BRIDGE/-ENOSYS` when
called. Object-only generic libraries and original session libraries
remain usable for their existing operations; new symbols are optional.

The standalone package includes these modules. Compile against only
`<package>/mojo`, then run the binary with `LD_LIBRARY_PATH=<package>/lib`
and `LMB_NATIVE_LIB=<package>/lib/libbpf_mojo.so.1`. Installed host
consumers verify imports, ownership, relocation and rejecting paths
without load; successful package map/test-run execution requires separate
runtime qualification. The scripted test libraries are never shipped.
