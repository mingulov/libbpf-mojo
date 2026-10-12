<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Explicit links and ring consumers

Import `Link` and `attach_tracepoint` from `libbpf_mojo.link`, and
`Buffer`, `BufferPollResult` and `open_ring` from `libbpf_mojo.buffer`.
Both owners are movable and cannot be copied. Module imports do not load
a native library. Their native contract is [generic ABI v1](generic-abi-v1.md).

```mojo
def attach_tracepoint(
    mut program: ProgramView, category: String, event: String,
    flags: UInt32 = 0,
) raises LmbError -> Link

def open_ring(
    mut ring: MapView, max_raw_bytes: UInt32 = 4096,
    stage_slots: UInt32 = 1, flags: UInt32 = 0,
) raises LmbError -> Buffer

# Both owners:
def close(mut self) raises LmbError
def is_closed(self) -> Bool

# Buffer:
def poll(
    mut self, dst: Span[mut=True, UInt8, _], timeout_ms: Int32 = 0,
) -> BufferPollResult
```

Open an `Object` from caller-owned ELF bytes, configure it before loading,
then call `load()` explicitly. Create the program/map view from that object
and pass it to the factory. Each factory checks the view's configuration
generation before acquisition, then uses that view's original native library,
object handle and copied name. Loading does not attach. A tracepoint request
requires a tracepoint program and explicit category/event names. Other attach
families need separately specified interfaces. Flags must be zero; a ring
requires a RINGBUF map, maximum 1..4096 and exactly one staging slot.

Each native child retains its parent. The Mojo owner shares the originating
dynamic library until native teardown finishes. Moving or releasing the
parent and closing the original view preserves a surviving child. Explicit
parent close reports BUSY while any child/view remains. The final native
reference destroys the parsed object once. Explicit link close preserves a
signed libbpf teardown error even when that call clears the handle. A destructor
performs best-effort cleanup; use explicit close to observe errors. Repeated
close on the Mojo owner does not destroy a resource twice. Close does not
depend on a generation check. A closed buffer rejects polling before accessing
its retired parent.

`BufferPollResult` is copyable and contains `kind: UInt32`, `used: UInt64`,
`needed: UInt64` and an owned `error: LmbError`. Inspect it with `is_frame()`,
`is_empty()`, `is_short()` and `is_error()`. Poll borrows the mutable destination
for one synchronous call; it never resizes it, retries, or retains its span.
The native reader copies callback data into its owned staging slot.

Each successful poll returns at most one complete frame. A 16-byte payload
requires 24 bytes: capacity 23 reports `is_short()`, `used=0`, `needed=24`,
with the copied BRIDGE/-ENOSPC diagnostic and every destination byte preserved.
Repeated short calls retain that record; capacity 24 delivers it exactly once.
Consumers can assemble a prefix through successive destination spans. Earlier
successful frames survive a later short call. The existing `decode_frame`
accepts a checked u32 frame length (the maximum frame is 4104 bytes) and returns
an owned payload copy. Empty success may include reaching the bounded malformed
skip limit. It does not assert that the ring had no malformed records.

EINTR remains a POSIX error with no automatic retry. A LIBBPF error whose numeric
code equals ENOSPC is an error outcome. Only BUFFER_POLL/BRIDGE/-ENOSPC with a
valid required length is short. Diagnostics are copied immediately on the same
calling thread; inspecting a retained result after another successful operation
preserves its signed code, domain, operation and message.

New symbols remain optional. Link creation preflights attach and link-close;
ring creation preflights open, poll and close. Missing teardown support refuses
before acquisition with ATTACH or BUFFER_OPEN, BRIDGE/-ENOSYS. Existing object
and Session consumers continue to require only their original symbol slices.
No arbitrary Mojo callback crosses the native boundary. One calling thread
owns each handle; broader concurrency remains unqualified.

The standalone runtime tarball includes both modules and this guide. Compile
with the pinned Mojo compiler and `-I <package>/mojo`, then use the bundled
runtime library closure and `LMB_NATIVE_LIB=<package>/lib/libbpf_mojo.so.1`.
The installed-consumer test compiles six Mojo consumers and a C header consumer
outside the source tree, removes source imports, and executes after relocation
with an empty executable search path. `LMB_PACKAGE_CONSUMER_OUT` optionally
retains each attempt's binaries, input identities, argv/environment and logs.

The product-library host cases prove imports, ownership and load-gated refusals.
Separately selected `--host-test` consumers use an explicitly supplied external
test library and fixture (`LMB_PACKAGE_EVENTS_TEST_LIB` and
`LMB_PACKAGE_EVENTS_FIXTURE`). They exercise successful ownership and the actual
pinned reader over controlled mappings. The test library is absent from runtime
packages. These host controls do not qualify successful kernel loading,
attachment, event production, target cleanup, multithreaded/weak-memory behavior
or performance. Live collection retains the library's Linux >=7.0 admission floor.
