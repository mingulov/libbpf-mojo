# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Structured bridge errors.

Every native failure surfaces as an ``LmbError`` carrying the
operation, domain, and code as integers: callers match on fields,
never on message text.
"""

comptime EPERM = Int32(-1)
comptime ENOENT = Int32(-2)
comptime EINTR = Int32(-4)
comptime EBUSY = Int32(-16)
comptime EINVAL = Int32(-22)
comptime ENOSPC = Int32(-28)
comptime ENOSYS = Int32(-38)
comptime EBADMSG = Int32(-74)
comptime EOVERFLOW = Int32(-75)


@fieldwise_init
struct LmbError(Copyable, Writable):
    """One structured bridge failure."""

    var operation: UInt32
    var domain: UInt32
    var code: Int32
    var message: String


def message_from_bytes(raw: List[UInt8]) -> String:
    """Build the detail message from native message bytes.

    Native messages are short ASCII records; undecodable input can
    never fail error reporting, so it degrades to a placeholder.
    """
    try:
        return String(from_utf8=Span(raw))
    except e:
        return String("(undecodable error message)")
