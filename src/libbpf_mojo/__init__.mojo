"""Mojo ownership wrappers for the libbpf-mojo native bridge.

The native library owns loading, attaching, and event transport; this
package owns session lifetime, error surfacing, and batch parsing.
"""

from libbpf_mojo._ffi import (
    AttachV1,
    BytesV1,
    ErrorV1,
    MapInfoV1,
    NameV1,
    OptionsV1,
    StatsV1,
)
from libbpf_mojo.batch import Frame, PollResult, decode_frame
from libbpf_mojo.error import LmbError
from libbpf_mojo.session import (
    AttachSpec,
    BridgeStats,
    MapReadResult,
    Session,
)
