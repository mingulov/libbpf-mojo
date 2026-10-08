# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Shared helpers for the live (privileged) suites. Standard library only."""

import ctypes
import json
import os
import shutil
import subprocess
import sys
import time

LIVE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(LIVE_DIR))
BUILD_DIR = os.environ.get("LMB_BUILD_DIR", "build")
EXAMPLES = os.path.join(ROOT, BUILD_DIR, "examples")
NATIVE_LIB = os.path.join(ROOT, BUILD_DIR, "libbpf_mojo.so.1")

SKIP = 77


class Skip(Exception):
    """Explicit skip: the environment cannot run this row."""


class Fail(Exception):
    """Test failure with a plain message."""


def need_file(path):
    if not os.path.isfile(path):
        raise Fail("missing build artifact: %s (run tools/build first)"
                   % path)
    return path


def wait_file(path, timeout_s):
    deadline = time.monotonic() + timeout_s
    while not os.path.exists(path):
        if time.monotonic() >= deadline:
            raise Fail("timed out waiting for %s" % path)
        time.sleep(0.005)


def publish(path, content):
    """Atomically publish small file content (tmp file plus rename),
    so a polling reader never observes a partial write."""
    tmp = "%s.tmp-%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.rename(tmp, path)


def wait_content(path, want, timeout_s, label):
    """Wait until path holds exactly want (a set of recognized
    complete outcomes); partial writes keep waiting."""
    if isinstance(want, str):
        want = {want}
    deadline = time.monotonic() + timeout_s
    seen = None
    while True:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                seen = handle.read()
        except OSError:
            seen = None
        if seen in want:
            return seen
        if time.monotonic() >= deadline:
            raise Fail("%s: no recognized outcome (last: %r)"
                       % (label, seen))
        time.sleep(0.005)


def reap(proc):
    """Best-effort child teardown: terminate, wait, close pipes."""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def fd_count(pid):
    try:
        return len(os.listdir("/proc/%d/fd" % pid))
    except FileNotFoundError:
        raise Fail("process %d already gone during fd sampling" % pid)


def ns_identity():
    st = os.stat("/proc/self/ns/pid")
    return st.st_dev, st.st_ino


def has_privilege():
    """Independent BPF probe: can this process create a map?"""
    SYS_bpf = 321
    BPF_MAP_CREATE = 0
    BPF_MAP_TYPE_HASH = 1
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    attr = (ctypes.c_uint8 * 64)()
    ctypes.c_uint32.from_buffer(attr, 0).value = BPF_MAP_TYPE_HASH
    ctypes.c_uint32.from_buffer(attr, 4).value = 4
    ctypes.c_uint32.from_buffer(attr, 8).value = 8
    ctypes.c_uint32.from_buffer(attr, 12).value = 2
    fd = libc.syscall(SYS_bpf, BPF_MAP_CREATE, attr, 64)
    if fd >= 0:
        os.close(fd)
        return True
    err = ctypes.get_errno()
    if err in (1, 13):  # EPERM, EACCES
        return False
    raise Fail("privilege probe failed: errno %d" % err)


def require_privilege():
    if not has_privilege():
        raise Skip("no BPF privilege (independent map-create probe)")


# Objects owned by the example probe. The leftover check scopes
# to these names: a global id-set diff false-positives on shared
# machines where foreign BPF objects come and go during a run
# (observed once: three foreign maps alive only inside our window).
OUR_NAMES = frozenset(("trace_probe", "events", "filter", "count"))


def bpftool_rows(kind):
    exe = shutil.which("bpftool")
    if exe is None:
        raise Skip("bpftool not on PATH; cannot verify no-leftover")
    out = subprocess.run([exe, "-j", kind, "show"],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    if out.returncode != 0:
        raise Fail("bpftool %s show failed: %s" % (kind, out.stderr.strip()))
    try:
        rows = json.loads(out.stdout or "[]")
    except ValueError:
        raise Fail("bpftool %s show is not JSON" % kind)
    return rows


def snapshot():
    """Owned-name (kind, id) pairs currently alive in the kernel."""
    progs = bpftool_rows("prog")
    maps = bpftool_rows("map")
    links = bpftool_rows("link")
    ours = set()
    prog_ids = set()
    for row in progs:
        if (isinstance(row, dict) and row.get("name") in OUR_NAMES
                and "id" in row):
            ours.add(("prog", int(row["id"])))
            prog_ids.add(int(row["id"]))
    for row in maps:
        if (isinstance(row, dict) and row.get("name") in OUR_NAMES
                and "id" in row):
            ours.add(("map", int(row["id"])))
    for row in links:
        # Links carry no name; scope by attachment to our program.
        if (isinstance(row, dict) and "id" in row
                and int(row.get("prog_id", -1)) in prog_ids):
            ours.add(("link", int(row["id"])))
    return ours


def assert_no_leftover(before, label, settle_s=10.0):
    """No owned-name objects may survive the run.

    Kernel-side teardown is not always synchronous with the last
    close: occasionally our maps are still listed ~100ms after the
    owner exited (and vanish on their own). A single-shot assert
    therefore false-positives. Poll briefly instead: anything still
    alive after settle_s is a real leak.
    """
    deadline = time.monotonic() + settle_s
    leaked = []
    while True:
        leaked = sorted(snapshot() - before)
        if not leaked or time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    if leaked:
        raise Fail("%s leaked BPF objects: %r" % (label, leaked))


def parse_record(path):
    record = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            if "=" not in line:
                raise Fail("malformed record line in %s: %r" % (path, line))
            key, value = line.split("=", 1)
            record[key] = value
    return record


def run_main(main):
    try:
        main()
    except Skip as exc:
        print("SKIP: %s" % exc)
        return SKIP
    except Fail as exc:
        print("FAIL: %s" % exc)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit("liveutil is a helper module, not a suite")
