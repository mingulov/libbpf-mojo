#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged probes for test_cleanup.wait_writer_closed.

The writer-close wait must key on file identity, not pathname
spelling: a status file reached through a symlinked directory
(a symlinked TMPDIR) exposes only the resolved /proc fd target,
which never equals the unresolved spelling. Standard library
only; exit 0 on pass, 1 on failure.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "..", "live"))
import test_cleanup  # noqa: E402


def hold_then_close(path, hold_seconds):
    """Child holding path open, then closing but lingering.

    Lingering (not exiting) matters: an exited child is a
    zombie whose fd directory denies listing, which the wait
    reports as a gone process (False), not a closed writer.
    """
    return subprocess.Popen(
        [sys.executable, "-c",
         "import sys, time; handle = open(sys.argv[1]); "
         "time.sleep(float(sys.argv[2])); handle.close(); "
         "time.sleep(30)",
         path, str(hold_seconds)])


def await_hold(pid, path):
    """Poll until pid holds path open (proves the test setup)."""
    real = os.path.realpath(path)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            names = os.listdir("/proc/%d/fd" % pid)
        except OSError:
            return False
        for name in names:
            try:
                if os.readlink("/proc/%d/fd/%s" % (pid, name)) == real:
                    return True
            except OSError:
                continue
        time.sleep(0.005)
    return False


def main():
    tmp = tempfile.mkdtemp(prefix="writer-wait-")
    try:
        real_dir = os.path.join(tmp, "real")
        os.mkdir(real_dir)
        plain = os.path.join(real_dir, "status")
        with open(plain, "w", encoding="utf-8") as handle:
            handle.write("ready\n")
        link_dir = os.path.join(tmp, "link")
        os.symlink(real_dir, link_dir)
        via_link = os.path.join(link_dir, "status")

        # 1. Held through a symlinked directory: must block until
        # the close (the old spelling compare returned at once).
        child = hold_then_close(via_link, 2)
        try:
            if not await_hold(child.pid, via_link):
                return "symlink hold: child never opened the file"
            start = time.monotonic()
            got = test_cleanup.wait_writer_closed(
                child.pid, via_link, "symlink")
            elapsed = time.monotonic() - start
        finally:
            child.kill()
            child.wait()
        if got is not True:
            return "symlink hold: want True, got %r" % (got,)
        if elapsed < 1.0:
            return ("symlink hold: returned after %.2fs, "
                    "want the ~2s hold" % elapsed)

        # 2. Plain spelling still blocks while held.
        child = hold_then_close(plain, 2)
        try:
            if not await_hold(child.pid, plain):
                return "plain hold: child never opened the file"
            start = time.monotonic()
            got = test_cleanup.wait_writer_closed(
                child.pid, plain, "plain")
            elapsed = time.monotonic() - start
        finally:
            child.kill()
            child.wait()
        if got is not True or elapsed < 1.0:
            return ("plain hold: want True after ~2s, got %r "
                    "after %.2fs" % (got, elapsed))

        # 3. Nothing held: immediate True.
        idle = subprocess.Popen([sys.executable, "-c",
                                 "import time; time.sleep(30)"])
        try:
            start = time.monotonic()
            got = test_cleanup.wait_writer_closed(
                idle.pid, plain, "idle")
            elapsed = time.monotonic() - start
        finally:
            idle.kill()
            idle.wait()
        if got is not True or elapsed > 5:
            return ("idle: want immediate True, got %r after "
                    "%.2fs" % (got, elapsed))

        # 4. Dead process: False, not an exception.
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        if test_cleanup.wait_writer_closed(
                dead.pid, plain, "dead") is not False:
            return "dead pid: want False"

        # 5. A writer that never closes fails (short timeout).
        old_timeout = test_cleanup.WRITER_TIMEOUT
        test_cleanup.WRITER_TIMEOUT = 1
        try:
            child = hold_then_close(plain, 30)
            try:
                if not await_hold(child.pid, plain):
                    return "stuck writer: child never opened the file"
                test_cleanup.wait_writer_closed(
                    child.pid, plain, "stuck")
            except test_cleanup.Fail:
                pass
            else:
                return "stuck writer: want Fail"
            finally:
                child.kill()
                child.wait()
        finally:
            test_cleanup.WRITER_TIMEOUT = old_timeout

        # 6. An exited (zombie, unreaped) child reads as gone, not
        # as confinement: its fd directory denies listing.
        exiting = subprocess.Popen(
            [sys.executable, "-c",
             "import sys, time; open(sys.argv[1]).close()",
             plain])
        # No poll/wait here: only the parent reaps, so the
        # exited child stays a zombie until the final wait.
        deadline = time.monotonic() + 10
        while not test_cleanup.is_zombie(exiting.pid):
            if time.monotonic() >= deadline:
                exiting.wait()
                return "zombie: child never reached zombie state"
            time.sleep(0.005)
        start = time.monotonic()
        got = test_cleanup.wait_writer_closed(
            exiting.pid, plain, "zombie")
        elapsed = time.monotonic() - start
        fds = test_cleanup.fds_of(exiting.pid)
        exiting.wait()
        if got is not False:
            return "zombie wait: want False, got %r" % (got,)
        if fds is not None:
            return "zombie fds: want None, got %r" % (fds,)
        if elapsed > 5:
            return ("zombie wait: took %.2fs, want an instant "
                    "gone verdict" % elapsed)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_writer_wait: symlink, plain, idle, dead, "
          "stuck, zombie")
    return None


if __name__ == "__main__":
    error = main()
    if error is not None:
        print("FAIL test_writer_wait: %s" % error, file=sys.stderr)
        sys.exit(1)
