#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Packaged tracepoint demo runner.
#
# Usage: run-tracepoint.sh [want-count] [timeout-s]
#
# Runs the trigger plus the Mojo collector end to end and prints the
# settlement record. All paths resolve from the package root (this
# script's directory), never from the working directory. Needs BPF
# privilege for the collection step; without it the collector exits
# 77. Exit code is the collector's, except a missing or mismatched
# trigger ledger fails the run: the ledger is the independent half
# of the reconciliation, not an optional accessory.
#
# Process ownership: the trigger, the collector, and the timer
# are all direct children, tracked by PID. Every spawn resets
# inherited traps before exec: an async subshell that has not
# exec'd yet would otherwise run our INT/TERM/EXIT traps if our
# own kill lands first, wiping the tmpdir from under the live
# run (reproduced: stop_timer killed the timer subshell
# pre-exec and the ledger vanished). A TERM that lands in the
# fork-to-reset window is still consumed by the trap, so the
# child then execs and ignores the already-spent signal
# (reproduced: 9/100 timer stops stalled the full term);
# timers are therefore cancelled with KILL, which no trap can
# consume, and teardown escalates TERM to KILL on a bounded
# schedule instead of waiting unboundedly. Waits use the `wait`
# builtin so trapped signals interrupt promptly (a foreground
# external command would defer them); `wait -n -p` (bash >= 5.1)
# reports which child finished. Bash reaps background children
# asynchronously on SIGCHLD and serves their statuses from its
# job table, so a tracked PID may already be reaped, free, or
# recycled at any signal point (reproduced: 100/100 failure
# flows signalled an already-reaped trigger): no signal is
# ever sent without an ownership check, a lost PID collects
# its cached status instead of killing, and a child that
# survives KILL latches cleanup_failed, converting success or
# SKIP to failure at the exit point.
#
# This script ships inside the tools/package tarball. In a source
# checkout prefer ./tools/test live-tracepoint, which asserts the
# same flow plus reconciliation and cleanup.

set -u

PKG_ROOT="$(cd "$(dirname "$0")" && pwd)"
export LD_LIBRARY_PATH="$PKG_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LMB_NATIVE_LIB="$PKG_ROOT/lib/libbpf_mojo.so.1"

MAIN="$PKG_ROOT/examples/tracepoint_main"
TRIGGER="$PKG_ROOT/examples/tracepoint_trigger"
ELF="$PKG_ROOT/examples/probe.bpf.o"

want="${1:-128}"
timeout_s="${2:-60}"

for need in "$MAIN" "$TRIGGER" "$ELF" "$LMB_NATIVE_LIB"; do
    if [ ! -f "$need" ]; then
        echo "run-tracepoint: missing package file: $need" >&2
        exit 2
    fi
done

tmp="$(mktemp -d)"
trig_pid=""
main_pid=""
watchdog=""
cleanup_failed=""
MAIN_PID=$$

cleanup() {
    # Subshells must never clean: an async job that has not
    # exec'd yet still runs our traps if a kill lands first, and
    # its cleanup would delete the tmpdir from under the live
    # run. BASHPID (not $$, which a subshell inherits
    # unchanged) tells us apart. The test MUST use [[ ]]: a
    # pre-exec subshell inherits unfinished fork bookkeeping,
    # and bash replaces a `[` simple command's status with 127
    # (execute_cmd.c wait_for(last_made_pid)), which flips this
    # guard and reaches rm. [[ ]] takes the conditional-command
    # path and is immune (verified: 0/2000 vs 281/500).
    # Idempotent in the main shell: every signal path funnels
    # through here, and EXIT re-runs it after an INT/TERM
    # handler already did.
    if [[ "$BASHPID" != "$MAIN_PID" ]]; then
        return 0
    fi
    # teardown/stop_timer check ownership themselves before
    # every signal, so cleanup passes its PIDs straight
    # through; a lost PID collects its cached status.
    if [ -n "$trig_pid" ]; then
        teardown "$trig_pid" || true
    fi
    if [ -n "$main_pid" ]; then
        teardown "$main_pid" || true
    fi
    stop_timer || true
    trig_pid=""
    main_pid=""
    watchdog=""
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

spawn() {
    # Fork+exec with inherited traps reset to default first, so a
    # kill landing before exec ends the subshell silently. The
    # cleanup() BASHPID guard is the correctness backstop for the
    # fork-to-reset window itself. Never `trap ''` here: ignored
    # dispositions survive exec and would make the child
    # unkillable.
    ( trap - INT TERM EXIT; exec "$@" ) &
}

start_timer() {
    # Directly owned timer: the subshell execs sleep, so the only
    # process is the timer itself — killed and reaped explicitly,
    # never an orphaned grandchild. All stdio detached so the
    # timer never pins a pipe.
    spawn sleep "$1" </dev/null >/dev/null 2>&1
    watchdog=$!
}

owned() {
    # True when the PID is a live process whose parent is us. A
    # zombie still names us, which is correct: reaping it is
    # ours to do. Callers pass non-empty PIDs only.
    [ -d "/proc/$1" ] || return 1
    [ "$(awk '{print $4}' "/proc/$1/stat" 2>/dev/null)" = "$MAIN_PID" ]
}

killable() {
    # True when a signal to the PID would land on our own live
    # child: owned, and not a zombie (a zombie needs reaping,
    # not killing). Bash reaps asynchronously, so a tracked PID
    # that is gone or foreign is done, not pending: the single
    # wait below then serves its cached status immediately
    # instead of blocking. No signal is ever sent unless this
    # holds. Callers pass non-empty PIDs only.
    owned "$1" || return 1
    [ "$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)" != "Z" ]
}

teardown() {
    # Bounded kill of one tracked child: TERM, a short grace
    # poll, then KILL, each signal guarded by an ownership
    # check. Returns the child's status via the single wait,
    # which serves its cached status when bash already reaped
    # it. Only an unkillable (D-state) survivor is abandoned,
    # latching cleanup_failed, rather than waited on forever.
    local pid=$1 deadline
    if killable "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        deadline=$((SECONDS + 5))
        while killable "$pid" && [ "$SECONDS" -lt "$deadline" ]; do
            sleep 0.1
        done
        if killable "$pid"; then
            kill -KILL "$pid" 2>/dev/null || true
            deadline=$((SECONDS + 1))
            while killable "$pid" \
                && [ "$SECONDS" -lt "$deadline" ]; do
                sleep 0.05
            done
        fi
    fi
    if ! killable "$pid"; then
        wait "$pid" 2>/dev/null
        return $?
    fi
    cleanup_failed=1
    echo "run-tracepoint: pid $pid survived KILL; abandoned" >&2
    return 1
}

stop_timer() {
    # Timers die by KILL, never TERM: a TERM landing before the
    # timer subshell resets its inherited traps is consumed by
    # the trap, and the subshell then execs sleep and runs the
    # full term while the wait below stalls (reproduced 9/100).
    # KILL cannot be trapped, so the wait only reaps. The KILL
    # is ownership-guarded: an already-reaped timer collects
    # its cached status instead of signalling a dead PID. A
    # timer that survives KILL latches cleanup_failed: losing
    # the PID must not silently keep a success/SKIP verdict.
    if [ -n "$watchdog" ]; then
        local deadline
        if killable "$watchdog"; then
            kill -KILL "$watchdog" 2>/dev/null || true
            deadline=$((SECONDS + 1))
            while killable "$watchdog" \
                && [ "$SECONDS" -lt "$deadline" ]; do
                sleep 0.05
            done
        fi
        if ! killable "$watchdog"; then
            wait "$watchdog" 2>/dev/null || true
            watchdog=""
            return 0
        fi
        cleanup_failed=1
        echo "run-tracepoint: timer $watchdog survived KILL; " \
            "abandoned" >&2
        watchdog=""
        return 1
    fi
    return 0
}

spawn "$TRIGGER" "$tmp/ready" "$tmp/ledger" "$want" "$timeout_s" \
    "$tmp/tgid"
trig_pid=$!
# Atomic pidfile: the trigger must never observe an empty file.
echo "$trig_pid" >"$tmp/tgid.new"
mv "$tmp/tgid.new" "$tmp/tgid"
# Follow the namespace symlink: without -L, stat reports the
# symlink itself (a fresh wrong inode per call) instead of the
# stable namespace identity the BPF helper wants.
ns_dev="$(stat -L -c %d /proc/self/ns/pid)"
ns_ino="$(stat -L -c %i /proc/self/ns/pid)"

spawn "$MAIN" "$ELF" "$trig_pid" "$ns_dev" "$ns_ino" \
    "$tmp/ready" "$tmp/out" "$want" "$timeout_s"
main_pid=$!
start_timer "$((timeout_s + 60))"
wait -n -p done_pid "$main_pid" "$watchdog"
first_rc=$?
timed_out=""
if [ "$done_pid" = "$watchdog" ]; then
    # The timer fired and wait -n reaped it: clear the PID at
    # once. The collector may already be reaped too (bash
    # reaps asynchronously): teardown signals only an owned
    # live child and otherwise collects its cached status.
    watchdog=""
    timed_out="1"
    teardown "$main_pid"
    rc=$?
else
    # wait -n reaped the collector (or served its already
    # recorded status); first_rc is its status.
    rc=$first_rc
fi
main_pid=""
stop_timer
if [ -n "$timed_out" ] && [ "$rc" -ne 0 ]; then
    echo "run-tracepoint: collector timed out" >&2
fi

if [ "$rc" -eq 0 ]; then
    # The collector can observe the final event before the trigger
    # flushes its ledger, so success must wait for the trigger and
    # require its receipt; killing it here would drop the
    # independent half of the reconciliation.
    start_timer 30
    wait -n -p done_pid "$trig_pid" "$watchdog"
    trig_first_rc=$?
    trig_timed_out=""
    if [ "$done_pid" = "$watchdog" ]; then
        # wait -n reaped the fired timer: clear it. The
        # trigger may already be reaped too; teardown only
        # signals an owned live child.
        watchdog=""
        trig_timed_out="1"
        teardown "$trig_pid"
        trig_rc=$?
    else
        trig_rc=$trig_first_rc
    fi
    tgid="$trig_pid"
    trig_pid=""
    stop_timer
    if [ -n "$trig_timed_out" ] && [ "$trig_rc" -ne 0 ]; then
        echo "run-tracepoint: trigger timed out after collector" >&2
    fi
    if [ "$trig_rc" -ne 0 ]; then
        echo "run-tracepoint: trigger exit $trig_rc" >&2
        rc=1
    elif ! grep -qxF "tgid=$tgid count=$want" "$tmp/ledger" \
        2>/dev/null; then
        echo "run-tracepoint: ledger missing or mismatched" >&2
        rc=1
    fi
else
    teardown "$trig_pid" || true
    trig_pid=""
fi

if [ -f "$tmp/ledger" ]; then
    echo "ledger: $(cat "$tmp/ledger")"
fi
if [ -f "$tmp/out" ]; then
    cat "$tmp/out"
fi
if [ -n "$cleanup_failed" ] \
    && { [ "$rc" -eq 0 ] || [ "$rc" -eq 77 ]; }; then
    # An abandoned child means cleanup was never proven:
    # success and SKIP both become failure. Other statuses
    # already fail and are preserved.
    echo "run-tracepoint: a child survived teardown; failing" >&2
    rc=1
fi
exit "$rc"
