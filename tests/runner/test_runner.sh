#!/usr/bin/env bash
# Runner teardown tests: the packaged run-tracepoint.sh against fake
# doubles. No privilege, no BPF, no Mojo: the sandbox copies the
# current script plus fake binaries satisfying its file checks, so
# the tests track the shipped runner exactly.
#
# Covers the round-3 findings: timer cancellation never stalls
# (KILL, not TERM), TERM-ignoring children die on a bounded
# TERM-to-KILL schedule, a parent TERM reaps every owned child
# promptly, and exit codes plus the ledger check still propagate.
# Exit 0 on pass, 1 on failure. Needs bash >= 5.1, coreutils.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RUNNER_SRC="$ROOT/examples/tracepoint/run-tracepoint.sh"

fails=0

fail() {
    echo "runner-test: FAIL: $1" >&2
    fails=$((fails + 1))
}

sandbox() {
    # $1 = test name. Prints the sandbox dir with the runner copy
    # plus placeholder package files; the caller adds doubles.
    local dir
    dir="$(mktemp -d /tmp/runner-test-XXXXXX)"
    mkdir -p "$dir/examples" "$dir/lib"
    cp "$RUNNER_SRC" "$dir/run-tracepoint.sh"
    chmod +x "$dir/run-tracepoint.sh"
    : >"$dir/examples/probe.bpf.o"
    : >"$dir/lib/libbpf_mojo.so.1"
    echo "$dir"
}

fake_trigger_ok() {
    # Instant trigger writing a correct ledger. Args: ready ledger
    # want timeout tgidfile.
    cat >"$1" <<'EOF'
#!/usr/bin/env bash
echo "tgid=$$ count=$3" >"$2"
EOF
    chmod +x "$1"
}

fake_main_ok() {
    # Instant successful collector.
    cat >"$1" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$1"
}

prepend_runner() {
    # Insert observer lines after the sandbox runner's shebang.
    # The shipped logic is untouched; the preamble only observes
    # (signal logging) or faults (kill stub) for these cases.
    local dir=$1 line=$2 tmp
    tmp="$(mktemp)"
    { head -n 1 "$dir/run-tracepoint.sh"; echo "$line";
      tail -n +2 "$dir/run-tracepoint.sh"; } >"$tmp"
    mv "$tmp" "$dir/run-tracepoint.sh"
    chmod +x "$dir/run-tracepoint.sh"
}

reap_session() {
    # After waiting the leader, kill every session survivor
    # (orphaned timers keep their process group).
    kill -KILL -- "-$1" 2>/dev/null || true
}

case_fast_path() {
    # Twenty instant runs: every timer stop must return at once
    # (the old TERM stop stalled 9/100 for the full term) and
    # the ledger check must pass each time.
    local dir out rc i
    dir="$(sandbox)"
    fake_main_ok "$dir/examples/tracepoint_main"
    fake_trigger_ok "$dir/examples/tracepoint_trigger"
    for i in $(seq 1 20); do
        out="$("$dir/run-tracepoint.sh" 8 10 2>&1)"
        rc=$?
        if [ "$rc" -ne 0 ]; then
            fail "fast path iter $i exit $rc: $out"
            break
        fi
        if ! printf '%s\n' "$out" \
            | grep -q "ledger: tgid=[0-9][0-9]* count=8"; then
            fail "fast path iter $i missing ledger: $out"
            break
        fi
    done
    rm -rf "$dir"
}

case_exit_codes() {
    # Collector status and ledger mismatches propagate.
    local dir out rc
    dir="$(sandbox)"
    cat >"$dir/examples/tracepoint_main" <<'EOF'
#!/usr/bin/env bash
exit 3
EOF
    chmod +x "$dir/examples/tracepoint_main"
    fake_trigger_ok "$dir/examples/tracepoint_trigger"
    out="$("$dir/run-tracepoint.sh" 8 10 2>&1)"
    rc=$?
    [ "$rc" -eq 3 ] || fail "exit code: want 3 got $rc: $out"
    cat >"$dir/examples/tracepoint_trigger" <<'EOF'
#!/usr/bin/env bash
echo "tgid=$$ count=WRONG" >"$2"
EOF
    chmod +x "$dir/examples/tracepoint_trigger"
    fake_main_ok "$dir/examples/tracepoint_main"
    out="$("$dir/run-tracepoint.sh" 8 10 2>&1)"
    rc=$?
    [ "$rc" -eq 1 ] || fail "ledger mismatch: want 1 got $rc: $out"
    rm -rf "$dir"
}

case_escalation() {
    # A TERM-ignoring collector past a 1s timer must die on the
    # bounded TERM-to-KILL schedule (~6s), not when its own
    # 30s sleep ends, and must leave no orphan behind.
    local dir rc start elapsed pid
    dir="$(sandbox)"
    cat >"$dir/examples/tracepoint_main" <<EOF
#!/usr/bin/env bash
echo \$\$ >"$dir/main.pid"
trap '' TERM
exec sleep 30
EOF
    chmod +x "$dir/examples/tracepoint_main"
    fake_trigger_ok "$dir/examples/tracepoint_trigger"
    start=$SECONDS
    "$dir/run-tracepoint.sh" 8 -59 >/dev/null 2>&1
    rc=$?
    elapsed=$((SECONDS - start))
    [ "$rc" -ne 0 ] || fail "escalation: want nonzero got 0"
    if [ "$elapsed" -ge 20 ]; then
        fail "escalation: took ${elapsed}s, want under 20s"
    fi
    if [ -f "$dir/main.pid" ]; then
        pid="$(cat "$dir/main.pid")"
        if kill -0 "$pid" 2>/dev/null; then
            fail "escalation: collector $pid still alive"
            kill -KILL "$pid" 2>/dev/null || true
        fi
    else
        fail "escalation: collector never started"
    fi
    rm -rf "$dir"
}

case_parent_term() {
    # TERM to the runner must reap every owned child promptly
    # and exit 143.
    local dir rc start elapsed pid runner
    dir="$(sandbox)"
    cat >"$dir/examples/tracepoint_main" <<EOF
#!/usr/bin/env bash
echo \$\$ >"$dir/main.pid"
exec sleep 30
EOF
    chmod +x "$dir/examples/tracepoint_main"
    fake_trigger_ok "$dir/examples/tracepoint_trigger"
    start=$SECONDS
    "$dir/run-tracepoint.sh" 8 60 >/dev/null 2>&1 &
    runner=$!
    sleep 1
    kill -TERM "$runner" 2>/dev/null || true
    wait "$runner"
    rc=$?
    elapsed=$((SECONDS - start))
    [ "$rc" -eq 143 ] || fail "parent TERM: want 143 got $rc"
    if [ "$elapsed" -ge 12 ]; then
        fail "parent TERM: took ${elapsed}s, want under 12s"
    fi
    if [ -f "$dir/main.pid" ]; then
        pid="$(cat "$dir/main.pid")"
        if kill -0 "$pid" 2>/dev/null; then
            fail "parent TERM: collector $pid still alive"
            kill -KILL "$pid" 2>/dev/null || true
        fi
    else
        fail "parent TERM: collector never started"
    fi
    rm -rf "$dir"
}

case_trigger_timeout() {
    # A hanging trigger after a successful collector must hit
    # the 30s timer branch and fail 1 on a bounded schedule.
    local dir rc start elapsed
    dir="$(sandbox)"
    fake_main_ok "$dir/examples/tracepoint_main"
    cat >"$dir/examples/tracepoint_trigger" <<'EOF'
#!/usr/bin/env bash
exec sleep 60
EOF
    chmod +x "$dir/examples/tracepoint_trigger"
    start=$SECONDS
    "$dir/run-tracepoint.sh" 8 10 >/dev/null 2>&1
    rc=$?
    elapsed=$((SECONDS - start))
    [ "$rc" -eq 1 ] || fail "trigger timeout: want 1 got $rc"
    if [ "$elapsed" -lt 28 ] || [ "$elapsed" -ge 45 ]; then
        fail "trigger timeout: took ${elapsed}s, want 28-45s"
    fi
    rm -rf "$dir"
}

case_no_stale_signals() {
    # Every signal must target an owned live child: bash reaps
    # asynchronously, and the unguarded helpers signalled an
    # already-reaped trigger on 100/100 failure flows. The
    # observer preamble logs each signal's ownership verdict
    # and delegates to the real kill; shipped logic untouched.
    local dir i
    dir="$(sandbox)"
    cat >"$dir/examples/tracepoint_main" <<'EOF'
#!/usr/bin/env bash
exit 3
EOF
    chmod +x "$dir/examples/tracepoint_main"
    fake_trigger_ok "$dir/examples/tracepoint_trigger"
    prepend_runner "$dir" 'kill() { if owned "$2"; then echo "SIGNAL $1 owned=yes"; else echo "SIGNAL $1 owned=NO-STALE"; fi >>"$SIGNAL_LOG"; command kill "$@"; }'
    export SIGNAL_LOG="$dir/signals.log"
    : >"$SIGNAL_LOG"
    for i in $(seq 1 20); do
        "$dir/run-tracepoint.sh" 8 10 >/dev/null 2>&1
    done
    if grep -q "NO-STALE" "$SIGNAL_LOG"; then
        fail "stale signals sent: $(grep -c NO-STALE "$SIGNAL_LOG")"
    fi
    if ! grep -q "SIGNAL" "$SIGNAL_LOG"; then
        fail "no signals observed (harness broken?)"
    fi
    rm -rf "$dir"
}

case_term_status() {
    # A TERM-killed collector reports 143: teardown must
    # preserve the terminated-child status it collected.
    local dir rc start elapsed
    dir="$(sandbox)"
    cat >"$dir/examples/tracepoint_main" <<'EOF'
#!/usr/bin/env bash
exec sleep 30
EOF
    chmod +x "$dir/examples/tracepoint_main"
    fake_trigger_ok "$dir/examples/tracepoint_trigger"
    start=$SECONDS
    "$dir/run-tracepoint.sh" 8 -59 >/dev/null 2>&1
    rc=$?
    elapsed=$((SECONDS - start))
    [ "$rc" -eq 143 ] || fail "term status: want 143 got $rc"
    if [ "$elapsed" -ge 10 ]; then
        fail "term status: took ${elapsed}s, want under 10s"
    fi
    rm -rf "$dir"
}

case_abandon_skip() {
    # A child that survives KILL converts SKIP to failure: with
    # kill stubbed out, the pending timer never dies, the latch
    # trips, and exit 77 must become exit 1.
    local dir rc out runner
    dir="$(sandbox)"
    cat >"$dir/examples/tracepoint_main" <<'EOF'
#!/usr/bin/env bash
exit 77
EOF
    chmod +x "$dir/examples/tracepoint_main"
    fake_trigger_ok "$dir/examples/tracepoint_trigger"
    prepend_runner "$dir" 'kill() { return 0; }'
    # New session directly in this shell (a $() wrapper would
    # orphan the job from wait): orphans keep the group, so one
    # group kill reaps every stray afterwards.
    setsid "$dir/run-tracepoint.sh" 8 -58 >"$dir/out.log" 2>&1 &
    runner=$!
    wait "$runner"
    rc=$?
    reap_session "$runner"
    out="$(cat "$dir/out.log")"
    [ "$rc" -eq 1 ] || fail "abandon skip: want 1 got $rc: $out"
    if ! printf '%s\n' "$out" | grep -q "survived teardown"; then
        fail "abandon skip: missing latch message: $out"
    fi
    rm -rf "$dir"
}

case_abandon_success() {
    # Same latch from the success path: instant doubles, dead
    # kill, and the 0 verdict must still become 1.
    local dir rc out runner
    dir="$(sandbox)"
    fake_main_ok "$dir/examples/tracepoint_main"
    fake_trigger_ok "$dir/examples/tracepoint_trigger"
    prepend_runner "$dir" 'kill() { return 0; }'
    # New session directly in this shell: orphans keep the
    # group, so one group kill reaps every stray afterwards.
    setsid "$dir/run-tracepoint.sh" 8 -58 >"$dir/out.log" 2>&1 &
    runner=$!
    wait "$runner"
    rc=$?
    reap_session "$runner"
    out="$(cat "$dir/out.log")"
    [ "$rc" -eq 1 ] || fail "abandon success: want 1 got $rc: $out"
    if ! printf '%s\n' "$out" | grep -q "survived teardown"; then
        fail "abandon success: missing latch message: $out"
    fi
    rm -rf "$dir"
}

case_fast_path
case_exit_codes
case_escalation
case_parent_term
case_trigger_timeout
case_no_stale_signals
case_term_status
case_abandon_skip
case_abandon_success

if [ "$fails" -ne 0 ]; then
    echo "runner-test: $fails case(s) failed" >&2
    exit 1
fi
echo "runner-test: PASS (fastx20, codes, escalation, term, timeout,"
echo "  no-stale, term143, abandon-skip, abandon-ok)"
