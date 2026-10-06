#!/bin/sh
# Clean-room package check: no compiler, no Pixi, no Mojo, no Python.
#
# Usage: clean-check.sh <expected-root>
# Invoked as `sh /clean-check.sh <root>` inside the clean image with
# the tarball mounted at /pkg.tgz (read-only) and tracefs mounted.
# Unpacks the tarball enforcing exactly one expected root, runs the
# packaged demo, and asserts no owned BPF objects survive.
#
# Prints CLEAN-PASS plus the settlement record on success, CLEAN-SKIP
# (exit 77) without privilege, CLEAN-FAIL (exit 1) otherwise.
# POSIX sh only: dash has no pipefail, so every bpftool status is
# captured explicitly and no pipeline hides an enumeration failure.
set -eu

ROOT="${1:?usage: clean-check.sh <expected-root>}"
PKG=/pkg.tgz
WORK=/work

fail() { echo "CLEAN-FAIL: $*" >&2; exit 1; }

echo "clean-runtime: $(cat /etc/os-release 2>/dev/null \
  | grep -m1 PRETTY_NAME || echo unknown)"
echo "clean-runtime: $(bpftool --version 2>/dev/null | head -1)"

command -v bpftool >/dev/null 2>&1 || fail "bpftool missing from image"
test -f "$PKG" || fail "$PKG not mounted"

# Every member must live under exactly the expected root: an extra
# root could otherwise supply an unverified privileged runner.
members="$WORK.members"
tar tzf "$PKG" >"$members" 2>/dev/null \
  || fail "cannot list tarball members"
saw_root=0
while IFS= read -r m; do
  case "$m" in
    "$ROOT"|"$ROOT"/*) ;;
    *) fail "member outside expected root: $m" ;;
  esac
  saw_root=1
done <"$members"
test "$saw_root" -eq 1 || fail "empty tarball"

rm -rf "$WORK"
mkdir -p "$WORK"
tar xzf "$PKG" -C "$WORK" || fail "extraction failed"
cd "$WORK/$ROOT" || fail "expected root missing after extract"

test -x ./run-tracepoint.sh || fail "run-tracepoint.sh missing"
test -f MANIFEST.json || fail "MANIFEST.json missing"
test -f THIRD-PARTY-NOTICES.md || fail "notices file missing"
test -n "$(ls licenses/ 2>/dev/null)" || fail "licenses/ empty"

# Owned object names from the example probe. Snapshots scope to
# these: raw id-set diffs false-positive on shared kernels where
# foreign objects come and go mid-run.
NAMES='trace_probe|events|filter|count'

snap_ids() {
  # $1: kind (prog|map), $2: output file. Prints owned ids, one per
  # line. Enumeration failure or a malformed listing fails
  # closed: a failed listing must never read as "zero objects".
  # Entries wrap across whitespace-led continuation lines; those
  # carry no identity and are skipped. Header lines without a
  # name are definitively foreign (every owned object is named)
  # and are scoped out, not treated as errors.
  out="$2"
  raw="$out.raw"
  if ! bpftool "$1" show >"$raw" 2>"$out.err"; then
    fail "bpftool $1 show failed: $(head -c 300 "$out.err")"
  fi
  awk -v names="$NAMES" '
    /^[0-9]+:/ {
      id = $1; sub(/:$/, "", id);
      name = "";
      for (i = 1; i < NF; i++)
        if ($i == "name") name = $(i + 1);
      if (name != "" && (" " name " ") ~ (" (" names ") "))
        print id;
      next;
    }
    /^[ \t]/ { next; }
    NF > 0 { print "UNPARSEABLE: " $0; }
  ' "$raw" >"$out" || fail "cannot parse bpftool $1 output"
  if grep -q "^UNPARSEABLE:" "$out"; then
    fail "unrecognized bpftool $1 line: $(grep -m1 '^UNPARSEABLE:' \
      "$out" | head -c 200)"
  fi
}

snap_links() {
  # $1: space-separated owned prog ids, $2: output file. Links carry
  # no name; scope by attachment to our programs.
  want=" $1 "
  out="$2"
  raw="$out.raw"
  if ! bpftool link show >"$raw" 2>"$out.err"; then
    fail "bpftool link show failed: $(head -c 300 "$out.err")"
  fi
  awk -v want="$want" '
    /^[0-9]+:/ {
      id = $1; sub(/:$/, "", id);
      prog = "";
      for (i = 1; i < NF; i++)
        if ($i == "prog" || $i == "prog_id") prog = $(i + 1);
      if (prog == "") { print "UNPARSEABLE: " $0; next; }
      if (index(want, " " prog " ") > 0) print id;
      next;
    }
    /^[ \t]/ { next; }
    NF > 0 { print "UNPARSEABLE: " $0; }
  ' "$raw" >"$out" || fail "cannot parse bpftool link output"
  if grep -q "^UNPARSEABLE:" "$out"; then
    fail "unrecognized bpftool link line: $(grep -m1 '^UNPARSEABLE:' \
      "$out" | head -c 200)"
  fi
}

snapshot() {
  # $1: directory to hold prog/map/link id files. Sort and compare
  # must use the same collation: comm(1) compares lexically, so a
  # numeric sort feeds it misordered input (9 before 10), which
  # fails the comparison and can report pre-existing ids as new.
  # Plain sort under LC_ALL=C keeps both sides consistent.
  mkdir -p "$1"
  snap_ids prog "$1/prog"
  snap_ids map "$1/map"
  LC_ALL=C sort -o "$1/prog" "$1/prog"
  LC_ALL=C sort -o "$1/map" "$1/map"
  progs="$(tr '\n' ' ' <"$1/prog")"
  snap_links "$progs" "$1/link"
  LC_ALL=C sort -o "$1/link" "$1/link"
}

snapshot /tmp/before

run_out=/tmp/run.out
set +e
./run-tracepoint.sh 8 60 >"$run_out" 2>&1
rc=$?
set -e
cat "$run_out"
if [ "$rc" -eq 77 ]; then
  echo "CLEAN-SKIP: clean room reports no privilege"
  exit 77
fi
if [ "$rc" -ne 0 ]; then
  fail "packaged demo exit $rc"
fi
grep -q "^complete=true$" "$run_out" \
  || fail "packaged demo left no complete record"

# Kernel-side teardown lags the last close by ~100ms sometimes, so
# poll briefly: anything still alive after the settle window is a
# real leak. Compare id sets, not counts: a disappearing foreign
# object must never cancel an actual leftover.
assert_no_leak() {
  label="$1"
  leaked=""
  attempt=0
  while [ "$attempt" -lt 100 ]; do
    snapshot /tmp/after
    leaked=""
    for kind in prog map link; do
      newobjs="$(LC_ALL=C comm -13 /tmp/before/$kind /tmp/after/$kind)"
      if [ -n "$newobjs" ]; then
        # shellcheck disable=SC2086
        for id in $newobjs; do
          leaked="$leaked $kind:$id"
        done
      fi
    done
    if [ -z "$leaked" ]; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  if [ -n "$leaked" ]; then
    fail "$label: owned BPF objects leaked:$leaked"
  fi
}

assert_no_leak "positive run"

# Negatives: a damaged package must fail loudly with the exact
# expected status, never half-run. Any nonzero is not enough: a
# crash (128+signal) or a privilege SKIP (77) would also be
# nonzero but would prove nothing about library handling.
mv lib/libbpf_mojo.so.1 lib/hidden.so.1
set +e
./run-tracepoint.sh 2 20 >/tmp/neg1.out 2>&1
nrc=$?
set -e
mv lib/hidden.so.1 lib/libbpf_mojo.so.1
test "$nrc" -eq 2 \
  || fail "missing bridge exit $nrc, want 2 (runner usage check)"
echo "negative missing-bridge: exit 2 (correctly failed)"

incompat=""
for lib in lib/*.so*; do
  case "$lib" in
    *libbpf_mojo*) ;;
    *) if [ -f "$lib" ]; then incompat="$lib"; break; fi ;;
  esac
done
test -n "$incompat" || fail "no bundled runtime library for negative"
cp "$incompat" /tmp/incompat.orig
echo "not an ELF object" >"$incompat"
set +e
./run-tracepoint.sh 2 20 >/tmp/neg2.out 2>&1
nrc=$?
set -e
cp /tmp/incompat.orig "$incompat"
rm -f /tmp/incompat.orig
test "$nrc" -eq 127 \
  || fail "incompatible runtime exit $nrc, want 127 (loader refusal)"
echo "negative incompatible-runtime: exit 127 (correctly failed)"

assert_no_leak "negative runs"

echo "CLEAN-PASS"
