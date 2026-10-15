# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Finite disposable-guest map checks. Importing this file performs no work.

All expected hashes enter through an independently frozen profile. The witness
contains observations, never authority. No tool is started before guest checks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import uuid
import struct

PHASES = ("loaded", "initialized", "executed", "keys-seeded", "key-deleted", "keys-empty", "owner-released", "closed")
ROLES = ("object", "mutant_object", "stock_consumer", "mojo_consumer", "bridge", "bpftool", "setpriv")
V2 = frozenset("fpu cx8 cmov mmx fxsr sse sse2 lm pni ssse3 sse4_1 sse4_2 popcnt cx16 lahf_lm".split())
VALUES = {"00000000": "efcdab8967452301", "07000000": "1032547698badcfe", "ffffffff": "8877665544332211"}
END = {"operation": 19, "domain": 3, "code": -2}


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _version(value):
    match = re.match(r"^(\d+)\.(\d+)(?:[.\-]|$)", value) if isinstance(value, str) else None
    return tuple(map(int, match.groups())) if match else (0, 0)


def _uuid(value):
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _absolute(value):
    return isinstance(value, str) and value.startswith("/") and ".." not in Path(value).parts

def validate_profile(profile, artifacts, expected_attempt):
    """Pure acceptance predicate for externally admitted functional inputs."""
    errors = []
    try:
        if type(profile["schema_version"]) is not int or profile["schema_version"] != 1 or profile["profile_id"] != "linux7-x86_64-le-tcg-map-v1" or profile["admission"] != "accepted":
            errors.append("profile is not an independently admitted functional expectation")
        identity = profile["identity"]
        if type(identity["online_cpus"]) is not int:
            errors.append("profile CPU count type")
        for name, value in (("architecture", "x86_64"), ("endian", "little"), ("execution_class", "tcg"), ("userspace_cpu", "x86-64-v2"), ("online_cpus", 1), ("boot_id_rule", "fresh-not-host-or-prior")):
            if identity[name] != value:
                errors.append("profile identity: " + name)
        if "boot_id" in identity:
            errors.append("profile cannot learn/freeze its future guest boot ID")
        for name in ("attempt", "hostname", "host_boot_id"):
            if not expected_attempt[name] or identity[name] != expected_attempt[name]:
                errors.append("wrong guest/attempt: " + name)
        boot = expected_attempt["boot_id"]
        if not _uuid(boot) or not _uuid(identity["host_boot_id"]) or boot == identity["host_boot_id"] or boot in profile["previous_boot_ids"]:
            errors.append("host or stale boot")
        if _version(identity["kernel_release"]) < (7, 0) or _version(identity["glibc"]) < (2, 38):
            errors.append("kernel/glibc floor")
        if not V2 <= set(identity["cpu_flags"]) or set(identity["capabilities"]) != {"bpf", "array", "hash", "xdp_test_run"}:
            errors.append("missing CPU/capability requirement")
        if not _digest(identity["rootfs_sha256"]) or not _digest(identity["btf_sha256"]) or re.fullmatch(r"[0-9a-f]{16,128}", identity["kernel_build_id"]) is None:
            errors.append("missing kernel/root identity")
        if set(artifacts) != set(ROLES) or set(profile["artifacts"]) != set(ROLES) or profile["artifacts"] != artifacts or not all(_digest(v) for v in artifacts.values()) or artifacts["object"] == artifacts["mutant_object"]:
            errors.append("missing/swapped/stale artifact")
        closure = profile["runtime_closure"]
        if set(closure) != set(ROLES):
            errors.append("missing runtime closure")
        for role in ROLES:
            row = closure[role]
            nodes = row["nodes"]
            by_path = {n["guest_path"]: n for n in nodes}
            canonical = json.dumps(nodes, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            if row["closure_sha256"] != hashlib.sha256(canonical).hexdigest() or nodes != sorted(nodes, key=lambda n: n["guest_path"]) or row["sha256"] != artifacts[role] or not _absolute(row["guest_path"]) or len(by_path) != len(nodes) or row["guest_path"] not in by_path or by_path[row["guest_path"]]["sha256"] != artifacts[role]:
                errors.append("unbound runtime closure: " + role)
            for node in nodes:
                if not _absolute(node["guest_path"]) or not _digest(node["sha256"]) or node["needed"] != sorted(set(node["needed"])) or any(edge not in by_path for edge in node["needed"]):
                    errors.append("incomplete runtime edge: " + role)
        facts = profile["expected_facts"]
        if not all(_digest(facts[n]) for n in ("notes_sha256", "config_sha256")):
            errors.append("unbound expected raw facts")
        if [r["name"] for r in facts["modules"]] != ["netfs", "9pnet", "9pnet_virtio", "9p"] or any(not _digest(r["btf_sha256"]) for r in facts["modules"]):
            errors.append("unbound expected modules")
        if not facts["policy"]["lsm_raw"].strip() or "[none]" not in facts["policy"]["lockdown_raw"]:
            errors.append("unbound policy")
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        errors.append("missing/malformed profile: " + str(error))
    return errors


def validate_row(record, artifacts, expected_attempt):
    """Check literal results and independently read kernel bytes, with no I/O."""
    errors = []
    try:
        if record["identity"] != expected_attempt or record["artifacts"] != artifacts or record["object_sha256"] != artifacts["object"]:
            errors.append("row guest/artifact binding")
        if record["consumer"] not in ("stock", "mojo") or record["phases"] != list(PHASES):
            errors.append("missing/duplicate/out-of-order phase")
        if record["initialized"] != {"counter": 41, "raw": "2900000000000000"}:
            errors.append("initial 41 oracle")
        executed = record["executed"]
        if executed["counter"] != 42 or executed["raw"] != "2a00000000000000" or executed["retval"] != 2 or executed["data_actual"] != 60 or executed["ctx_actual"] != 0 or type(executed["duration_ns"]) is not int or executed["duration_ns"] < 0:
            errors.append("executed 42/XDP/length/raw-byte oracle")
        keys = record["keys"]
        if keys["empty_first"] is not None or keys["zero_first"] != "00000000" or keys["zero_next"] is not None or keys["empty_final"] is not None:
            errors.append("NULL-first/zero-key/end oracle")
        for name, expected, calls, terminal in (("seeded", set(VALUES), "calls", "terminal"), ("after_delete", {"00000000", "ffffffff"}, "after_calls", "after_terminal")):
            observed = keys[name]
            end = {"kind": "typed_none"} if record["consumer"] == "mojo" else END
            if len(observed) != len(expected) or set(observed) != expected or keys[calls] != len(expected) + 1 or keys[terminal] != end:
                errors.append("bounded unordered key set/exact terminal diagnostic: " + name)
        if keys["first"] not in VALUES or keys["restart"] != keys["first"]:
            errors.append("absent cursor restart")
        for name, operation in (("missing_delete", 18), ("missing_lookup", 7)):
            if keys[name] != {"operation": operation, "domain": 3, "code": -2}:
                errors.append("exact missing-key diagnostic: " + name)
        if (keys["array_first"], keys["array_next"], keys["array_restart"]) != ("00000000", None, "00000000") or type(keys["array_delete"]) is not int or keys["array_delete"] >= 0:
            errors.append("ARRAY traversal/delete refusal")
        independent = record["independent"]
        if independent["seeded"] != VALUES or independent["deleted"] != {k: v for k, v in VALUES.items() if k != "07000000"} or independent["empty"] != {}:
            errors.append("independent HASH bytes/delete oracle")
        if record["retained"] != {"counter": 42, "first": None}:
            errors.append("retained-view oracle")
        owned, cleanup = record["owned"], record["cleanup"]
        if len(owned["map_ids"]) != 2 or len(set(owned["map_ids"])) != 2 or len(owned["program_ids"]) != 1 or any(type(i) is not int or i <= 0 for i in owned["map_ids"] + owned["program_ids"]):
            errors.append("unbound owned IDs")
        if record["exit_code"] != 0 or cleanup["complete"] is not True or sorted(cleanup["map_ids_absent"]) != sorted(owned["map_ids"]) or cleanup["program_ids_absent"] != owned["program_ids"]:
            errors.append("incomplete owned-ID cleanup")
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        errors.append("missing/malformed row: " + str(error))
    return errors


def validate_witness(witness, profile, artifacts, expected_attempt, expected_sha256):
    """Pure witness validation; external references never become guest proof."""
    errors = validate_profile(profile, artifacts, expected_attempt)
    try:
        if witness["schema_version"] != 1 or witness["profile_id"] != profile["profile_id"] or witness["admission"] != "observed" or witness["mode"] != "functional" or witness["expected_sha256"] != expected_sha256:
            errors.append("witness-only/self-admitted/edited expectation")
        identity = witness["identity"]
        expected_identity = {k: v for k, v in profile["identity"].items() if k not in ("boot_id_rule", "capabilities")}
        expected_identity["boot_id"] = expected_attempt["boot_id"]
        if identity != expected_identity or witness["artifacts"] != artifacts or witness["runtime_closure"] != profile["runtime_closure"]:
            errors.append("witness identity/artifact/closure contradiction")
        if witness["external_custody_reference_fields"] != ["identity.host_boot_id", "identity.rootfs_sha256", "identity.execution_class"]:
            errors.append("custody reference basis lost")
        facts, expected = witness["facts"], profile["expected_facts"]
        for fact, key in (("release", "kernel_release"), ("build_id", "kernel_build_id"), ("btf_sha256", "btf_sha256"), ("boot_id", "boot_id"), ("hostname", "hostname"), ("architecture", "architecture"), ("byte_order", "endian"), ("cpus", "online_cpus"), ("cpu_flags", "cpu_flags"), ("glibc", "glibc")):
            if facts[fact] != identity[key]:
                errors.append("raw witness/identity mismatch: " + fact)
        if facts["notes_sha256"] != expected["notes_sha256"] or facts["config_sha256"] != expected["config_sha256"] or facts["btf_errors"] != []:
            errors.append("notes/config/BTF mismatch")
        if hashlib.sha256(facts["config_raw"].encode()).hexdigest() != expected["config_sha256"]:
            errors.append("associated packaged config bytes changed")
        status = dict(line.split(":", 1) for line in facts["status_raw"].splitlines() if ":" in line)
        required_caps = (1 << 21) | (1 << 38) | (1 << 39)
        if facts["uid"] != 0 or facts["euid"] != 0 or list(map(int, status["Uid"].split())) != [0, 0, 0, 0] or int(status["CapEff"].strip(), 16) & required_caps != required_caps or int(status["CapBnd"].strip(), 16) & required_caps != required_caps or status["NoNewPrivs"].strip() != "0":
            errors.append("root UID/capabilities unavailable")
        raw_flags = next(line.split(":", 1)[1].split() for line in facts["cpu_raw"].splitlines() if line.split(":", 1)[0].strip() == "flags")
        if set(raw_flags) != set(facts["cpu_flags"]) or not V2 <= set(raw_flags) or facts["page_size"] != 4096 or not re.search(r"^MemTotal:\s+[1-9][0-9]* kB$", facts["meminfo"], re.M) or facts["glibc_raw"] != "glibc " + identity["glibc"]:
            errors.append("raw CPU/memory/glibc fact unavailable")
        for name in ("MEMLOCK", "NOFILE"):
            if len(facts["rlimits"][name]) != 2 or any(type(v) is not int or v < -1 for v in facts["rlimits"][name]):
                errors.append("rlimit unavailable")
        for name in ("jit", "jit_harden"):
            raw = facts[name]
            if raw["status"] != "read" or raw["raw"].strip() not in (("1", "2") if name == "jit" else ("0", "1", "2")):
                errors.append("required JIT fact unavailable: " + name)
        policy = facts["policy"]
        mounted = any(len(line.split(" - ", 1)) == 2 and line.split()[4] == "/sys/kernel/security" and line.split(" - ", 1)[1].split()[0] == "securityfs" for line in policy["mountinfo"].splitlines())
        if not mounted or policy["acquisition"]["returncode"] != 0 or policy["acquisition"]["owned"] is not True:
            errors.append("required securityfs mount/acquisition unavailable")
        for name, raw_name in (("lsm", "lsm_raw"), ("lockdown", "lockdown_raw")):
            if policy[name]["status"] != "read" or not policy[name]["raw"].strip() or policy[name]["raw"] != expected["policy"][raw_name]:
                errors.append("required raw policy unavailable/changed: " + name)
        if "[none]" not in policy["lockdown"]["raw"]:
            errors.append("lockdown active")
        if [{"name": m["name"], "btf_sha256": m["btf_sha256"]} for m in facts["modules"]] != expected["modules"] or any(m["loaded"] is not True for m in facts["modules"]):
            errors.append("required loaded module/BTF mismatch")
        consumed = {r["guest_path"]: r for r in facts["consumed_files"]}
        if len(consumed) != len(facts["consumed_files"]):
            errors.append("duplicate consumed file")
        for closure in profile["runtime_closure"].values():
            for node in closure["nodes"]:
                row = consumed[node["guest_path"]]
                if row["match"] is not True or row["actual_sha256"] != node["sha256"] or row["expected_sha256"] != node["sha256"]:
                    errors.append("consumed runtime node changed")
    except (KeyError, TypeError, AttributeError, ValueError, StopIteration, IndexError) as error:
        errors.append("missing/malformed raw witness: " + str(error))
    return errors


def main(argv=None):
    # Real host entry must refuse here, before parsing paths or using subprocess.
    try:
        marker = json.loads(Path("/etc/library-attempt.json").read_text())
        if marker["status"] != "ROOT_FROZEN_FOR_ATTEMPT" or marker["mode"] != "functional" or not re.fullmatch(r"lmb-l7-[a-zA-Z0-9-]+", marker["attempt_id"]) or hashlib.sha256(Path("/etc/os-release").read_bytes()).hexdigest() != "a9cf75cefad48006288dc08006822451b8e8b9939eb4fa7ca186eb4fccc0b2d4":
            raise ValueError("designated functional disposable guest required")
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.stderr.write("guest guard refused: " + str(error) + "\n")
        return 2
    return guest_main(marker, argv)


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _save(path, data):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.rename(path)


def _budget(deadline, cap=15):
    remaining = min(cap, deadline - time.monotonic())
    if remaining <= 0:
        raise TimeoutError("external/phase deadline exhausted")
    return remaining


def _run(argv, deadline, commands):
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    record = {"argv": argv, "cwd": "/", "env": env, "returncode": None, "stdout": None, "stderr": None}
    commands.append(record)
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                cwd="/", env=env,
                                timeout=_budget(deadline))
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        return record
    except subprocess.TimeoutExpired as error:
        record.update(failure="timeout", timeout_seconds=error.timeout)
        for name in ("stdout", "stderr"):
            value = getattr(error, name)
            record[name] = value.decode(errors="replace") if isinstance(value, bytes) else value
            if isinstance(value, bytes):
                record[name + "_hex"] = value.hex()
        # run owns direct-child timeout kill/wait. Its exception exposes neither
        # PID nor exit/reap observations; descendants are not checked here.
        record["process_outcome"] = {"owner": "subprocess.run", "policy": "kill and wait for direct child on timeout",
            "pid": None, "returncode": None, "reap_observation": "not exposed by subprocess.run",
            "descendant_cleanup": "not checked"}
        raise


def _tool(bpftool, arguments, deadline, commands):
    row = _run([bpftool, "-j", *arguments], deadline, commands)
    if row["returncode"] != 0:
        raise ValueError("bpftool failed: " + str(row))
    return json.loads(row["stdout"])


def _one(value):
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    if isinstance(value, dict):
        return value
    raise ValueError("expected exactly one owned kernel object")


def _raw_bytes(value, extent):
    if not isinstance(value, list) or len(value) != extent:
        raise ValueError("independent raw byte extent missing")
    result = bytearray()
    for byte in value:
        if isinstance(byte, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{2}", byte):
            byte = int(byte, 16)
        if type(byte) is not int or not 0 <= byte <= 255:
            raise ValueError("invalid independent raw byte")
        result.append(byte)
    return result.hex()


def _start_id(pid):
    # Parenthesized command names may themselves contain spaces or ')'.
    return Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[19]


def _owned_ids(pid, start):
    if _start_id(pid) != start:
        raise ValueError("child process identity changed")
    maps, programs = set(), set()
    for path in sorted(Path(f"/proc/{pid}/fdinfo").iterdir()):
        for line in path.read_text().splitlines():
            if line.startswith("map_id:"):
                maps.add(int(line.split(":", 1)[1]))
            if line.startswith("prog_id:"):
                programs.add(int(line.split(":", 1)[1]))
    if _start_id(pid) != start:
        raise ValueError("child process identity changed during FD read")
    return {"map_ids": sorted(maps), "program_ids": sorted(programs)}


def check_owned_metadata(owned, maps, programs):
    """Pure literal geometry and program-to-map association check."""
    if {m["id"] for m in maps} != set(owned["map_ids"]) or {p["id"] for p in programs} != set(owned["program_ids"]):
        raise ValueError("owned ID metadata mismatch")
    geometry = {m["name"]: (m["type"], m["bytes_key"], m["bytes_value"], m["max_entries"]) for m in maps}
    if len(maps) != 2 or geometry != {"counter": ("array", 4, 8, 1), "values": ("hash", 4, 8, 8)} or any(m.get("btf_id", 0) <= 0 for m in maps):
        raise ValueError("owned map/BTF geometry mismatch")
    bound = {m["name"]: m["id"] for m in maps}
    # Both maps are object-owned; only counter is referenced by the XDP code.
    if len(programs) != 1 or programs[0]["name"] != "lmb_map_live" or programs[0]["type"] != "xdp" or programs[0]["map_ids"] != [bound["counter"]]:
        raise ValueError("owned program/map association mismatch")
    return bound


def _lookup(bpftool, map_id, deadline, commands):
    row = _tool(bpftool, ["map", "lookup", "id", str(map_id), "key", "hex", "00", "00", "00", "00"], deadline, commands)
    if _raw_bytes(row["key"], 4) != "00000000":
        raise ValueError("independent lookup cursor changed")
    return _raw_bytes(row["value"], 8)


def _dump(bpftool, map_id, deadline, commands):
    rows = _tool(bpftool, ["map", "dump", "id", str(map_id)], deadline, commands)
    if not isinstance(rows, list):
        raise ValueError("independent dump did not return raw rows")
    result = {}
    for row in rows:
        key, value = _raw_bytes(row["key"], 4), _raw_bytes(row["value"], 8)
        if key in result or len(result) >= 8:
            raise ValueError("duplicate/unbounded independent dump")
        result[key] = value
    return result


def _absent(bpftool, kind, object_id, deadline, commands):
    row = _run([bpftool, "-j", kind, "show", "id", str(object_id)], deadline, commands)
    return check_absence_record(row, kind, object_id)


def check_absence_record(row, kind, object_id):
    """Only a pinned-tool ENOENT for the queried owned ID proves absence."""
    if row["returncode"] == 0:
        return False
    if type(row["returncode"]) is not int or not 1 <= row["returncode"] <= 255:
        raise ValueError("cleanup query did not complete with a native exit status")
    # An arbitrary nonzero, permission error or timeout is not absence evidence.
    try:
        error = json.loads(row["stdout"])["error"]
    except (ValueError, KeyError, TypeError):
        error = row["stderr"].strip().removeprefix("Error: ")
    if error != f"can't get {kind} by id ({object_id}): No such file or directory":
        raise ValueError("cleanup query failed without exact owned-ID ENOENT: " + str(row))
    return True


def _cleanup_ids(bpftool, owned, deadline, commands):
    limit = min(deadline, time.monotonic() + 15)
    missing_maps, missing_programs = set(), set()
    while time.monotonic() < limit:
        for column, kind, absent in (("map_ids", "map", missing_maps), ("program_ids", "prog", missing_programs)):
            for object_id in owned[column]:
                if object_id not in absent and _absent(bpftool, kind, object_id, limit, commands):
                    absent.add(object_id)
        if missing_maps == set(owned["map_ids"]) and missing_programs == set(owned["program_ids"]):
            return {"complete": True, "map_ids_absent": sorted(missing_maps), "program_ids_absent": sorted(missing_programs)}
        time.sleep(min(0.01, _budget(limit)))
    return {"complete": False, "map_ids_absent": sorted(missing_maps), "program_ids_absent": sorted(missing_programs)}


def _ack(directory, phase, accept):
    path = directory / (phase + ".ack")
    if path.exists():
        return
    temporary = path.with_suffix(".ack.tmp")
    temporary.write_text("continue\n" if accept else "abort\n")
    temporary.rename(path)


def _phase(process, directory, phase, deadline):
    limit = min(deadline, time.monotonic() + 15)
    path = directory / (phase + ".json")
    while not path.exists():
        if process.poll() is not None:
            raise ValueError("consumer exited before phase " + phase)
        time.sleep(min(0.005, _budget(limit)))
    actual = {p.stem for p in directory.glob("*.json") if p.name != "result.json"}
    expected = set(PHASES[:PHASES.index(phase) + 1])
    if actual != expected:
        raise ValueError("unexpected/out-of-order phase publication")
    return json.loads(path.read_text())


def _normalize_keys(consumer, phase, data):
    result = data.copy()
    if consumer == "stock":
        for name in {"keys-seeded": ("empty_first", "zero_next"), "keys-empty": ("empty_final", "array_next")}.get(phase, ()):
            if result.pop(name + "_code") != -2:
                raise ValueError("stock terminal native code was not exact ENOENT")
            result[name] = None
    return result


def run_row(name, consumer, executable, object_path, args, artifacts, identity, deadline):
    directory = Path(args.output) / name
    directory.mkdir(mode=0o700)
    control = directory / "control"
    control.mkdir(mode=0o700)
    record = {"consumer": consumer, "identity": identity.copy(), "artifacts": artifacts.copy(),
              "phases": [], "independent": {}, "commands": [], "owned": None, "cleanup": {"complete": False},
              "object_sha256": _sha(object_path), "exit_code": None}
    argv = [executable, object_path, str(control), str(control / "result.json")]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LD_LIBRARY_PATH": str(Path(args.bridge).parent),
           "LMB_NATIVE_LIB": args.bridge, "LMB_LIVE_DEADLINE_MONOTONIC_NS": str(int(deadline * 1e9))}
    record["launch"] = {"argv": argv, "env": env, "cwd": "/"}
    process, phase = None, None
    failed = None
    try:
        with (directory / "stdout").open("xb") as stdout, (directory / "stderr").open("xb") as stderr:
            try:
                process = subprocess.Popen(argv, cwd="/", env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                record["pid"] = process.pid
                record["start_id"] = _start_id(process.pid)
                bound = None
                keys = {}
                for phase in PHASES:
                    phase_limit = min(deadline, time.monotonic() + 15)
                    data = _phase(process, control, phase, phase_limit)
                    record["phases"].append(phase)
                    record.setdefault("phase_records", {})[phase] = data.copy()
                    if phase == "loaded":
                        record["owned"] = _owned_ids(process.pid, record["start_id"])
                        maps = [_one(_tool(args.bpftool, ["map", "show", "id", str(i)], phase_limit, record["commands"])) for i in record["owned"]["map_ids"]]
                        programs = [_one(_tool(args.bpftool, ["prog", "show", "id", str(i)], phase_limit, record["commands"])) for i in record["owned"]["program_ids"]]
                        bound = check_owned_metadata(record["owned"], maps, programs)
                        record["metadata"] = {"maps": maps, "programs": programs}
                    elif phase in ("initialized", "executed"):
                        raw = _lookup(args.bpftool, bound["counter"], phase_limit, record["commands"])
                        record[phase] = {**data, "raw": raw}
                        expected = "2900000000000000" if phase == "initialized" else "2a00000000000000"
                        if raw != expected or data["counter"] != int.from_bytes(bytes.fromhex(expected), "little"):
                            # Raw 43 is durable before abort closes the mutant's views.
                            _save(directory / "rejected-at-live-barrier.json", record)
                            raise ValueError("unchanged independent 41/42 oracle rejected at " + phase)
                    elif phase in ("keys-seeded", "key-deleted", "keys-empty"):
                        keys.update(_normalize_keys(consumer, phase, data))
                        label = {"keys-seeded": "seeded", "key-deleted": "deleted", "keys-empty": "empty"}[phase]
                        actual = _dump(args.bpftool, bound["values"], phase_limit, record["commands"])
                        record["independent"][label] = actual
                        expected = VALUES if phase == "keys-seeded" else ({k: v for k, v in VALUES.items() if k != "07000000"} if phase == "key-deleted" else {})
                        if actual != expected:
                            raise ValueError("independent HASH bytes differ at " + phase)
                        record["keys"] = keys.copy()
                    elif phase == "owner-released":
                        if consumer == "stock":
                            if data.pop("first_code") != -2:
                                raise ValueError("retained HASH end was not ENOENT")
                            data["first"] = None
                        record["retained"] = data
                        if _lookup(args.bpftool, bound["counter"], phase_limit, record["commands"]) != "2a00000000000000":
                            raise ValueError("ARRAY deletion/release changed the counter")
                    if phase != "closed":
                        if _owned_ids(process.pid, record["start_id"]) != record["owned"]:
                            raise ValueError("owned FD set changed before close")
                        _budget(phase_limit)
                        _ack(control, phase, True)
                record["exit_code"] = process.wait(timeout=_budget(deadline))
            finally:
                if process is not None and process.poll() is None:
                    if phase is not None and phase != "closed":
                        _ack(control, phase, False)
                    try:
                        process.wait(timeout=_budget(deadline, 2))
                    except (subprocess.TimeoutExpired, TimeoutError):
                        process.terminate()
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=1)
                if process is not None:
                    record["exit_code"] = process.returncode
    except BaseException as error:
        failed = error
        record["failure"] = {"class": type(error).__name__, "detail": str(error)}
    finally:
        try:
            if record["owned"] is not None:
                record["cleanup"] = _cleanup_ids(args.bpftool, record["owned"], deadline, record["commands"])
        except BaseException as error:
            record["cleanup"] = {"complete": False, "failure": str(error)}
        record["stdout"] = (directory / "stdout").read_text(errors="replace") if (directory / "stdout").exists() else None
        record["stderr"] = (directory / "stderr").read_text(errors="replace") if (directory / "stderr").exists() else None
        record["errors"] = validate_row(record, artifacts, identity)
        _save(directory / "row.json", record)
    if isinstance(failed, (KeyboardInterrupt, SystemExit)):
        raise failed
    return record


def _permission_negative(args, deadline, identity):
    command = [args.setpriv, "--reuid=1001", "--regid=1001", "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", args.stock_consumer, "--permission-negative", args.object]
    commands = []
    record = {"identity": identity.copy(), "commands": commands}
    try:
        row = _run(command, deadline, commands)
        actual = json.loads(row["stdout"])
        errors = validate_permission_negative(row, actual)
        if errors:
            raise ValueError("permission control failed: " + str(errors))
        return actual
    except BaseException as error:
        record["failure"] = {"class": type(error).__name__, "detail": str(error)}
        raise
    finally:
        _save(Path(args.output) / "permission-negative-raw.json", record)


def validate_permission_negative(command, actual):
    """A stdout-only load denial must include real dropped credentials/cleanup."""
    try:
        status = dict(line.split(":", 1) for line in actual["status_raw"].splitlines() if ":" in line)
        if command["returncode"] != 0 or actual["stage"] != "load" or actual["native_code"] not in (-1, -13) or actual["uid"] != 1001 or actual["euid"] != 1001 or list(map(int, status["Uid"].split())) != [1001] * 4 or any(int(status[name].strip(), 16) != 0 for name in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")) or status["Groups"].strip() or status["NoNewPrivs"].strip() != "1" or actual["bpf_fds_before_close"] != 0 or actual["bpf_fds_after_close"] != 0:
            return ["permission control did not establish genuine load denial and cleanup"]
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        return ["missing/malformed permission observation: " + str(error)]
    return []


def _raw_target(profile, witness):
    facts = witness["facts"]
    if _sha("/sys/kernel/notes") != profile["expected_facts"]["notes_sha256"] or _sha("/sys/kernel/btf/vmlinux") != profile["identity"]["btf_sha256"]:
        raise ValueError("direct same-boot raw notes/BTF changed")
    # Independently parse the running GNU notes and BTF section bounds.
    notes = Path("/sys/kernel/notes").read_bytes()
    cursor, build_id = 0, None
    while cursor + 12 <= len(notes):
        names, size, kind = struct.unpack_from("<III", notes, cursor)
        cursor += 12
        name_end = cursor + names
        if name_end > len(notes):
            raise ValueError("running note name truncated")
        name = notes[cursor:name_end].rstrip(b"\0")
        cursor += (names + 3) & ~3
        if cursor + size > len(notes):
            raise ValueError("running note description truncated")
        if name == b"GNU" and kind == 3:
            build_id = notes[cursor:cursor + size].hex()
        cursor += (size + 3) & ~3
    if build_id != profile["identity"]["kernel_build_id"]:
        raise ValueError("running build-id mismatch")
    btf = Path("/sys/kernel/btf/vmlinux").read_bytes()
    if len(btf) < 24:
        raise ValueError("BTF header missing")
    magic, version, flags, header, types, type_len, strings, string_len = struct.unpack_from("<HBBIIIII", btf)
    if (magic, version, flags) != (0xeb9f, 1, 0) or header < 24 or type_len == 0 or string_len == 0 or header + types + type_len > len(btf) or header + strings + string_len > len(btf) or btf[header + strings] != 0:
        raise ValueError("running BTF bounds/type/string sections invalid")
    for module in profile["expected_facts"]["modules"]:
        if not (Path("/sys/module") / module["name"]).is_dir() or _sha(Path("/sys/kernel/btf") / module["name"]) != module["btf_sha256"]:
            raise ValueError("running selected module/BTF mismatch")
    if Path("/proc/cpuinfo").read_text() != facts["cpu_raw"] or Path("/sys/kernel/security/lsm").read_text() != facts["policy"]["lsm"]["raw"] or Path("/sys/kernel/security/lockdown").read_text() != facts["policy"]["lockdown"]["raw"]:
        raise ValueError("raw CPU/policy changed since witness")
    if Path("/proc/sys/net/core/bpf_jit_enable").read_text() != facts["jit"]["raw"] or os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError("live JIT/credentials changed")
    current_status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    witness_status = dict(line.split(":", 1) for line in facts["status_raw"].splitlines() if ":" in line)
    if any(current_status[name].strip() != witness_status[name].strip() for name in ("Uid", "CapEff", "CapBnd", "NoNewPrivs")):
        raise ValueError("current credentials differ from raw witness")
    mountinfo = Path("/proc/self/mountinfo").read_text()
    if not any(line.split()[4] == "/sys/kernel/security" and line.split(" - ", 1)[1].split()[0] == "securityfs" for line in mountinfo.splitlines()):
        raise ValueError("actual securityfs mount unavailable")


def guest_main(marker, argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ROLES:
        parser.add_argument("--" + role.replace("_", "-"), required=True)
    parser.add_argument("--expected-profile", required=True)
    parser.add_argument("--expected-profile-sha256", required=True)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--deadline-monotonic-ns", type=int, required=True)
    args = parser.parse_args(argv)
    output, summary = Path(args.output), {"status": "FAIL", "rows": []}
    validated_output = False
    try:
        if not _digest(args.expected_profile_sha256) or _sha(args.expected_profile) != args.expected_profile_sha256:
            raise ValueError("externally fixed expected-profile hash mismatch")
        pins = [t.split("=", 1)[1] for t in Path("/proc/cmdline").read_text().split() if t.startswith("lmb_expected_sha256=")]
        if pins != [args.expected_profile_sha256]:
            raise ValueError("launch-bound expected-profile pin mismatch")
        profile, witness = json.loads(Path(args.expected_profile).read_text()), json.loads(Path(args.witness).read_text())
        identity = {"attempt": marker["attempt_id"], "hostname": Path("/proc/sys/kernel/hostname").read_text().strip(), "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "host_boot_id": profile["identity"]["host_boot_id"]}
        artifacts = {role: _sha(getattr(args, role)) for role in ROLES}
        errors = validate_witness(witness, profile, artifacts, identity, args.expected_profile_sha256)
        if identity["hostname"] != identity["attempt"] or platform.release() != profile["identity"]["kernel_release"] or platform.machine() != "x86_64" or sys.byteorder != "little" or errors:
            raise ValueError("pre-native witness/profile refusal: " + str(errors))
        for role, closure in profile["runtime_closure"].items():
            if str(Path(getattr(args, role)).resolve()) != closure["guest_path"]:
                raise ValueError("artifact path swapped: " + role)
            for node in closure["nodes"]:
                if _sha(node["guest_path"]) != node["sha256"]:
                    raise ValueError("actual runtime closure byte mismatch")
        _raw_target(profile, witness)
        deadline = args.deadline_monotonic_ns / 1e9
        if not 0 < deadline - time.monotonic() <= 900:
            raise ValueError("invalid external attempt deadline")
        # Only after all pre-native checks may this controller acquire output.
        if not output.is_dir() or output.is_symlink() or any(output.iterdir()) or output.stat().st_uid != os.getuid():
            raise ValueError("output must be an empty owned directory")
        validated_output = True
        args.output = str(output.resolve())
        stock = run_row("stock", "stock", args.stock_consumer, args.object, args, artifacts, identity, deadline)
        summary["rows"].append(stock)
        if stock["errors"]:
            raise ValueError("stock positive control failed")
        summary["permission_negative_raw"] = "permission-negative-raw.json"
        summary["permission_negative"] = _permission_negative(args, deadline, identity)
        mojo = run_row("mojo", "mojo", args.mojo_consumer, args.object, args, artifacts, identity, deadline)
        summary["rows"].append(mojo)
        if mojo["errors"] or mojo["keys"]["array_delete"] != stock["keys"]["array_delete"]:
            raise ValueError("typed row failed or ARRAY native refusal differs from stock")
        mutant = run_row("increment-two", "mojo", args.mojo_consumer, args.mutant_object, args, artifacts, identity, deadline)
        summary["rows"].append(mutant)
        executed = mutant.get("executed", {})
        if not mutant["errors"] or executed.get("counter") != 43 or executed.get("raw") != "2b00000000000000" or executed.get("retval") != 2 or executed.get("data_actual") != 60 or executed.get("ctx_actual") != 0 or mutant["exit_code"] != 3 or mutant.get("failure", {}).get("detail") != "unchanged independent 41/42 oracle rejected at executed" or not mutant["cleanup"].get("complete") or not (Path(args.output) / "increment-two/rejected-at-live-barrier.json").is_file():
            raise ValueError("actual increment-two rejection/independent 43/cleanup missing")
        if _sha(args.expected_profile) != args.expected_profile_sha256 or any(_sha(getattr(args, role)) != digest for role, digest in artifacts.items()):
            raise ValueError("input bytes changed during attempt")
        summary.update(status="PASS", scope="two C-produced-object consumer rows; rejected actual increment-two control; exact attempt only")
        return 0
    except BaseException as error:
        summary["failure"] = {"class": type(error).__name__, "detail": str(error)}
        sys.stderr.write("first live maps refused/failed: " + str(error) + "\n")
        return 3
    finally:
        if validated_output:
            _save(Path(args.output) / "result.json", summary)


if __name__ == "__main__":
    raise SystemExit(main())
