# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Pure independent rejection examples; never start a native tool or a guest."""
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("first_live_maps", HERE / "standard_objects/test_first_live_maps.py")
CHECKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKS)


def example():
    artifacts = {name: digit * 64 for name, digit in (
        ("object", "1"), ("mutant_object", "2"), ("stock_consumer", "3"),
        ("mojo_consumer", "4"), ("bridge", "5"), ("bpftool", "6"), ("setpriv", "7"))}
    attempt = {"attempt": "map-test-unique", "hostname": "map-test-unique",
               "boot_id": "dfce27b8-671e-4a00-96ac-975ac9b49631",
               "host_boot_id": "c51423db-2670-46e9-8f85-f737ba296c5a"}
    profile = {
        "schema_version": 1, "profile_id": "linux7-x86_64-le-tcg-map-v1",
        "admission": "accepted", "identity": {
            "attempt": attempt["attempt"], "hostname": attempt["hostname"], "host_boot_id": attempt["host_boot_id"],
            "boot_id_rule": "fresh-not-host-or-prior", "kernel_release": "7.0.0-38-generic", "architecture": "x86_64",
            "endian": "little", "execution_class": "tcg", "userspace_cpu": "x86-64-v2",
            "glibc": "2.43", "cpu_flags": ["fpu", "cx8", "cmov", "mmx", "fxsr", "sse", "sse2", "lm", "pni", "ssse3", "sse4_1", "sse4_2", "popcnt", "cx16", "lahf_lm"],
            "online_cpus": 1, "rootfs_sha256": "8" * 64, "btf_sha256": "9" * 64,
            "kernel_build_id": "a" * 40, "capabilities": ["bpf", "array", "hash", "xdp_test_run"]},
        "artifacts": artifacts.copy(), "runtime_closure": {name: {"guest_path": "/opt/map-test/" + name,
            "sha256": digest, "closure_sha256": "b" * 64,
            "nodes": [{"guest_path": "/opt/map-test/" + name, "sha256": digest, "needed": []}]}
            for name, digest in artifacts.items()},
        "expected_facts": {"notes_sha256": "c" * 64, "config_sha256": "925f5500d35b300e7db909dcd7b350ebe8d639a2166f20c516d36b84bb26e7a9",
            "modules": [{"name": name, "btf_sha256": "e" * 64} for name in ("netfs", "9pnet", "9pnet_virtio", "9p")],
            "policy": {"lsm_raw": "capability,landlock,lockdown,yama,apparmor,bpf\n", "lockdown_raw": "[none] integrity confidentiality\n"}},
        "previous_boot_ids": []}
    kernel_end = {"operation": 19, "domain": 3, "code": -2}
    row = {"identity": attempt.copy(), "artifacts": artifacts.copy(), "consumer": "mojo",
        "object_sha256": "1" * 64,
        "phases": ["loaded", "initialized", "executed", "keys-seeded", "key-deleted", "keys-empty", "owner-released", "closed"],
        "initialized": {"counter": 41, "raw": "2900000000000000"},
        "executed": {"counter": 42, "raw": "2a00000000000000", "retval": 2, "data_actual": 60, "ctx_actual": 0, "duration_ns": 0},
        "keys": {"empty_first": None, "zero_first": "00000000", "zero_next": None,
            "seeded": ["ffffffff", "00000000", "07000000"], "calls": 4,
            "terminal": {"kind": "typed_none"}, "restart": "ffffffff", "first": "ffffffff",
            "after_delete": ["ffffffff", "00000000"], "after_calls": 3,
            "after_terminal": {"kind": "typed_none"}, "empty_final": None,
            "missing_delete": {"operation": 18, "domain": 3, "code": -2},
            "missing_lookup": {"operation": 7, "domain": 3, "code": -2},
            "array_first": "00000000", "array_next": None, "array_restart": "00000000", "array_delete": -22},
        "independent": {"seeded": {"00000000": "efcdab8967452301", "07000000": "1032547698badcfe", "ffffffff": "8877665544332211"},
            "deleted": {"00000000": "efcdab8967452301", "ffffffff": "8877665544332211"}, "empty": {}},
        "retained": {"counter": 42, "first": None}, "exit_code": 0,
        "owned": {"map_ids": [101, 102], "program_ids": [103]},
        "cleanup": {"map_ids_absent": [101, 102], "program_ids_absent": [103], "complete": True}}
    for closure in profile["runtime_closure"].values():
        closure["closure_sha256"] = hashlib.sha256(json.dumps(closure["nodes"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return profile, artifacts, attempt, row


def witness(p, a, e):
    identity = {**p["identity"], "boot_id": e["boot_id"]}
    identity.pop("boot_id_rule")
    identity.pop("capabilities")
    status = "Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nNoNewPrivs:\t0\n"
    facts = {"release": identity["kernel_release"], "build_id": identity["kernel_build_id"],
        "boot_id": identity["boot_id"], "hostname": identity["hostname"], "uid": 0, "euid": 0,
        "status_raw": status, "rlimits": {"MEMLOCK": [-1, -1], "NOFILE": [1024, 1024]},
        "cpu_raw": "flags\t: " + " ".join(identity["cpu_flags"]), "cpu_flags": identity["cpu_flags"],
        "architecture": "x86_64", "byte_order": "little", "cpus": 1, "page_size": 4096,
        "meminfo": "MemTotal: 750000 kB\n", "glibc_raw": "glibc 2.43", "glibc": "2.43",
        "jit": {"status": "read", "raw": "1\n"}, "jit_harden": {"status": "read", "raw": "0\n"},
        "notes_sha256": p["expected_facts"]["notes_sha256"], "btf_sha256": identity["btf_sha256"], "btf_errors": [],
        "config_sha256": p["expected_facts"]["config_sha256"], "config_raw": "CONFIG_BPF_JIT_ALWAYS_ON=y\n",
        "policy": {"mountinfo": "25 1 0:1 / /sys/kernel/security rw - securityfs securityfs rw\n",
            "acquisition": {"returncode": 0, "owned": True},
            "lsm": {"status": "read", "raw": p["expected_facts"]["policy"]["lsm_raw"]},
            "lockdown": {"status": "read", "raw": p["expected_facts"]["policy"]["lockdown_raw"]}},
        "modules": [{**row, "loaded": True} for row in p["expected_facts"]["modules"]],
        "consumed_files": [{"guest_path": row["guest_path"], "actual_sha256": row["sha256"], "expected_sha256": row["sha256"], "match": True} for closure in p["runtime_closure"].values() for row in closure["nodes"]]}
    return {"schema_version": 1, "profile_id": p["profile_id"], "admission": "observed", "mode": "functional",
        "expected_sha256": "a" * 64, "identity": identity, "artifacts": a.copy(),
        "runtime_closure": copy.deepcopy(p["runtime_closure"]), "facts": facts,
        "external_custody_reference_fields": ["identity.host_boot_id", "identity.rootfs_sha256", "identity.execution_class"]}


class Profiles(unittest.TestCase):
    def test_portable_profile_is_candidate(self):
        data = json.loads((HERE / "target_profiles.json").read_text())
        self.assertEqual("CANDIDATE", data["status"])
        self.assertEqual("NOT_RUN", data["runtime_qualification"])
        self.assertEqual([7, 0], data["kernel_min"])

    def test_positive_profile(self):
        p, a, e, _ = example()
        self.assertEqual([], CHECKS.validate_profile(p, a, e))

    def test_contradictory_profiles(self):
        cases = [
            ("missing profile", lambda p, a, e: p.clear()),
            ("missing artifact", lambda p, a, e: a.pop("bridge")),
            ("producer only", lambda p, a, e: p["identity"].update(kernel_release="6.12.1")),
            ("wrong cpu", lambda p, a, e: p["identity"].update(architecture="aarch64")),
            ("wrong endian", lambda p, a, e: p["identity"].update(endian="big")),
            ("wrong class", lambda p, a, e: p["identity"].update(execution_class="kvm")),
            ("wrong profile", lambda p, a, e: p.update(profile_id="producer-6.12")),
            ("missing closure", lambda p, a, e: p["runtime_closure"].pop("mojo_consumer")),
            ("cpu floor", lambda p, a, e: p["identity"].update(userspace_cpu="x86-64")),
            ("cpu feature", lambda p, a, e: p["identity"]["cpu_flags"].remove("cx16")),
            ("glibc floor", lambda p, a, e: p["identity"].update(glibc="2.37")),
            ("wrong guest", lambda p, a, e: p["identity"].update(hostname="other")),
            ("wrong attempt", lambda p, a, e: p["identity"].update(attempt="other")),
            ("host boot", lambda p, a, e: e.update(boot_id=e["host_boot_id"])),
            ("stale boot", lambda p, a, e: p.update(previous_boot_ids=[e["boot_id"]])),
            ("swapped object", lambda p, a, e: a.update(object=a["mutant_object"])),
            ("swapped bridge", lambda p, a, e: a.update(bridge=a["stock_consumer"])),
            ("swapped consumer", lambda p, a, e: a.update(mojo_consumer=a["stock_consumer"])),
            ("unaccepted", lambda p, a, e: p.update(admission="candidate")),
            ("boolean schema", lambda p, a, e: p.update(schema_version=True)),
            ("boolean CPU count", lambda p, a, e: p["identity"].update(online_cpus=True)),
            ("unresolved edge", lambda p, a, e: p["runtime_closure"]["bridge"]["nodes"][0]["needed"].append("/missing/loader")),
            ("edited closure seal", lambda p, a, e: p["runtime_closure"]["bridge"].update(closure_sha256="f" * 64)),
        ]
        for name, change in cases:
            p, a, e, _ = copy.deepcopy(example())
            change(p, a, e)
            with self.subTest(name=name):
                self.assertTrue(CHECKS.validate_profile(p, a, e), name)

    def test_positive_unordered_keys(self):
        _, a, e, r = example()
        self.assertEqual([], CHECKS.validate_row(r, a, e))

    def test_contradictory_rows(self):
        cases = [
            ("missing phase", lambda r: r["phases"].remove("executed")),
            ("duplicate phase", lambda r: r["phases"].insert(3, "executed")),
            ("zero sentinel", lambda r: r["keys"].update(zero_first=None)),
            ("wrong set", lambda r: r["keys"]["seeded"].__setitem__(0, "01000000")),
            ("duplicate keys", lambda r: r["keys"]["seeded"].__setitem__(0, "00000000")),
            ("unbounded traversal", lambda r: r["keys"].update(calls=5)),
            ("wrong diagnostic", lambda r: r["keys"].update(terminal={"operation": 7, "domain": 3, "code": -2})),
            ("stale diagnostic", lambda r: r["keys"].update(terminal={"operation": 19, "domain": 4, "code": -2})),
            ("edited bytes", lambda r: r["executed"].update(raw="2b00000000000000")),
            ("mutant 43", lambda r: r["executed"].update(counter=43, raw="2b00000000000000")),
            ("wrong guest", lambda r: r["identity"].update(boot_id="other")),
            ("wrong artifact", lambda r: r["artifacts"].update(object="f" * 64)),
            ("missing deletion", lambda r: r["independent"]["deleted"].update({"07000000": "1032547698badcfe"})),
            ("missing cleanup", lambda r: r["cleanup"].update(complete=False)),
            ("wrong cleanup id", lambda r: r["cleanup"].update(map_ids_absent=[999, 102])),
            ("successful array delete", lambda r: r["keys"].update(array_delete=0)),
            ("retained lost", lambda r: r["retained"].update(counter=0)),
            ("actual object swap", lambda r: r.update(object_sha256="2" * 64)),
        ]
        for name, change in cases:
            _, a, e, r = copy.deepcopy(example())
            change(r)
            with self.subTest(name=name):
                self.assertTrue(CHECKS.validate_row(r, a, e), name)

    def test_actual_witness_contract(self):
        p, a, e, _ = example()
        self.assertEqual([], CHECKS.validate_witness(witness(p, a, e), p, a, e, "a" * 64))

    def test_false_or_missing_raw_witness_facts(self):
        cases = [
            ("witness only", lambda w: w.update(mode="witness-only")),
            ("self admission", lambda w: w.update(admission="accepted")),
            ("edited expectation", lambda w: w.update(expected_sha256="b" * 64)),
            ("wrong uid", lambda w: w["facts"].update(uid=1001)),
            ("missing caps", lambda w: w["facts"].update(status_raw="Uid:\t0\nCapEff:\t0000000000000000\n")),
            ("jit unavailable", lambda w: w["facts"].update(jit={"status": "missing", "raw": None})),
            ("securityfs absent", lambda w: w["facts"]["policy"].update(mountinfo="")),
            ("securityfs acquisition failed", lambda w: w["facts"]["policy"]["acquisition"].update(returncode=1)),
            ("lsm unreadable", lambda w: w["facts"]["policy"]["lsm"].update(status="unreadable")),
            ("lockdown active", lambda w: w["facts"]["policy"]["lockdown"].update(raw="none [integrity] confidentiality\n")),
            ("missing notes", lambda w: w["facts"].update(notes_sha256=None)),
            ("btf parse failure", lambda w: w["facts"].update(btf_errors=["bounds"])),
            ("module absent", lambda w: w["facts"]["modules"][0].update(loaded=False)),
            ("consumed swapped", lambda w: w["facts"]["consumed_files"][0].update(actual_sha256="f" * 64)),
            ("cpu raw contradiction", lambda w: w["facts"].update(cpu_raw="flags: sse\n")),
            ("stale proc boot", lambda w: w["identity"].update(boot_id="other")),
            ("closure edited", lambda w: w["runtime_closure"]["bridge"]["nodes"][0].update(sha256="f" * 64)),
            ("config bytes edited", lambda w: w["facts"].update(config_raw="CONFIG_BPF=n\n")),
        ]
        for name, change in cases:
            p, a, e, _ = example()
            w = witness(p, a, e)
            change(w)
            with self.subTest(name=name):
                self.assertTrue(CHECKS.validate_witness(w, p, a, e, "a" * 64), name)

    def test_real_host_entry_refuses_before_native(self):
        with mock.patch.object(CHECKS.subprocess, "Popen", side_effect=AssertionError("native launch")), mock.patch.object(CHECKS.subprocess, "run", side_effect=AssertionError("native launch")):
            self.assertEqual(2, CHECKS.main([]))

    def test_designated_guest_entry_dispatches_without_native_work(self):
        marker = {"status": "ROOT_FROZEN_FOR_ATTEMPT", "mode": "functional", "attempt_id": "lmb-l7-pure-guard"}
        root = b'ID=mojobpf-disposable\nPRETTY_NAME="MojoBPF owned package-file root"\n'
        calls = []

        def read_text(path, *args, **kwargs):
            self.assertEqual(Path("/etc/library-attempt.json"), path)
            return json.dumps(marker)

        def read_bytes(path):
            self.assertEqual(Path("/etc/os-release"), path)
            return root

        def guest_entry(actual_marker, argv):
            calls.append((actual_marker, argv))
            return 37

        with mock.patch.object(Path, "read_text", read_text), mock.patch.object(Path, "read_bytes", read_bytes), mock.patch.object(CHECKS, "guest_main", guest_entry), mock.patch.object(CHECKS.subprocess, "Popen", side_effect=AssertionError("native launch")), mock.patch.object(CHECKS.subprocess, "run", side_effect=AssertionError("native launch")):
            self.assertEqual(37, CHECKS.main(["--pure-dispatch-only"]))
        self.assertEqual([(marker, ["--pure-dispatch-only"])], calls)

    def test_guest_entry_refuses_wrong_marker_mode_attempt_or_root(self):
        valid = {"status": "ROOT_FROZEN_FOR_ATTEMPT", "mode": "functional", "attempt_id": "lmb-l7-pure-guard"}
        root = b'ID=mojobpf-disposable\nPRETTY_NAME="MojoBPF owned package-file root"\n'
        cases = [
            ("missing marker", None, root),
            ("unfrozen marker", {**valid, "status": "CANDIDATE"}, root),
            ("witness only", {**valid, "mode": "witness-only"}, root),
            ("wrong attempt", {**valid, "attempt_id": "host"}, root),
            ("wrong root", valid, root + b"CHANGED=1\n"),
        ]
        for name, marker, root_bytes in cases:
            def read_text(path, *args, **kwargs):
                self.assertEqual(Path("/etc/library-attempt.json"), path)
                if marker is None:
                    raise FileNotFoundError("missing disposable marker")
                return json.dumps(marker)

            with self.subTest(name=name), mock.patch.object(Path, "read_text", read_text), mock.patch.object(Path, "read_bytes", return_value=root_bytes), mock.patch.object(CHECKS, "guest_main", side_effect=AssertionError("invalid guest dispatch")), mock.patch.object(CHECKS.subprocess, "Popen", side_effect=AssertionError("native launch")), mock.patch.object(CHECKS.subprocess, "run", side_effect=AssertionError("native launch")):
                self.assertEqual(2, CHECKS.main([]))

    def test_permission_timeout_persists_attempt_and_partial_output_as_failure(self):
        # Keep real guest_main, _permission_negative, _run and atomic _save.
        # Replace only pre-native target observations, the stock row and run's
        # external process boundary. This observes persistence, never cleanup.
        with tempfile.TemporaryDirectory(prefix="lmb-pure-permission-") as temporary:
            base = Path(temporary)
            output = base / "results"
            output.mkdir()
            p, a, e, row = example()
            e.update(attempt="lmb-l7-pure-timeout", hostname="lmb-l7-pure-timeout")
            p["identity"].update(attempt=e["attempt"], hostname=e["hostname"])
            paths = {}
            for role in CHECKS.ROLES:
                path = base / role
                path.write_text("pure artifact " + role)
                paths[role] = str(path)
                a[role] = hashlib.sha256(path.read_bytes()).hexdigest()
                nodes = [{"guest_path": str(path), "sha256": a[role], "needed": []}]
                p["runtime_closure"][role] = {"guest_path": str(path), "sha256": a[role], "nodes": nodes,
                    "closure_sha256": hashlib.sha256(json.dumps(nodes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
            p["artifacts"] = a.copy()
            profile = base / "profile.json"
            profile.write_text(json.dumps(p))
            pin = hashlib.sha256(profile.read_bytes()).hexdigest()
            w = witness(p, a, e)
            w["expected_sha256"] = pin
            observed = base / "witness.json"
            observed.write_text(json.dumps(w))
            argv = [item for role, path in paths.items() for item in ("--" + role.replace("_", "-"), path)]
            argv += ["--expected-profile", str(profile), "--expected-profile-sha256", pin,
                     "--witness", str(observed), "--output", str(output), "--deadline-monotonic-ns", "110000000000"]
            row.update(identity=e.copy(), artifacts=a.copy(), object_sha256=a["object"], errors=[])
            real_read_text = Path.read_text
            raw_reads = {"/proc/cmdline": "lmb_expected_sha256=" + pin,
                         "/proc/sys/kernel/hostname": e["hostname"] + "\n",
                         "/proc/sys/kernel/random/boot_id": e["boot_id"] + "\n"}

            def read_text(path, *args, **kwargs):
                return raw_reads[str(path)] if str(path) in raw_reads else real_read_text(path, *args, **kwargs)

            partial_out, partial_err = b'{"stage":"load",', b"partial verifier\xff\n"
            timeout = CHECKS.subprocess.TimeoutExpired([paths["setpriv"]], 10, output=partial_out, stderr=partial_err)
            with mock.patch.object(Path, "read_text", read_text), mock.patch.object(CHECKS.platform, "release", return_value="7.0.0-38-generic"), mock.patch.object(CHECKS.platform, "machine", return_value="x86_64"), mock.patch.object(CHECKS, "_raw_target", return_value=None), mock.patch.object(CHECKS, "run_row", return_value=row), mock.patch.object(CHECKS.time, "monotonic", return_value=100), mock.patch.object(CHECKS.subprocess, "Popen", side_effect=AssertionError("native launch")), mock.patch.object(CHECKS.subprocess, "run", side_effect=timeout):
                self.assertEqual(3, CHECKS.guest_main({"attempt_id": e["attempt"]}, argv))
            summary = json.loads((output / "result.json").read_text())
            self.assertEqual("FAIL", summary["status"])
            self.assertEqual("TimeoutExpired", summary["failure"]["class"])
            self.assertNotIn("permission_negative", summary)
            raw = output / "permission-negative-raw.json"
            self.assertTrue(raw.is_file(), "timeout command and partial captures must survive")
            self.assertEqual(raw.name, summary["permission_negative_raw"])
            record = json.loads(raw.read_text())
            self.assertEqual(e, record["identity"])
            self.assertEqual("TimeoutExpired", record["failure"]["class"])
            self.assertEqual(1, len(record["commands"]))
            command = record["commands"][0]
            self.assertEqual([paths["setpriv"], "--reuid=1001", "--regid=1001", "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", paths["stock_consumer"], "--permission-negative", paths["object"]], command["argv"])
            self.assertEqual("/", command["cwd"])
            self.assertEqual({"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, command["env"])
            self.assertEqual("timeout", command["failure"])
            self.assertEqual(10, command["timeout_seconds"])
            self.assertEqual(partial_out.decode(), command["stdout"])
            self.assertEqual(partial_err.decode(errors="replace"), command["stderr"])
            self.assertEqual(partial_out.hex(), command["stdout_hex"])
            self.assertEqual(partial_err.hex(), command["stderr_hex"])
            self.assertIsNone(command["returncode"])
            self.assertEqual({"owner": "subprocess.run", "policy": "kill and wait for direct child on timeout",
                "pid": None, "returncode": None, "reap_observation": "not exposed by subprocess.run",
                "descendant_cleanup": "not checked"}, command["process_outcome"])

    def test_permission_refusal_is_stage_and_credentials_bound(self):
        status = "Uid:\t1001\t1001\t1001\t1001\nGroups:\t\nCapEff:\t0\nCapPrm:\t0\nCapInh:\t0\nCapAmb:\t0\nCapBnd:\t0\nNoNewPrivs:\t1\n"
        command = {"returncode": 0}
        actual = {"stage": "load", "native_code": -1, "uid": 1001, "euid": 1001,
                  "bpf_fds_before_close": 0, "bpf_fds_after_close": 0, "status_raw": status}
        self.assertEqual([], CHECKS.validate_permission_negative(command, actual))
        cases = [
            ("open denial", lambda c, a: a.update(stage="open")),
            ("parse denial", lambda c, a: a.update(native_code=-22)),
            ("generic nonzero", lambda c, a: c.update(returncode=3)),
            ("wrong uid", lambda c, a: a.update(uid=0)),
            ("effective caps", lambda c, a: a.update(status_raw=status.replace("CapEff:\t0", "CapEff:\t1"))),
            ("no-new-privileges absent", lambda c, a: a.update(status_raw=status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"))),
            ("owned fds leaked", lambda c, a: a.update(bpf_fds_after_close=1)),
            ("status absent", lambda c, a: a.pop("status_raw")),
        ]
        for name, change in cases:
            c, a = copy.deepcopy(command), copy.deepcopy(actual)
            change(c, a)
            with self.subTest(name=name):
                self.assertTrue(CHECKS.validate_permission_negative(c, a), name)

    def test_owned_kernel_metadata_uses_bpftool_byte_geometry(self):
        owned = {"map_ids": [101, 102], "program_ids": [103]}
        maps = [{"id": 101, "name": "counter", "type": "array", "bytes_key": 4, "bytes_value": 8, "max_entries": 1, "btf_id": 104},
                {"id": 102, "name": "values", "type": "hash", "bytes_key": 4, "bytes_value": 8, "max_entries": 8, "btf_id": 104}]
        programs = [{"id": 103, "name": "lmb_map_live", "type": "xdp", "map_ids": [101]}]
        try:
            actual = CHECKS.check_owned_metadata(owned, maps, programs)
        except ValueError as error:
            self.fail("the counter-only fixture must pass: " + str(error))
        self.assertEqual({"counter": 101, "values": 102}, actual)
        for name, change in [
            ("foreign map", lambda m, p: m[0].update(id=999)),
            ("wrong value extent", lambda m, p: m[1].update(bytes_value=4)),
            ("missing counter", lambda m, p: p[0].update(map_ids=[])),
            ("foreign association", lambda m, p: p[0].update(map_ids=[999])),
            ("HASH only", lambda m, p: p[0].update(map_ids=[102])),
            ("extra HASH association", lambda m, p: p[0].update(map_ids=[101, 102])),
            ("duplicate counter association", lambda m, p: p[0].update(map_ids=[101, 101])),
            ("missing BTF", lambda m, p: m[1].pop("btf_id")),
        ]:
            m, p = copy.deepcopy(maps), copy.deepcopy(programs)
            change(m, p)
            with self.subTest(name=name), self.assertRaises(ValueError):
                CHECKS.check_owned_metadata(owned, m, p)

    def test_cleanup_requires_exact_owned_id_enoent(self):
        absent = {"returncode": 255, "stdout": json.dumps({"error": "can't get map by id (101): No such file or directory"}), "stderr": ""}
        self.assertTrue(CHECKS.check_absence_record(absent, "map", 101))
        self.assertFalse(CHECKS.check_absence_record({"returncode": 0, "stdout": "{}", "stderr": ""}, "map", 101))
        for name, change in [
            ("foreign id", lambda row: row.update(stdout=json.dumps({"error": "can't get map by id (999): No such file or directory"}))),
            ("permission denied", lambda row: row.update(stdout=json.dumps({"error": "can't get map by id (101): Operation not permitted"}))),
            ("generic nonzero", lambda row: row.update(stdout="{}", stderr="error")),
            ("no native status", lambda row: row.update(returncode=None)),
        ]:
            row = copy.deepcopy(absent)
            change(row)
            with self.subTest(name=name), self.assertRaises(ValueError):
                CHECKS.check_absence_record(row, "map", 101)


if __name__ == "__main__":
    unittest.main()
