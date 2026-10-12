#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Trusted schema-data acquisition; this does not validate result semantics."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import schema_bundle as sb


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lmb-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "supplied data"
        shutil.copytree(os.environ["LMB_TEST_CONTRACT_BUNDLE"], self.source)

    def manifest(self):
        return json.loads((self.source / "bundle.json").read_text())

    def write_manifest(self, data):
        (self.source / "bundle.json").write_text(json.dumps(data))

    def test_relocated_copy_and_independent_pin(self):
        acquired = self.root / "owned output"
        report = sb.acquire_bundle(self.source, acquired)
        self.assertEqual(report["canonical_sha256"],
                         "f26344f33e5efd863ece1ce59d8e19bf26daaae0c82b97074afd176ae7011ad7")
        expected = {"bundle.json", "cost.schema.json", "fixture.schema.json",
                    "result.schema.json", "run-plan.schema.json", "target.schema.json"}
        self.assertEqual({p.name for p in acquired.iterdir()}, expected)
        for name in expected:
            self.assertEqual((acquired / name).read_bytes(), (self.source / name).read_bytes())
        moved = self.root / "relocated"
        acquired.rename(moved)
        self.assertEqual(sb.verify_bundle(moved)["canonical_sha256"], report["canonical_sha256"])

    def test_missing_manifest_and_each_schema(self):
        for name in ["bundle.json", *self.manifest()["schemas"]]:
            path = self.source / name
            data = path.read_bytes()
            path.unlink()
            with self.assertRaises(sb.BundleError):
                sb.verify_bundle(self.source)
            path.write_bytes(data)

    def test_changed_schema_and_self_repinned_manifest(self):
        path = self.source / "cost.schema.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaises(sb.BundleError):
            sb.verify_bundle(self.source)
        manifest = self.manifest()
        manifest["schemas"][path.name]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_manifest(manifest)
        with self.assertRaises(sb.BundleError):
            sb.verify_bundle(self.source)

    def test_strict_integer_versions(self):
        original = self.manifest()
        for value in (True, False, 1.0, "1", 2):
            manifest = json.loads(json.dumps(original))
            manifest["version"] = value
            self.write_manifest(manifest)
            with self.assertRaises(sb.BundleError):
                sb.verify_bundle(self.source)
            manifest = json.loads(json.dumps(original))
            manifest["schemas"]["cost.schema.json"]["version"] = value
            self.write_manifest(manifest)
            with self.assertRaises(sb.BundleError):
                sb.verify_bundle(self.source)

    def test_exact_schema_set_and_no_path_escape(self):
        manifest = self.manifest()
        manifest["schemas"]["../outside.schema.json"] = manifest["schemas"].pop("cost.schema.json")
        self.write_manifest(manifest)
        with self.assertRaises(sb.BundleError):
            sb.verify_bundle(self.source)

    def test_symlink_root_parent_and_files(self):
        link = self.root / "linked"
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(sb.BundleError):
            sb.verify_bundle(link)
        with self.assertRaises(sb.BundleError):
            sb.verify_bundle(link / ".")
        path = self.source / "result.schema.json"
        outside = self.root / "outside"
        path.rename(outside)
        path.symlink_to(outside)
        with self.assertRaises(sb.BundleError):
            sb.verify_bundle(self.source)

    def test_duplicate_manifest_keys(self):
        original = (self.source / "bundle.json").read_text()
        (self.source / "bundle.json").write_text('{"version":1,' + original[1:])
        with self.assertRaises(sb.BundleError):
            sb.verify_bundle(self.source)

    def test_existing_output_remains_untouched(self):
        destination = self.root / "existing"
        destination.mkdir()
        (destination / "sentinel").write_bytes(b"preserve")
        with self.assertRaises(sb.BundleError):
            sb.acquire_bundle(self.source, destination)
        self.assertEqual((destination / "sentinel").read_bytes(), b"preserve")
        self.assertEqual([p.name for p in destination.iterdir()], ["sentinel"])

    def test_bad_input_creates_no_output(self):
        (self.source / "target.schema.json").write_bytes(b"{}")
        output = self.root / "refused"
        with self.assertRaises(sb.BundleError):
            sb.acquire_bundle(self.source, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    if not os.environ.get("LMB_TEST_CONTRACT_BUNDLE"):
        raise SystemExit("NOT_RUN contracts: set LMB_TEST_CONTRACT_BUNDLE to explicit offline data")
    unittest.main()
