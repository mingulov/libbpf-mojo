# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Exercise reviewed hash refresh without permitting inventory meaning drift."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_api_coverage as coverage

ROOT = Path(__file__).resolve().parents[2]


class SealRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        paths = set(coverage.IMPLEMENTATION_SOURCES) | {
            coverage.SNAPSHOT_PATH, coverage.SCHEMA_PATH,
            'docs/api-coverage.json', 'tests/selftest/test_api_coverage.py',
            'tools/refresh-api-seals',
        }
        for rel in paths:
            source = ROOT / rel
            if source.exists():
                target = self.root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)

    def run_refresh(self, *args):
        return subprocess.run(
            [sys.executable, str(self.root / 'tools/refresh-api-seals'), *args],
            capture_output=True, text=True)

    def mutate_inventory(self, mutate):
        path = self.root / 'docs/api-coverage.json'
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

    def test_reviewed_source_refresh_is_deterministic_and_valid(self):
        path = self.root / 'README.md'
        path.write_text(path.read_text() + '\nAdditional consumer guidance.\n')
        result = self.run_refresh('--reviewed-source', 'README.md', '--write')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        files = ['docs/api-coverage.json', 'tests/selftest/test_api_coverage.py']
        first = [(self.root / p).read_bytes() for p in files]
        result = self.run_refresh('--reviewed-source', 'README.md', '--write')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(first, [(self.root / p).read_bytes() for p in files])
        result = self.run_refresh('--check')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_unreviewed_source_change_refused_without_writes(self):
        path = self.root / 'README.md'
        path.write_text(path.read_text() + '\nNew guidance.\n')
        inventory = (self.root / 'docs/api-coverage.json').read_bytes()
        result = self.run_refresh('--write')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('README.md', result.stderr)
        self.assertEqual(inventory, (self.root / 'docs/api-coverage.json').read_bytes())

    def test_signature_and_mapping_changes_cannot_be_resealed(self):
        for mutate, reason in (
            (lambda c: c['bridge_abi']['exports'][0].__setitem__('signature', 'int changed(void);'),
             'source signature changed'),
            (lambda c: next(r for r in c['rows'] if r['id'] == 'function:bpf_map_lookup_elem')['forwarding_adapter']['restrictions'].append('unreviewed claim'),
             'source mapping/option disposition/restrictions changed'),
        ):
            with self.subTest(mutate=mutate):
                original = (self.root / 'docs/api-coverage.json').read_bytes()
                self.mutate_inventory(mutate)
                changed = (self.root / 'docs/api-coverage.json').read_bytes()
                result = self.run_refresh('--reviewed-source', 'README.md', '--write')
                self.assertNotEqual(0, result.returncode)
                self.assertIn('review required', result.stderr)
                self.assertIn(reason, result.stderr)
                self.assertEqual(changed, (self.root / 'docs/api-coverage.json').read_bytes())
                (self.root / 'docs/api-coverage.json').write_bytes(original)

    def test_schema_and_unknown_source_cannot_be_resealed(self):
        path = self.root / coverage.SCHEMA_PATH
        path.write_text(path.read_text() + '\n')
        result = self.run_refresh('--reviewed-source', 'README.md', '--write')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('review required', result.stderr)
        self.assertIn('immutable vocabulary seal mismatch', result.stderr)
        result = self.run_refresh('--reviewed-source', coverage.SCHEMA_PATH, '--write')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('unlisted sources', result.stderr)

    def test_abi_sources_require_contract_review(self):
        sources = ('native/include/libbpf_mojo.h',
                   'native/include/libbpf_mojo_generic.h',
                   'native/libbpf_mojo.map', 'tests/native/abi_v1_frozen.h')
        snapshots = {rel: (self.root / rel).read_bytes() for rel in sources + (
            'docs/api-coverage.json', 'tests/selftest/test_api_coverage.py')}
        for rel in sources:
            with self.subTest(source=rel):
                for source, raw in snapshots.items():
                    (self.root / source).write_bytes(raw)
                path = self.root / rel
                path.write_text(path.read_text() + '\n/* Changed contract. */\n')
                before = (self.root / 'docs/api-coverage.json').read_bytes()
                result = self.run_refresh('--reviewed-source', rel, '--write')
                self.assertNotEqual(0, result.returncode)
                self.assertIn('ABI sources require contract review', result.stderr)
                self.assertEqual(before, (self.root / 'docs/api-coverage.json').read_bytes())

    def test_reviewed_anchors_refresh_mapping_and_abi_hashes(self):
        def anchors(value, rel):
            found = []
            if isinstance(value, dict):
                if value.get('path') == rel and 'span_sha256' in value:
                    found.append(value)
                for child in value.values():
                    found.extend(anchors(child, rel))
            elif isinstance(value, list):
                for child in value:
                    found.extend(anchors(child, rel))
            return found

        sources = ('native/src/ring_stage.h', 'tests/native/check_exports.sh')
        snapshots = {rel: (self.root / rel).read_bytes() for rel in sources + (
            'docs/api-coverage.json', 'tests/selftest/test_api_coverage.py')}
        for rel in sources:
            with self.subTest(source=rel):
                for source, raw in snapshots.items():
                    (self.root / source).write_bytes(raw)
                before = json.loads(snapshots['docs/api-coverage.json'])
                old = anchors(before, rel)
                self.assertTrue(old, 'fixture must exercise real inventory anchors')
                path = self.root / rel
                path.write_bytes(path.read_bytes() + b'\n')
                result = self.run_refresh('--reviewed-source', rel, '--write')
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                after = json.loads((self.root / 'docs/api-coverage.json').read_text())
                refs = anchors(after, rel)
                self.assertEqual(len(old), len(refs))
                for original, updated in zip(old, refs):
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), updated['sha256'])
                    self.assertNotEqual(original['sha256'], updated['sha256'])
                    self.assertEqual(original['span_sha256'], updated['span_sha256'])
                result = self.run_refresh('--check')
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
