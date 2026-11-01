# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Release custody checks use synthetic metadata and never contact GitHub."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


def api():
    assert importlib.util.find_spec('release_custody'), 'release custody verifier missing'
    import release_custody
    return release_custody




def bundle(tmp_path, damage=None):
    import hashlib, io, json, tarfile
    files = {'lib/libbpf_mojo.so.1': b'synthetic-library', 'LICENSE': b'synthetic-license'}
    entries = [{'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in files.items()]
    manifest = {'package': 'libbpf-mojo', 'version': '0.0.0', 'build': {'receipt': {'git': 'b'*40}}, 'files': entries}
    if damage == 'duplicate': entries.append(entries[0])
    if damage == 'substitution': files['lib/libbpf_mojo.so.1'] += b'tampered'
    if damage == 'extra': files['extra.so'] = b'unsealed'
    if damage == 'source': manifest['build']['receipt']['git'] = 'c'*40
    files['MANIFEST.json'] = json.dumps(manifest).encode()
    path = tmp_path / 'synthetic.tar.gz'
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in files.items():
            entry = tarfile.TarInfo('synthetic/' + name); entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return path


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.owner.name)

    def tearDown(self):
        self.owner.cleanup()

    def test_artifact_requires_exact_same_repository_source_and_live_retention(self):
        record = {'id': 10, 'expired': False, 'digest': 'sha256:' + 'a'*64, 'name': 'candidate-' + 'b'*40,
                  'expires_at': '2099-01-01T00:00:00Z', 'workflow_run': {'id': 20, 'repository_id': 30,
                  'head_repository_id': 30, 'head_sha': 'b'*40}}
        m = api(); m.verify_artifact(record, '10', '20', '30', 'b'*40, 'a'*64)
        for key, value in [('id', 11), ('expired', True), ('digest', 'sha256:' + 'c'*64), ('expires_at', '2000-01-01T00:00:00Z')]:
            bad = copy.deepcopy(record); bad[key] = value
            with self.assertRaises(ValueError): m.verify_artifact(bad, '10', '20', '30', 'b'*40, 'a'*64)
        bad = copy.deepcopy(record); bad['workflow_run']['head_repository_id'] = 40
        with self.assertRaises(ValueError): m.verify_artifact(bad, '10', '20', '30', 'b'*40, 'a'*64)

    def test_tag_alone_never_rebuilds_or_publishes(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertNotIn('\n  push:', workflow)
        self.assertTrue('workflow_dispatch:' in workflow and 'ARM-' in workflow)
        self.assertIn('retention-days: 90', workflow)
        self.assertIn('release-custody', workflow)
        self.assertIn('build-candidate', workflow)
        promote = workflow.split('  promote:')[1]
        self.assertNotIn('tools/build', promote)
        self.assertNotIn('tools/package', promote)

    def test_complete_bundle_closure(self):
        self.assertEqual(api().verify_bundle(bundle(self.tmp_path), 'b'*40)['version'], '0.0.0')

    def check_damage(self, damage):
        with self.assertRaises(ValueError): api().verify_bundle(bundle(self.tmp_path, damage), 'b'*40)

    def test_duplicate(self): self.check_damage('duplicate')
    def test_substitution(self): self.check_damage('substitution')
    def test_extra(self): self.check_damage('extra')
    def test_source(self): self.check_damage('source')

    def test_unarmed_promote_does_not_touch_remote_or_files(self):
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'dispatch'):
                api().promote('promote', {}, self.tmp_path / 'out')
        self.assertFalse((self.tmp_path / 'out').exists())


if __name__ == '__main__': unittest.main(verbosity=2)
