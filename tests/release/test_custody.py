# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Release custody checks use synthetic metadata and never contact GitHub."""
import copy
import importlib.util
from pathlib import Path
import sys
import pytest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


def api():
    assert importlib.util.find_spec('release_custody'), 'release custody verifier missing'
    import release_custody
    return release_custody


def test_artifact_requires_exact_same_repository_source_and_live_retention():
    record = {'id': 10, 'expired': False, 'digest': 'sha256:' + 'a'*64, 'name': 'candidate-' + 'b'*40,
              'expires_at': '2099-01-01T00:00:00Z', 'workflow_run': {'id': 20, 'repository_id': 30,
              'head_repository_id': 30, 'head_sha': 'b'*40}}
    m = api(); m.verify_artifact(record, '10', '20', '30', 'b'*40, 'a'*64)
    for key, value in [('id', 11), ('expired', True), ('digest', 'sha256:' + 'c'*64), ('expires_at', '2000-01-01T00:00:00Z')]:
        bad = copy.deepcopy(record); bad[key] = value
        with pytest.raises(ValueError): m.verify_artifact(bad, '10', '20', '30', 'b'*40, 'a'*64)
    bad = copy.deepcopy(record); bad['workflow_run']['head_repository_id'] = 40
    with pytest.raises(ValueError): m.verify_artifact(bad, '10', '20', '30', 'b'*40, 'a'*64)


def test_tag_alone_never_rebuilds_or_publishes():
    workflow = (ROOT / '.github/workflows/release.yml').read_text()
    assert '\n  push:' not in workflow
    assert 'workflow_dispatch:' in workflow and 'ARM-' in workflow
    assert 'retention-days: 90' in workflow
    assert 'release-custody' in workflow
    assert 'build-candidate' in workflow
    promote = workflow.split('  promote:')[1]
    assert 'tools/build' not in promote and 'tools/package' not in promote


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


def test_complete_bundle_closure(tmp_path):
    assert api().verify_bundle(bundle(tmp_path), 'b'*40)['version'] == '0.0.0'


@pytest.mark.parametrize('damage', ['duplicate', 'substitution', 'extra', 'source'])
def test_changed_bundle_refuses(tmp_path, damage):
    with pytest.raises(ValueError): api().verify_bundle(bundle(tmp_path, damage), 'b'*40)


def test_unarmed_promote_does_not_touch_remote_or_files(tmp_path, monkeypatch):
    monkeypatch.delenv('RELEASE_ARM', raising=False)
    with pytest.raises(ValueError, match='dispatch'):
        api().promote('promote', {}, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()
