#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Host-only real-wrapper transactions over sealed synthetic build artifacts.

No compiler, loader or runtime qualification. Real notice/manifest/source checks
run over a synthetic conda package; readelf alone supplies synthetic DT_NEEDED.
Faults are injected in child Python processes via a private sitecustomize.
Set LMB_TRANSACTION_EVIDENCE to retain commands, logs and archive identities.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import provenance


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


INJECT = '''import gzip, os, signal, tarfile
mode = os.environ.get("LMB_TRANSACTION_FAULT", "")
def fault():
    print("INJECTED " + mode, file=__import__('sys').stderr, flush=True)
    if mode in ("int-parent", "term-parent"):
        os.kill(os.getppid(), signal.SIGINT if mode == "int-parent" else signal.SIGTERM)
        return
    if mode in ("int", "term"):
        os.killpg(0, signal.SIGINT if mode == "int" else signal.SIGTERM)
        raise KeyboardInterrupt("injected interrupt")
    raise OSError("injected " + mode)
if mode in ("add", "int", "term", "int-parent", "term-parent"):
    original = tarfile.TarFile.addfile
    def add(self, info, fileobj=None):
        original(self, info, fileobj)
        fault()
    tarfile.TarFile.addfile = add
elif mode in ("tar-close", "gzip-close"):
    cls = tarfile.TarFile if mode == "tar-close" else gzip.GzipFile
    original = cls.close
    def close(self):
        active = not (getattr(self, "closed", False) if mode == "tar-close" else self.fileobj is None)
        original(self)
        if active:
            fault()
    cls.close = close
elif mode == "write":
    original = gzip.GzipFile.write
    def write(self, data):
        original(self, data[:max(1, len(data) // 2)])
        fault()
    gzip.GzipFile.write = write
elif mode == "raw-close":
    import builtins
    original = builtins.open
    class RawClose:
        def __init__(self, raw): self.raw = raw
        def __getattr__(self, key): return getattr(self.raw, key)
        def __enter__(self): return self
        def __exit__(self, *args):
            self.raw.close()
            fault()
    def open_file(path, mode="r", *args, **kwargs):
        raw = original(path, mode, *args, **kwargs)
        if mode == "wb" and ".tar.gz" in str(path):
            return RawClose(raw)
        return raw
    builtins.open = open_file
elif mode == "replace":
    os.replace = lambda *args, **kwargs: fault()
'''


class PackageTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='package-transaction-')
        cls.base = Path(cls.tmp.name)
        cls.tree = cls.base / 'source'
        # Copy the declared source inventory, without Git or development outputs.
        for rel in provenance.archive_files(str(ROOT)):
            src = ROOT / rel
            dst = cls.tree / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        cls.envroot = cls.tree / '.pixi/envs/default'
        runtime = b'synthetic runtime bytes\n'
        write(cls.envroot / 'lib/libz.so.1', runtime)
        meta = {'name': 'libzlib', 'version': '1.0', 'build': 'fixture',
                'license': 'Zlib', 'url': 'https://example.invalid/synthetic',
                'sha256': '0' * 64, 'files': ['lib/libz.so.1']}
        write(cls.envroot / 'conda-meta/libzlib.json', json.dumps(meta).encode())
        cls.cache = cls.base / 'pkgs'
        write(cls.cache / 'libzlib-1.0-fixture/info/paths.json', json.dumps({
            'paths': [{'_path': 'lib/libz.so.1', 'sha256': digest(runtime)}]
        }).encode())
        for name in ('gcc-libs', 'libstdc++'):
            write(cls.envroot / 'share/licenses' / name / 'RUNTIME.LIBRARY.EXCEPTION',
                  (ROOT / 'tools/notices/GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt').read_bytes())
        build = cls.tree / 'build'
        artifacts = {}
        for rel in ('libbpf_mojo.so.1', 'examples/tracepoint_main',
                    'examples/tracepoint_trigger', 'examples/probe.bpf.o',
                    'examples/reference_consumer'):
            data = ('synthetic artifact ' + rel + '\n').encode()
            write(build / rel, data)
            artifacts[rel] = digest(data)
        write(build / 'libbpf_external-prefix/src/libbpf_external/LICENSE.BSD-2-Clause',
              b'synthetic libbpf license fixture\n')
        receipt = {'cmake_cache_sha256': 'fixture-no-native-configuration',
                   'artifacts': artifacts,
                   'sources': provenance.source_manifest(str(cls.tree), 'archive')}
        write(build / 'build-receipt.json', json.dumps(receipt).encode())
        cls.bin = cls.base / 'bin'
        readelf = cls.bin / 'readelf'
        write(readelf, b'#!/usr/bin/env bash\ncase "$2" in *libz.so.1) ;; *) echo " (NEEDED) [libz.so.1]" ;; esac\n')
        readelf.chmod(0o755)
        for tool in ('rm', 'sha256sum'):
            real = shutil.which(tool)
            script = ('#!/usr/bin/env bash\n'
                      'if [ "${LMB_TRANSACTION_SHELL_FAULT:-}" = "' + tool + '" ]; then\n'
                      '  echo "INJECTED ' + tool + '" >&2; exit 1\n'
                      'fi\nexec ' + real + ' "$@"\n')
            write(cls.bin / tool, script.encode())
            (cls.bin / tool).chmod(0o755)
        cls.inject = cls.base / 'injection'
        write(cls.inject / 'sitecustomize.py', INJECT.encode())
        cls.evidence = os.environ.get('LMB_TRANSACTION_EVIDENCE')
        if cls.evidence:
            Path(cls.evidence).mkdir(parents=True, exist_ok=True)
            write(Path(cls.evidence) / 'fixture.json', json.dumps({
                'receipt': receipt, 'readelf_sha256': digest(readelf.read_bytes()),
                'injection_sha256': digest(INJECT.encode()),
                'package_sha256': digest((cls.tree / 'tools/package').read_bytes()),
            }, indent=2, sort_keys=True).encode())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.out = self.base / self.id().rsplit('.', 1)[-1]
        self.out.mkdir()
        self.final = self.out / 'libbpf-mojo-0.2.0.tar.gz'
        # A readable sentinel archive with an independent predecessor payload.
        stream = io.BytesIO()
        with gzip.GzipFile(fileobj=stream, mode='wb', mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w') as tar:
                info = tarfile.TarInfo('previous-generation.txt')
                data = b'independent predecessor generation\n'
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        self.sentinel = stream.getvalue()
        self.final.write_bytes(self.sentinel)
        self.unrelated = self.out / '.unrelated.tmp'
        self.unrelated.write_bytes(b'leave alone')

    def run_package(self, mode='', label=None, shell_fault=''):
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                   PYTHONPATH=str(self.inject), PYTHONDONTWRITEBYTECODE='1',
                   SOURCE_DATE_EPOCH='1234567890', LMB_CONDA_PKGS=str(self.cache),
                   LMB_TRANSACTION_FAULT=mode, LMB_BUILD_DIR='build',
                   LMB_TRANSACTION_SHELL_FAULT=shell_fault)
        cmd = ['bash', str(self.tree / 'tools/package'), '--out', str(self.out)]
        result = subprocess.run(cmd, cwd=self.tree, env=env, capture_output=True,
                                text=True, start_new_session=True, timeout=30)
        paths = {str(p.relative_to(self.out)): (digest(p.read_bytes()) if p.is_file() else 'directory')
                 for p in sorted(self.out.rglob('*'))}
        record = {'argv': cmd, 'fault': mode, 'shell_fault': shell_fault, 'returncode': result.returncode,
                  'predecessor_sha256': digest(self.sentinel), 'output_paths': paths,
                  'stdout': result.stdout, 'stderr': result.stderr}
        if self.evidence:
            name = self.id().rsplit('.', 1)[-1] + (('-' + label) if label else ('-' + mode if mode else ''))
            write(Path(self.evidence) / (name + '.json'),
                  json.dumps(record, indent=2, sort_keys=True).encode())
        return result

    def assert_failed_transaction(self, mode, predecessor=True):
        if not predecessor:
            self.final.unlink()
        result = self.run_package(mode)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('INJECTED ' + mode, result.stderr)
        self.assertEqual(self.unrelated.read_bytes(), b'leave alone')
        if predecessor:
            self.assertEqual(digest(self.final.read_bytes()), digest(self.sentinel),
                             'predecessor bytes lost after ' + mode)
        else:
            self.assertFalse(self.final.exists(), 'failed attempt published final artifact')
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         sorted(['.unrelated.tmp'] + ([self.final.name] if predecessor else [])))

    def test_member_failure_preserves_predecessor(self):
        self.assert_failed_transaction('add')

    def test_tar_finalization_failure_preserves_predecessor(self):
        self.assert_failed_transaction('tar-close')

    def test_gzip_finalization_failure_preserves_predecessor(self):
        self.assert_failed_transaction('gzip-close')

    def test_interrupt_preserves_predecessor(self):
        self.assert_failed_transaction('int')

    def test_termination_preserves_predecessor(self):
        self.assert_failed_transaction('term')

    def test_rename_failure_preserves_predecessor(self):
        self.assert_failed_transaction('replace')

    def test_parent_interrupt_preserves_predecessor(self):
        self.assert_failed_transaction('int-parent')

    def test_parent_termination_preserves_predecessor(self):
        self.assert_failed_transaction('term-parent')

    def test_partial_write_failure_preserves_predecessor(self):
        self.assert_failed_transaction('write')

    def test_raw_close_failure_preserves_predecessor(self):
        self.assert_failed_transaction('raw-close')

    def test_failures_without_predecessor(self):
        for mode in ('add', 'write', 'tar-close', 'gzip-close', 'raw-close',
                     'int', 'term', 'int-parent', 'term-parent', 'replace'):
            with self.subTest(fault=mode):
                self.final.write_bytes(self.sentinel)
                self.assert_failed_transaction(mode, False)

    def test_cleanup_failure_is_observable(self):
        result = self.run_package('add', shell_fault='rm')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot clean temporary archive', result.stderr)
        self.assertIn('cannot clean staging directory', result.stderr)
        self.assertEqual(self.final.read_bytes(), self.sentinel)
        self.assertTrue(list(self.out.glob('.libbpf-mojo-*.tar.gz.*')))
        self.assertTrue(list(self.out.glob('stage.*')))

    def test_postpublication_cleanup_failure_retains_complete_new_archive(self):
        result = self.run_package(shell_fault='rm')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot clean staging directory', result.stderr)
        self.assertNotEqual(self.final.read_bytes(), self.sentinel)
        with tarfile.open(self.final) as archive:
            self.assertIn('libbpf-mojo-0.2.0/MANIFEST.json', archive.getnames())

    def test_postpublication_checksum_failure_retains_complete_new_archive(self):
        result = self.run_package(shell_fault='sha256sum')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('INJECTED sha256sum', result.stderr)
        self.assertNotEqual(self.final.read_bytes(), self.sentinel)
        with tarfile.open(self.final) as archive:
            self.assertIn('libbpf-mojo-0.2.0/MANIFEST.json', archive.getnames())
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ['.unrelated.tmp', self.final.name])

    def test_successful_replacement_is_complete_and_deterministic(self):
        result = self.run_package(label='first')
        self.assertEqual(result.returncode, 0, result.stderr)
        mask = os.umask(0)
        os.umask(mask)
        self.assertEqual(stat.S_IMODE(self.final.stat().st_mode), 0o666 & ~mask)
        first = self.final.read_bytes()
        self.assertNotEqual(first, self.sentinel)
        with tarfile.open(self.final) as archive:
            members = archive.getmembers()
            self.assertTrue(all(m.mtime == 1234567890 and m.uid == m.gid == 0 for m in members))
            prefix = 'libbpf-mojo-0.2.0/'
            manifest = json.load(archive.extractfile(prefix + 'MANIFEST.json'))
            for row in manifest['files']:
                self.assertEqual(digest(archive.extractfile(prefix + row['path']).read()), row['sha256'])
            self.assertIn(prefix + 'LICENSES/LLVM-exception.txt', archive.getnames())
        result = self.run_package(label='second')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.final.read_bytes(), first)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ['.unrelated.tmp', self.final.name])

    def test_success_without_predecessor(self):
        self.final.unlink()
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.final) as archive:
            self.assertIn('libbpf-mojo-0.2.0/MANIFEST.json', archive.getnames())


if __name__ == '__main__':
    unittest.main(verbosity=2)
