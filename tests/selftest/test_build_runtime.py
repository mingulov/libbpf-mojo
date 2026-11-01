#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Development runtime layout preserves pre-existing filesystem entries."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BuildRuntime(unittest.TestCase):
    def test_create_repeat_and_refuse_conflicting_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            top = Path(tmp)
            sdk = top / "SDK runtime"
            sdk.mkdir()
            (sdk / "runtime.so").write_bytes(b"runtime marker")
            for state in ("absent", "file", "directory", "symlink", "dangling"):
                with self.subTest(state=state):
                    build = top / state
                    build.mkdir()
                    link = build / "lib"
                    if state == "file":
                        link.write_bytes(b"preserve me")
                    elif state == "directory":
                        link.mkdir()
                        (link / "owned").write_bytes(b"preserve me")
                    elif state in ("symlink", "dangling"):
                        link.symlink_to(top if state == "symlink" else top / "missing")
                    before = link.lstat() if state != "absent" else None
                    command = [sys.executable, str(ROOT / "tools/build_runtime.py"), str(build), str(sdk)]
                    result = subprocess.run(command, capture_output=True, text=True)
                    if state == "absent":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertTrue(link.is_symlink())
                        self.assertFalse(link.readlink().is_absolute())
                        self.assertEqual((link / "runtime.so").read_bytes(), b"runtime marker")
                        inode = link.lstat().st_ino
                        repeat = subprocess.run(command, capture_output=True, text=True)
                        self.assertEqual(repeat.returncode, 0, repeat.stderr)
                        self.assertEqual(link.lstat().st_ino, inode)
                    else:
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertIn("refusing existing", result.stderr)
                        after = link.lstat()
                        self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns, after.st_size),
                                         (before.st_ino, before.st_mode, before.st_mtime_ns, before.st_size))
                        if state == "file":
                            self.assertEqual(link.read_bytes(), b"preserve me")
                        elif state == "directory":
                            self.assertEqual((link / "owned").read_bytes(), b"preserve me")


if __name__ == "__main__":
    unittest.main()
