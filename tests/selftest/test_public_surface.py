#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""No public-surface name may come from the private `_ffi` module.

The top-level `libbpf_mojo` package re-exports every diagnostic
constant and read helper (see `src/libbpf_mojo/__init__.mojo`).
Any Mojo file outside `src/libbpf_mojo/` that imports one of
those names from `libbpf_mojo._ffi` fails this test. Intra-package
imports and white-box struct/handle imports stay allowed.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INIT = ROOT / "src/libbpf_mojo/__init__.mojo"
FROM_RE = re.compile(
    r"from\s+libbpf_mojo\._ffi\s+import\s+(?:\(([^)]*)\)|([A-Za-z_0-9,\s]+))",
    re.MULTILINE,
)


def public_names():
    text = INIT.read_text()
    names = set()
    for chunk in re.findall(
            r"from\s+libbpf_mojo\._ffi\s+import\s+\(([^)]*)\)", text):
        for name in chunk.replace("\n", " ").split(","):
            name = name.strip()
            if name:
                names.add(name)
    return names


class PublicSurfaceTests(unittest.TestCase):
    def test_reexports_cover_consumers(self):
        # Every name a downstream consumer needs must resolve at
        # the top level; this is the set memveil imports today.
        needed = {
            "ATTACH_TRACING", "DOMAIN_LIBBPF", "LOG_DISCARD",
            "LOG_ON_FAILURE", "OP_ATTACH", "OP_LOAD",
            "read_u16_le", "read_u32_le", "read_u64_le",
        }
        self.assertTrue(
            needed <= public_names(),
            "missing re-exports: %s" % sorted(needed - public_names()))

    def test_no_private_import_of_public_names(self):
        public = public_names()
        offenders = []
        roots = [ROOT / "tests", ROOT / "examples"]
        for base in roots:
            for path in sorted(base.rglob("*.mojo")):
                text = path.read_text()
                for match in FROM_RE.finditer(text):
                    chunk = match.group(1) or match.group(2) or ""
                    for name in chunk.replace("\n", " ").split(","):
                        name = name.strip()
                        if name in public:
                            offenders.append(
                                "%s imports %s from _ffi"
                                % (path.relative_to(ROOT), name))
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
