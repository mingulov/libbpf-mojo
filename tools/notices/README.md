<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Vendored third-party license texts

These files are the canonical license texts that `tools/package`
stages into binary distributions under `licenses/`. They are
**third-party material**, not this repository's own license
(which is still undecided): do not move them to the repository
root or rename them to look like project license files.

| File | Text | Provenance |
|---|---|---|
| `GPL-3.0.txt` | GNU GPL version 3 | Byte copy of Debian `common-licenses/GPL-3`, itself the FSF text |
| `GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt` | GCC Runtime Library Exception 3.1 | Byte copy of the pixi env text (both `gcc-libs` and `libstdc++` copies verified identical) |
| `ZLIB.txt` | zlib license | Extracted from the `zlib.h` 1.3.1 header comment; the bundled 1.3.2 carries identical terms |

Re-verify against the upstreams before use:

- `https://www.gnu.org/licenses/gpl-3.0.txt`
- `https://www.gnu.org/licenses/gcc-exception-3.1.txt`
- `https://zlib.net/zlib_license.html`

`tools/package` fails closed when the live pixi env's exception
texts differ from the vendored copy, so a toolchain upgrade that
changes the exception version breaks packaging loudly instead of
shipping stale notices.
