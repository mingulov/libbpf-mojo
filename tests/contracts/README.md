<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Portable test schema data

This test-only helper acquires five `mojobpf-test-contracts` schemas from
an explicit offline data directory. It trusts the canonical manifest digest
and exact schema hashes in [bundle-lock.json](bundle-lock.json), independently
of the supplied manifest. Canonical JSON uses sorted keys, compact separators,
ASCII encoding and `ensure_ascii=True`; the pin is
`f26344f33e5efd863ece1ce59d8e19bf26daaae0c82b97074afd176ae7011ad7`.
This is a canonical digest, rather than the raw `bundle.json` digest.

An installed MojoBPF package can export the data through its public
`mojobpf.validation.export_schema_bundle` function. Supply the resulting
directory as `LMB_TEST_CONTRACT_BUNDLE`; the library tests import no publisher
code and require no sibling checkout or network fallback:

```sh
LMB_TEST_CONTRACT_BUNDLE=/path/to/schema-data ./tools/test contracts
python3 tests/contracts/schema_bundle.py /path/to/schema-data /new/owned/output
```

The helper checks the exact schema set, integer versions and bytes, rejects
symlink paths and duplicate keys, copies only the manifest and five schemas
into a fresh output directory, then verifies the copy. Missing input is
`NOT_RUN` with a nonzero exit, not a passing acquisition test.

Acquisition establishes data identity only. It does not validate arbitrary
result semantics or strict expected/observed equality. A runtime result needs
its separately admitted semantic validator. These files and the controlled
host test libraries are absent from shipping runtime packages.
