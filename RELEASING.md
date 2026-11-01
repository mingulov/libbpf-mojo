<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Releasing

Tags do not build or publish. The manually dispatched release workflow has
separate `build-candidate`, `dry-run` and `promote` modes, each explicitly armed.
The `release-custody` environment must have the repository's required reviewer
and branch protections configured before remote use.

A hosted build creates a new candidate with its own actual output hashes. It
cannot inherit qualification from a local build or an earlier workflow run.
The build runs the required suites, packages once for retention, and tests
that exact archive through the installed consumer and compiler-free clean
room without a subsequent rebuild. Skipped required suites fail the job.
`tools/release-custody seal --directory dist` records truthful hosted build
origin, source, toolchain lock, complete file digests and corresponding source.
GitHub signs build provenance for the exact retained files. Artifact retention
is 90 days; expired artifacts require a newly qualified candidate.

Promotion takes a reviewed request containing `repository`, `source_commit`,
`run_id`, `artifact_id`, `artifact_sha256` and `tag`. It downloads by immutable
artifact ID, verifies same-repository run/source identity, signed provenance,
checksums, complete bundle files and version, and requires the existing tag
to point to that source. Dry-run runs those validations without writing a
release. Promotion first creates a draft, uploads stored bytes without
replacement, and publishes only after upload succeeds. Existing releases or
conflicting assets fail; interrupted drafts require separately reviewed
cleanup. `v0.*` and hyphenated versions remain prereleases.

Use `tools/release-custody --help` for the local verifier interface. Real
remote dispatch, release creation, attestation verification and protection
configuration require their own authorization and recorded evidence. Local
fixture tests do not prove those remote controls. Consumers continue to pin
exact versions and archive hashes; this workflow changes no consumer pin.
