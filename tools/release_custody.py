#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Promote an immutable hosted candidate; never rebuild during promotion."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile


def need(condition, message):
    if not condition: raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''): h.update(block)
    return h.hexdigest()


def verify_artifact(record, artifact_id, run_id, repository_id, source, sha256):
    need(re.fullmatch('[0-9a-f]{40}', source) and re.fullmatch('[0-9a-f]{64}', sha256) and sha256 != '0'*64, 'invalid artifact identity')
    need(str(record.get('id')) == artifact_id and record.get('expired') is False and
         record.get('name') == 'candidate-' + source and record.get('digest') == 'sha256:' + sha256, 'wrong or expired candidate artifact')
    need(datetime.fromisoformat(record['expires_at'].replace('Z', '+00:00')) > datetime.now(timezone.utc), 'candidate artifact expired')
    run = record.get('workflow_run', {})
    need(str(run.get('id')) == run_id and str(run.get('repository_id')) == repository_id and
         str(run.get('head_repository_id')) == repository_id and run.get('head_sha') == source, 'candidate source/run/repository mismatch')


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', '-H', 'X-GitHub-Api-Version: 2022-11-28', path]))


def verify_bundle(path, source):
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers(); seen = set(); files = {}
        for item in members:
            parts = item.name.rstrip('/').split('/')
            need(all(p not in ('', '.', '..') for p in parts) and item.name not in seen and
                 (item.isfile() or item.isdir()), 'unsafe candidate archive')
            seen.add(item.name)
            if item.isfile(): files[item.name] = hashlib.sha256(archive.extractfile(item).read()).hexdigest()
        roots = {name.split('/')[0] for name in files}; need(len(roots) == 1, 'candidate archive roots differ')
        root = next(iter(roots)) + '/'
        manifest = json.load(archive.extractfile(root + 'MANIFEST.json'))
        need(manifest['package'] == 'libbpf-mojo' and manifest['build']['receipt']['git'] == source, 'bundle source differs')
        actual = {name[len(root):]: value for name, value in files.items() if name != root + 'MANIFEST.json'}
        expected = manifest['files']
        if isinstance(expected, list):
            need(len({entry['path'] for entry in expected}) == len(expected), 'duplicate bundle manifest entry')
            expected = {entry['path']: entry['sha256'] for entry in expected}
        need(actual == expected, 'bundle complete file closure differs')
        return manifest


def seal(directory):
    source = os.environ['GITHUB_SHA']; need(re.fullmatch('[0-9a-f]{40}', source), 'invalid source')
    directory = Path(directory)
    bundles = list(directory.glob('libbpf-mojo-*.tar.gz'))
    need(len(bundles) == 1, 'exactly one candidate bundle required')
    manifest = verify_bundle(bundles[0], source)
    record = {'schema': 'libbpf-mojo-hosted-candidate/1', 'origin': 'github-actions-build',
              'source_commit': source, 'run_id': os.environ['GITHUB_RUN_ID'],
              'repository': os.environ['GITHUB_REPOSITORY'], 'toolchain_lock_sha256': digest('toolchain.lock.json'),
              'files': {p.name: digest(p) for p in sorted(directory.iterdir()) if p.is_file()}}
    with open(directory / 'CANDIDATE.json', 'x') as stream: json.dump(record, stream, sort_keys=True); stream.write('\n')
    with open(directory / 'SHA256SUMS.txt', 'x') as stream:
        for path in sorted(directory.iterdir()):
            if path.name != 'SHA256SUMS.txt': stream.write(digest(path) + '  ' + path.name + '\n')


def promote(mode, request, destination):
    need(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
         os.environ.get('RELEASE_ARM') == 'ARM-' + mode.upper(), 'explicit promotion dispatch required')
    repo = os.environ['GITHUB_REPOSITORY']; source = request['source_commit']
    need(request['repository'] == repo and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo), 'wrong repository')
    for field in ('artifact_id', 'run_id'): need(re.fullmatch('[1-9][0-9]*', request[field]), 'invalid immutable ID')
    record = api('repos/' + repo + '/actions/artifacts/' + request['artifact_id'])
    verify_artifact(record, request['artifact_id'], request['run_id'], os.environ['GITHUB_REPOSITORY_ID'], source, request['artifact_sha256'])
    run = api('repos/' + repo + '/actions/runs/' + request['run_id'])
    need(run['status'] == 'completed' and run['conclusion'] == 'success' and run['event'] == 'workflow_dispatch' and
         run['path'] == '.github/workflows/release.yml' and run['head_sha'] == source, 'candidate workflow did not pass')
    destination = Path(destination); destination.mkdir(mode=0o700)
    archive = destination / 'candidate.zip'
    with open(archive, 'xb') as stream:
        subprocess.run(['gh', 'api', 'repos/' + repo + '/actions/artifacts/' + request['artifact_id'] + '/zip'], stdout=stream, check=True)
    need(digest(archive) == request['artifact_sha256'], 'stored candidate bytes changed')
    files = destination / 'files'; files.mkdir()
    with zipfile.ZipFile(archive) as stream:
        seen = set()
        for item in stream.infolist():
            need(re.fullmatch('[A-Za-z0-9_.-]+', item.filename) and item.filename not in seen and
                 not item.is_dir() and (item.external_attr >> 16) & 0o170000 in (0, 0o100000), 'unsafe stored artifact')
            seen.add(item.filename)
            with open(files / item.filename, 'xb') as output: output.write(stream.read(item))
    for path in files.iterdir():
        subprocess.run(['gh', 'attestation', 'verify', str(path), '--repo', repo,
                        '--signer-workflow', repo + '/.github/workflows/release.yml', '--signer-digest', source,
                        '--source-digest', source, '--deny-self-hosted-runners'], check=True)
    candidate = json.loads((files / 'CANDIDATE.json').read_text())
    need(candidate['schema'] == 'libbpf-mojo-hosted-candidate/1' and candidate['origin'] == 'github-actions-build' and
         candidate['source_commit'] == source and candidate['run_id'] == request['run_id'] and candidate['repository'] == repo, 'candidate provenance differs')
    actual = {p.name: digest(p) for p in files.iterdir() if p.name not in ('CANDIDATE.json', 'SHA256SUMS.txt')}
    need(actual == candidate['files'], 'candidate closure differs')
    sums = ''.join(digest(p) + '  ' + p.name + '\n' for p in sorted(files.iterdir()) if p.name != 'SHA256SUMS.txt')
    need((files / 'SHA256SUMS.txt').read_text() == sums, 'signed checksums differ')
    bundle = next(files.glob('libbpf-mojo-*.tar.gz')); manifest = verify_bundle(bundle, source)
    need(request['tag'] == 'v' + manifest['version'], 'tag/version mismatch')
    tag = request['tag']; need(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', tag), 'invalid tag')
    actual_source = subprocess.check_output(['git', 'rev-parse', 'refs/tags/' + tag + '^{commit}'], text=True).strip()
    need(actual_source == source, 'tag must point to candidate source')
    if mode == 'promote':
        args = ['gh', 'release', 'create', tag, '--repo', repo, '--verify-tag', '--draft', '--generate-notes']
        if tag.startswith('v0.') or '-' in tag: args.append('--prerelease')
        subprocess.run(args, check=True)
        subprocess.run(['gh', 'release', 'upload', tag, '--repo', repo, *[str(p) for p in sorted(files.iterdir())]], check=True)
        subprocess.run(['gh', 'release', 'edit', tag, '--repo', repo, '--draft=false'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('seal', 'promote', 'dry-run'))
    parser.add_argument('--directory', required=True)
    args = parser.parse_args()
    try:
        if args.mode == 'seal': seal(args.directory)
        else: promote(args.mode, json.loads(os.environ['RELEASE_REQUEST']), args.directory)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'release-custody: ' + str(error) + '\n')


if __name__ == '__main__': main()
