#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Explicit isolated-guest probe gates; no fixture executes without arming."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    if os.environ.get('LMB_ISOLATED_TEST_GUEST') != '1':
        print('NOT_RUN live-probes: requires LMB_ISOLATED_TEST_GUEST=1 in an isolated test guest')
        return 77
    if os.geteuid() != 0:
        print('FAIL live-probes: selected guest requires collection privilege')
        return 1
    build = ROOT / os.environ.get('LMB_BUILD_DIR', 'build')
    mode = os.environ.get('LMB_PROBE_MODE', 'positive')
    if mode not in ('positive', 'blacklist', 'lockdown'):
        print('FAIL live-probes: unknown mode')
        return 2
    args = [str(build / 'live_probe_lifecycle'), str(build / 'fixtures/probe_lifecycle.bpf.o'), '--' + mode]
    if mode == 'blacklist':
        symbol = os.environ.get('LMB_PROBE_BLACKLIST_SYMBOL', '')
        try:
            lines = Path('/sys/kernel/debug/kprobes/blacklist').read_text().splitlines()
        except OSError:
            print('FAIL live-probes: blacklist is unreadable')
            return 1
        symbols = {parts[1] for line in lines if len(parts := line.split()) >= 2}
        if not symbol or symbol not in symbols:
            print('FAIL live-probes: selected symbol is not in the observed kernel blacklist')
            return 1
        args.append(symbol)
    if mode == 'lockdown':
        try:
            active = Path('/sys/kernel/security/lockdown').read_text()
        except OSError:
            active = ''
        if '[confidentiality]' not in active:
            print('FAIL live-probes: confidentiality lockdown is not active')
            return 1
    rc = subprocess.run(args, check=False).returncode
    if rc:
        return rc if rc > 0 else 1
    if mode == 'positive':
        rc = subprocess.run([str(build / 'examples/probe_lifecycle_mojo'),
                             str(build / 'fixtures/probe_lifecycle.bpf.o'),
                             str(build / 'libbpf_mojo.so.1')], check=False).returncode
        if rc:
            return rc if rc > 0 else 1
    print('PASS live-probes selected-mode=' + mode)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
