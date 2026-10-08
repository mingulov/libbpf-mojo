#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Required live-suite status must retain skips and every native outcome."""
import importlib.util
import json
import os
import shlex
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path


class Results(unittest.TestCase):
    def check(self, exits, expected):
        loader=SourceFileLoader('results',str(Path(__file__).resolve().parents[2]/'tools/qualification-results'))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'tools').mkdir()
            tool=root/'tools/test'
            tool.write_text('#!/bin/sh\ncase "$1" in\n'+''.join(f'{s}) exit {r};;\n' for s,r in exits.items())+'esac\n')
            tool.chmod(0o755)
            rc=module.run_suites(root,root/'out',list(exits))
            report=json.loads((root/'out/results.json').read_text())
            self.assertEqual(report['status'],expected)
            self.assertEqual(rc,0 if expected=='PASS' else 1)
            self.assertEqual([e['native_exit'] for e in report['lanes']],list(exits.values()))

    def test_all_skips_block(self): self.check(dict(a=77,b=77),'BLOCKED')
    def test_partial_skip_blocks(self): self.check(dict(a=77,b=0),'BLOCKED')
    def test_failure_retains_other_result(self): self.check(dict(a=1,b=0),'FAIL')
    def test_healthy_control(self): self.check(dict(a=0,b=0),'PASS')

class Descendants(unittest.TestCase):
    def test_timeout_reaps_separate_session(self):
        loader=SourceFileLoader('results_owned',str(Path(__file__).resolve().parents[2]/'tools/qualification-results'))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'tools').mkdir()
            pidfile=root/'child.pid'
            script="import os,time,pathlib;pathlib.Path(%r).write_text(str(os.getpid()));time.sleep(30)" % str(pidfile)
            tool=root/'tools/test'
            tool.write_text('#!/bin/sh\nsetsid '+shlex.quote(sys.executable)+' -c '+shlex.quote(script)+' &\nwait\n')
            tool.chmod(0o755)
            rc=module.run_suites(root,root/'out',['owned-timeout'],timeouts={'owned-timeout':0.3})
            self.assertEqual(rc,1)
            self.assertFalse((Path('/proc')/pidfile.read_text()).exists())
            receipt=json.loads((root/'out/results.json').read_text())
            self.assertEqual(receipt['lanes'][0]['cleanup']['remaining_owned'],0)

if __name__=='__main__':unittest.main()
