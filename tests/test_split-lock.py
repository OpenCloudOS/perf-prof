#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_split_lock(runtime, memleak_check):
    #perf-prof split-lock -i 1000 --test
    prof = PerfProf(["split-lock", '-i', '1000', '--test'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_split_lock_T(runtime, memleak_check):
    #perf-prof split-lock -T 1000 --test
    prof = PerfProf(["split-lock", '-T', '1000', '--test'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)