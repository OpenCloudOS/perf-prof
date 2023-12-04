#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_profile_g(runtime, memleak_check):
    #perf-prof profile -F 997 -C 0 -m 32 -g
    prof = PerfProf(["profile", '-F', '997', '-C', '0', '-m', '32', '-g'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_profile_exclude_user(runtime, memleak_check):
    #perf-prof profile -F 997 -C 0 -m 32 --exclude-user --watermark 50 -g --flame-graph profile
    prof = PerfProf(["profile", '-F', '997', '-C', '0', '-m', '32', '--exclude-user', '--watermark', '50', '-g', '--flame-graph', 'profile'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

