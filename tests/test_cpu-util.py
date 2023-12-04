#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_cpu_util(runtime, memleak_check):
    #perf-prof cpu-util -C 0 -i 1000
    prof = PerfProf(["cpu-util", '-C', '0', '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)