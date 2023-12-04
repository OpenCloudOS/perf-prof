#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_watchdog(runtime, memleak_check):
    #perf-prof watchdog -F 10 -g
    prof = PerfProf(["watchdog", '-F', '10', '-g'])
    thresh = int(PerfProf.sysctl('kernel.watchdog_thresh'))
    for std, line in prof.run(runtime+thresh, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)