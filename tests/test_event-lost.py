#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_sched_wakeup(runtime, memleak_check):
    #perf-prof event-lost -e sched:sched_wakeup -m 64
    prof = PerfProf(["event-lost", '-e', 'sched:sched_wakeup', '-m', '64'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)