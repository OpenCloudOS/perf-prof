#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_sched_wakeup(runtime, memleak_check):
    #perf-prof event-lost -e sched:sched_wakeup -m 64
    prof = PerfProf(["event-lost", '-e', 'sched:sched_wakeup', '-m', '64'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)