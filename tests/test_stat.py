#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_sched_switch(runtime, memleak_check):
    #perf-prof stat -e sched:sched_switch -i 1000 --period 100ms
    prof = PerfProf(["stat", '-e', 'sched:sched_switch', '--period', '100ms', '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sched_switch_wakeup(runtime, memleak_check):
    #perf-prof stat -e sched:sched_switch,sched:sched_wakeup -i 1000
    prof = PerfProf(["stat", '-e', 'sched:sched_switch,sched:sched_wakeup', '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
