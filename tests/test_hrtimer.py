#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_sched_switch(runtime, memleak_check):
    prof = PerfProf(["hrtimer", '-e', 'sched:sched_switch', '-C', '0', '--period', '10ms', 'sched_switch==0'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sched_switch_sched_wakeup(runtime, memleak_check):
    prof = PerfProf(["hrtimer", '-e', 'sched:sched_switch,sched:sched_wakeup', '-C', '0-1', '-F', '20', '-g', 'sched_switch==0 && sched_wakeup==0'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
