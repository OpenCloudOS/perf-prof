#!/usr/bin/env python3

from PerfProf import PerfProf

def test_sched_switch(runtime, memleak_check):
    prof = PerfProf(["hrtimer", '-e', 'sched:sched_switch', '-C', '0', '--period', '10ms', 'sched_switch==0'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_sched_switch_sched_wakeup(runtime, memleak_check):
    prof = PerfProf(["hrtimer", '-e', 'sched:sched_switch,sched:sched_wakeup', '-C', '0-1', '-F', '20', '-g', 'sched_switch==0 && sched_wakeup==0'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT
