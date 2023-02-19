#!/usr/bin/env python3

from PerfProf import PerfProf

def test_sched_switch(runtime, memleak_check):
    #perf-prof stat -e sched:sched_switch -i 1000 --period 100ms
    prof = PerfProf(["stat", '-e', 'sched:sched_switch', '--period', '100ms', '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_irq_off2(runtime, memleak_check):
    #perf-prof stat -e sched:sched_switch,sched:sched_wakeup -i 1000
    prof = PerfProf(["stat", '-e', 'sched:sched_switch,sched:sched_wakeup', '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT
