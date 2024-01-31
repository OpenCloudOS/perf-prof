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

def test_sched_switch_wakeup_cpus(runtime, memleak_check):
    #perf-prof hrcount -e sched:sched_switch,sched:sched_wakeup//cpus=0-2/ --period 200ms -i 1000 --perins
    prof = PerfProf(["hrcount", '-e', 'sched:sched_switch,sched:sched_wakeup//cpus=0-2/', '--period', '200ms','-i', '1000', '--perins'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_sched_switch_wakeup_cpu0(runtime, memleak_check):
    #perf-prof hrcount -e sched:sched_switch//cpus=0/,sched:sched_wakeup/target_cpu==0/ --period 100ms -i 1000
    prof = PerfProf(["hrcount", '-e', 'sched:sched_switch//cpus=0/,sched:sched_wakeup/target_cpu==0/', '--period', '100ms','-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
