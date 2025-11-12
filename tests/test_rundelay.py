#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_rundelay(runtime, memleak_check):
    #perf-prof rundelay -e sched:sched_wakeup*,sched:sched_switch -e sched:sched_switch -i 1000 -m 256 --perins
    prof = PerfProf(["rundelay", '-e', 'sched:sched_wakeup*,sched:sched_switch',
                     '-e', 'sched:sched_switch', '-i', '1000', '-m', '256', '--perins'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_rundelay_p1(runtime, memleak_check):
    #perf-prof rundelay -e sched:sched_wakeup*,sched:sched_switch -e sched:sched_switch -p 1 -i 1000 --than 4ms --detail=samekey
    prof = PerfProf(["rundelay", '-e', 'sched:sched_wakeup*,sched:sched_switch',
                     '-e', 'sched:sched_switch', '-p', '1', '-i', '1000', '--than', '4ms', '--detail=samekey'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_rundelay_filter_python(runtime, memleak_check):
    #perf-prof rundelay -e sched:sched_wakeup*,sched:sched_switch -e sched:sched_switch --filter python -i 1000 --than 4ms --detail=samekey
    prof = PerfProf(["rundelay", '-e', 'sched:sched_wakeup*,sched:sched_switch',
                     '-e', 'sched:sched_switch', '--filter', 'python', '-i', '1000', '--than', '4ms', '--detail=samekey'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_rundelay_filter_python_perins(runtime, memleak_check):
    #perf-prof rundelay -e sched:sched_wakeup*,sched:sched_switch -e sched:sched_switch --filter python -i 1000 --than 4ms --detail=samekey --perins
    prof = PerfProf(["rundelay", '-e', 'sched:sched_wakeup*,sched:sched_switch',
                     '-e', 'sched:sched_switch', '--filter', 'python', '-i', '1000', '--than', '4ms', '--detail=samekey', '--perins'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_rundelay_filter_python_profile(runtime, memleak_check):
    #perf-prof rundelay -e sched:sched_wakeup*,sched:sched_switch -e 'sched:sched_switch,profile/-F 500 --watermark 50 -m 16 -g/untraced/'
    #--filter python -i 1000 --than 4ms --detail=samecpu
    prof = PerfProf(["rundelay", '-e', 'sched:sched_wakeup*,sched:sched_switch',
                     '-e', 'sched:sched_switch,profile/-F 500 --watermark 50 -m 16 -g/untraced/', '--filter', 'python', '-i', '1000', '--than', '4ms', '--detail=samecpu'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
