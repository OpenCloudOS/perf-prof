#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_rundelay_p1(runtime, memleak_check):
    #perf-prof rundelay -e sched:sched_wakeup,sched:sched_wakeup_new,sched:sched_switch//key=prev_pid/ -e sched:sched_switch//key=next_pid/ -k pid --order -p 1 -i 1000 --than 4ms
    prof = PerfProf(["rundelay", '-e', 'sched:sched_wakeup,sched:sched_wakeup_new,sched:sched_switch//key=prev_pid/',
                     '-e', 'sched:sched_switch//key=next_pid/', '-k', 'pid', '--order', '-p', '1', '-i', '1000', '--than', '4ms', '--detail=samekey'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_rundelay_filter_python(runtime, memleak_check):
    #perf-prof rundelay -e sched:sched_wakeup,sched:sched_wakeup_new,sched:sched_switch//key=prev_pid/ -e sched:sched_switch//key=next_pid/ -k pid --order --filter python -i 1000 --than 4ms
    prof = PerfProf(["rundelay", '-e', 'sched:sched_wakeup,sched:sched_wakeup_new,sched:sched_switch//key=prev_pid/',
                     '-e', 'sched:sched_switch//key=next_pid/', '-k', 'pid', '--order', '--filter', 'python', '-i', '1000', '--than', '4ms', '--detail=samekey'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_rundelay_filter_python_profile(runtime, memleak_check):
    #perf-prof rundelay -e sched:sched_wakeup,sched:sched_wakeup_new,sched:sched_switch//key=prev_pid/ -e 'sched:sched_switch//key=next_pid/,profile/-F 500 --watermark 50 -m 16 -g/untraced/' -k pid --order --filter python -i 1000 --than 4ms
    prof = PerfProf(["rundelay", '-e', 'sched:sched_wakeup,sched:sched_wakeup_new,sched:sched_switch//key=prev_pid/',
                     '-e', 'sched:sched_switch//key=next_pid/,profile/-F 500 --watermark 50 -m 16 -g/untraced/', '-k', 'pid', '--order', '--filter', 'python', '-i', '1000', '--than', '4ms', '--detail=samecpu'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)
