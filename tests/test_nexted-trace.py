#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_nested_trace_irq(runtime, memleak_check):
    #perf-prof nested-trace -e irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/ -i 1000 --impl call-delay
    prof = PerfProf(["nested-trace", '-e', 'irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/', '-i', '1000', '--impl', 'call-delay'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_nested_trace_irq_timer(runtime, memleak_check):
    #perf-prof nested-trace -e irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/ -e timer:timer_expire_entry,timer:timer_expire_exit -i 1000 --impl call-delay --than 50us
    prof = PerfProf(["nested-trace", '-e', 'irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/',
                    '-e', 'timer:timer_expire_entry,timer:timer_expire_exit', '-i', '1000', '--impl', 'call-delay', '--than', '50us'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_nested_trace_irq_timer_profile(runtime, memleak_check):
    #perf-prof nested-trace -e 'irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/,profile/-F 1000 --watermark 50 -m 16 -g/untraced/' \
    #-e timer:timer_expire_entry,timer:timer_expire_exit -i 1000 --impl call-delay --than 50us --detail=samecpu --order
    prof = PerfProf(["nested-trace", '-e', 'irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/,profile/-F 1000 --watermark 50 -m 16 -g/untraced/',
                    '-e', 'timer:timer_expire_entry,timer:timer_expire_exit', '-i', '1000', '--impl', 'call-delay', '--than', '50us', '--detail=samecpu', '--order'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)