#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_sched_wakeup(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_sched_wakeup_tsc(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '--tsc', '-N', '20'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_sched_wakeup_tsc_offset(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '--tsc-offset', '0xff', '-N', '20'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_flame_graph(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0 -g
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '-g', '--flame-graph', 'wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_overwrite(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup,sched:sched_switch --overwrite
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup,sched:sched_switch', '-m', '1', '--overwrite'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)
