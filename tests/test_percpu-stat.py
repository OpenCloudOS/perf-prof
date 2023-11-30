#!/usr/bin/env python3

from PerfProf import PerfProf

def test_percpu_stat(runtime, memleak_check):
    #perf-prof percpu-stat -i 1000
    prof = PerfProf(['percpu-stat', '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_percpu_stat_syscalls(runtime, memleak_check):
    #perf-prof percpu-stat --syscalls -i 2000
    prof = PerfProf(['percpu-stat', '--syscalls', '-i', '2000'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)
