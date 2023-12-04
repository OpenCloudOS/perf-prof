#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_percpu_stat(runtime, memleak_check):
    #perf-prof percpu-stat -i 1000
    prof = PerfProf(['percpu-stat', '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_percpu_stat_syscalls(runtime, memleak_check):
    #perf-prof percpu-stat --syscalls -i 2000
    prof = PerfProf(['percpu-stat', '--syscalls', '-i', '2000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
