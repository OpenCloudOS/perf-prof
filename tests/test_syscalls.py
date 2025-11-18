#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_syscalls(runtime, memleak_check):
    #perf-prof syscalls -e raw_syscalls:sys_enter -e raw_syscalls:sys_exit -i 1000 -m 128 -C 1
    prof = PerfProf(["syscalls", '-e', 'raw_syscalls:sys_enter', '-e', 'raw_syscalls:sys_exit', '-i', '1000', '-m', '128', '-C', '1'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_syscalls_perins(runtime, memleak_check):
    #perf-prof syscalls -e raw_syscalls:sys_enter -e raw_syscalls:sys_exit -i 1000 -m 128 -C 1 --perins
    prof = PerfProf(["syscalls", '-e', 'raw_syscalls:sys_enter', '-e', 'raw_syscalls:sys_exit', '-i', '1000', '-m', '128', '-C', '1', '--perins'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
