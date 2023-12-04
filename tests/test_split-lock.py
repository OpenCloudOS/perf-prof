#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_split_lock(runtime, memleak_check):
    #perf-prof split-lock -i 1000 --test
    prof = PerfProf(["split-lock", '-i', '1000', '--test'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_split_lock_T(runtime, memleak_check):
    #perf-prof split-lock -T 1000 --test
    prof = PerfProf(["split-lock", '-T', '1000', '--test'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)