#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_cpu_util(runtime, memleak_check):
    #perf-prof cpu-util -C 0 -i 1000
    prof = PerfProf(["cpu-util", '-C', '0', '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)