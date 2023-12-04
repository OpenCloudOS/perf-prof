#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_llcstat(runtime, memleak_check):
    #perf-prof llcstat -i 1000
    prof = PerfProf(["llcstat", '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)