#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_tlbstat(runtime, memleak_check):
    #perf-prof tlbstat
    prof = PerfProf(["tlbstat"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
