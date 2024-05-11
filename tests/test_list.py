#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_list(runtime, memleak_check):
    #perf-prof list
    prof = PerfProf(["list"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)