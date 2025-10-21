#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_misc(runtime, memleak_check):
    #perf-prof misc
    prof = PerfProf(["misc"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)