#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_sched_migrate(runtime, memleak_check):
    #perf-prof sched-migrate --detail
    prof = PerfProf(["sched-migrate", '--detail'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)