#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_watchdog(runtime, memleak_check):
    #perf-prof watchdog -F 10 -g
    prof = PerfProf(["watchdog", '-F', '10', '-g'])
    if runtime > 0:
        thresh = int(PerfProf.sysctl('kernel.watchdog_thresh'))
    else:
        thresh = 0
    for std, line in prof.run(runtime+thresh, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_watchdog1(runtime, memleak_check):
    #perf-prof watchdog -F 10 -g
    prof = PerfProf(["watchdog", '-F', '10', '-g', '-o', 'watchdog.log'])
    if runtime > 0:
        thresh = int(PerfProf.sysctl('kernel.watchdog_thresh'))
    else:
        thresh = 0
    for std, line in prof.run(runtime+thresh, memleak_check):
        result_check(std, line, runtime, memleak_check)
