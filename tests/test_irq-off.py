#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_irq_off1(runtime, memleak_check):
    #perf-prof irq-off --period 10ms --than 20ms -g
    prof = PerfProf(["irq-off", '--period', '10ms', '--than', '20ms', '-g'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_irq_off2(runtime, memleak_check):
    #perf-prof irq-off --period 10ms --than 20ms -g --exclude-user
    prof = PerfProf(["irq-off", '--period', '10ms', '--than', '20ms', '-g', '--exclude-user'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
