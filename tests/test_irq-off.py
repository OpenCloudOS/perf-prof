#!/usr/bin/env python3

from PerfProf import PerfProf

def test_irq_off1(runtime, memleak_check):
    #perf-prof irq-off --period 10ms --than 20ms -g
    prof = PerfProf(["irq-off", '--period', '10ms', '--than', '20ms', '-g'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_irq_off2(runtime, memleak_check):
    #perf-prof irq-off --period 10ms --than 20ms -g --exclude-user
    prof = PerfProf(["irq-off", '--period', '10ms', '--than', '20ms', '-g', '--exclude-user'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)
