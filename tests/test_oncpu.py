#!/usr/bin/env python3

from PerfProf import PerfProf, DeadLoop
import pytest

@pytest.fixture
def dead_loop_tid():
    loop = DeadLoop()
    yield loop.tid
    loop.stop()


def oncpu(args, runtime, memleak_check):
    cmdline = ["oncpu"]
    cmdline.extend(args)
    oncpu = PerfProf(cmdline)
    for std, line in oncpu.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)


def test_oncpu_attach_to_allcpu(runtime, memleak_check):
    oncpu(["-m", "128"], runtime, memleak_check)

def test_oncpu_attach_to_pid(runtime, memleak_check, dead_loop_tid):
    oncpu(['-m', '128', '-t', str(dead_loop_tid)], runtime, memleak_check)

def test_oncpu_attach_to_cpu0(runtime, memleak_check):
    oncpu(['-m', '128', '-C', '0'], runtime, memleak_check)

