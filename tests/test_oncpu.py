#!/usr/bin/env python3

from PerfProf import PerfProf, DeadLoop
from conftest import result_check
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
        result_check(std, line, runtime, memleak_check)


def test_oncpu_attach_to_allcpu(runtime, memleak_check):
    oncpu(["-m", "128"], runtime, memleak_check)

def test_oncpu_attach_to_allcpu_onlycomm(runtime, memleak_check):
    oncpu(["-m", "128", "--only-comm"], runtime, memleak_check)

def test_oncpu_attach_to_pid(runtime, memleak_check, dead_loop_tid):
    oncpu(['-m', '128', '-t', str(dead_loop_tid)], runtime, memleak_check)

def test_oncpu_attach_to_cpu0(runtime, memleak_check):
    oncpu(['-m', '128', '-C', '0'], runtime, memleak_check)

def test_oncpu_prio_rt(runtime, memleak_check):
    oncpu(['-m', '128', '--prio', '1-99'], runtime, memleak_check)

def test_oncpu_prio_100(runtime, memleak_check):
    oncpu(['-m', '128', '--prio', '100'], runtime, memleak_check)

def test_oncpu_prio_rt_CPU0(runtime, memleak_check):
    oncpu(['-m', '128', '-C', '0', '--prio', '1-99'], runtime, memleak_check)
