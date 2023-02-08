#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

@pytest.fixture(autouse=True)
def sysctl_kernel_sched_schedstats():
    old = PerfProf.sysctl('kernel.sched_schedstats', '1')
    yield
    PerfProf.sysctl('kernel.sched_schedstats', old)

def test_num_dist_sched_stat_runtime(runtime, memleak_check):
    num_dist = PerfProf(['num-dist', '-e', 'sched:sched_stat_runtime//num=runtime/', '-i', '1000'])
    for std, line in num_dist.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_num_dist_sched_stat_runtime_us(runtime, memleak_check):
    num_dist = PerfProf(['num-dist', '-e', 'sched:sched_stat_runtime//num="runtime/1000"/alias=sched_stat_runtime(us)/', '-i', '1000'])
    for std, line in num_dist.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_num_dist_sched_stat_blocked(runtime, memleak_check):
    num_dist = PerfProf(['num-dist', '-e', 'sched:sched_stat_blocked//num=delay/', '-i', '1000'])
    for std, line in num_dist.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_num_dist_sched_stat_iowait(runtime, memleak_check):
    num_dist = PerfProf(['num-dist', '-e', 'sched:sched_stat_iowait//num=delay/', '-i', '1000'])
    for std, line in num_dist.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_num_dist_sched_stat_sleep(runtime, memleak_check):
    num_dist = PerfProf(['num-dist', '-e', 'sched:sched_stat_sleep//num=delay/', '-i', '1000'])
    for std, line in num_dist.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_num_dist_sched_stat_wait(runtime, memleak_check):
    num_dist = PerfProf(['num-dist', '-e', 'sched:sched_stat_wait//num=delay/', '-i', '1000'])
    for std, line in num_dist.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_num_dist_sched_vmf_rundelay(runtime, memleak_check):
    exist, _ = PerfProf.tracepoint_exists('sched:sched_vmf_rundelay')
    if not exist:
        pytest.skip("'sched:sched_vmf_rundelay' does not exist")

    num_dist = PerfProf(['num-dist', '-e', 'sched:sched_vmf_rundelay//num=rundelay/', '-i', '1000'])
    for std, line in num_dist.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_num_dist_sched_vmf_rundelay_us(runtime, memleak_check):
    exist, _ = PerfProf.tracepoint_exists('sched:sched_vmf_rundelay')
    if not exist:
        pytest.skip("'sched:sched_vmf_rundelay' does not exist")

    num_dist = PerfProf(['num-dist', '-e', 'sched:sched_vmf_rundelay//num="rundelay/1000"/alias=rundelay(us)/', '-i', '1000'])
    for std, line in num_dist.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT
