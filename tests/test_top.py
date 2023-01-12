#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest


def test_sched_wakeup(runtime, memleak_check):
    #perf-prof top -e sched:sched_wakeup//comm=comm/ --only-comm -m 64
    top = PerfProf(['top', '-e', 'sched:sched_wakeup//comm=comm/', '--only-comm', '-m', '64'])
    for std, line in top.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_block_rq_issue(runtime, memleak_check):
    #perf-prof top -e block:block_rq_issue//top-by=nr_sector/comm=comm/ --only-comm -m 32
    top = PerfProf(['top', '-e', 'block:block_rq_issue//top-by=nr_sector/comm=comm/', '--only-comm', '-m', '32'])
    for std, line in top.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_block_rq_issue_filter(runtime, memleak_check):
    #perf-prof top -e 'block:block_rq_issue/rwbs==W&&nr_sector<4/top-by=nr_sector/comm=comm/' --only-comm -i 1000
    top = PerfProf(['top', '-e', 'block:block_rq_issue/rwbs==W&&nr_sector<4/top-by=nr_sector/comm=comm/', '--only-comm', '-m', '32'])
    for std, line in top.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_kvm_exit(runtime, memleak_check):
    exist, _ = PerfProf.tracepoint_exists('kvm:kvm_exit')
    if not exist:
        pytest.skip("'kvm:kvm_exit' does not exist")

    #perf-prof top -e kvm:kvm_exit//key=exit_reason/ -i 1000
    top = PerfProf(['top', '-e', 'kvm:kvm_exit//key=exit_reason/', '-i', '1000'])
    for std, line in top.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_sched_stat_runtime(runtime, memleak_check):
    #perf-prof top -e sched:sched_stat_runtime//top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/ -m 64
    top = PerfProf(['top', '-e', 'sched:sched_stat_runtime//top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/', '-m', '64'])
    for std, line in top.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_sched_process_exec(runtime, memleak_check):
    #perf-prof top -e sched:sched_process_exec//comm=filename/ --only-comm
    top = PerfProf(['top', '-e', 'sched:sched_process_exec//comm=filename/', '--only-comm'])
    for std, line in top.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT
