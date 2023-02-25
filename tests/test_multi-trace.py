#!/usr/bin/env python3

from PerfProf import PerfProf, DeadLoop
import pytest
import time

def test_multi_trace_switch(runtime, memleak_check):
    # perf-prof multi-trace -e sched:sched_switch --cycle -i 1000 --perins
    multi_trace = PerfProf(["multi-trace",
                            '-e', 'sched:sched_switch', '--cycle', '-i', '1000', '--perins'])
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_multi_trace_hrtimer(runtime, memleak_check):
    # perf-prof multi-trace -e timer:hrtimer_expire_entry/function==0x$tick/ -e timer:hrtimer_expire_exit -i 1000
    multi_trace = PerfProf(["multi-trace"])
    tick = PerfProf.kallsyms_lookup_name("tick_sched_timer")
    multi_trace += ["-e", "timer:hrtimer_expire_entry/function==" + hex(tick) + "/",
                    "-e", "timer:hrtimer_expire_exit", "-i", "1000"]
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_multi_trace_workqueue(runtime, memleak_check):
    multi_trace = PerfProf(["multi-trace"])
    tick = PerfProf.kallsyms_lookup_name("vmstat_update")
    multi_trace += ["-e", "workqueue:workqueue_queue_work/function==" + hex(tick) + "/",
                    "-e", "workqueue:workqueue_execute_start/function==" + hex(tick) + "/",
                    '-k', 'work', '--order', "-i", "1000"]
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_multi_trace_softirq_timer(runtime, memleak_check):
    # perf-prof multi-trace -e irq:softirq_entry/vec==1/ -e irq:softirq_exit/vec==1/ -i 1000
    multi_trace = PerfProf(["multi-trace",
                            '-e', 'irq:softirq_entry/vec==1/',
                            '-e', 'irq:softirq_exit/vec==1/',
                            '-i', '1000'])
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


def test_multi_trace_softirq_pair(runtime, memleak_check):
    # perf-prof multi-trace -e irq:softirq_entry/vec==1/ -e irq:softirq_exit/vec==1/ -i 1000 --impl pair
    multi_trace = PerfProf(["multi-trace",
                            '-e', 'irq:softirq_entry/vec==1/',
                            '-e', 'irq:softirq_exit/vec==1/',
                            '-i', '1000', '--impl', 'pair'])
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


def test_multi_trace_softirq_timer_detail(runtime, memleak_check):
    # perf-prof multi-trace -e irq:softirq_entry/vec==1/ -e irq:softirq_exit/vec==1/ -i 1000 --than 100us --order --detail=-1ms
    multi_trace = PerfProf(["multi-trace",
                            '-e', 'irq:softirq_entry/vec==1/',
                            '-e', 'irq:softirq_exit/vec==1/',
                            '-i', '1000', '--than', '100us', '--order', '--detail=-1ms'])
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


def test_multi_trace_softirq_timer_detail_only_than(runtime, memleak_check):
    # perf-prof multi-trace -e irq:softirq_entry/vec==1/ -e irq:softirq_exit/vec==1/ -i 1000 --only-than 100us --order --detail=-1ms
    multi_trace = PerfProf(["multi-trace",
                            '-e', 'irq:softirq_entry/vec==1/',
                            '-e', 'irq:softirq_exit/vec==1/',
                            '-i', '1000', '--only-than', '100us', '--order', '--detail=-1ms'])
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


@pytest.fixture
def sleep_loop_tid():
    loop = DeadLoop(lambda :time.sleep(0.001))
    yield loop.tid
    loop.stop()

def test_multi_trace_tid_sleep_1ms(runtime, memleak_check, sleep_loop_tid):
    multi_trace = PerfProf(["multi-trace",
                            '-e', 'sched:sched_switch/prev_pid==' + str(sleep_loop_tid) + '/',
                            '-e', 'sched:sched_wakeup/pid==' + str(sleep_loop_tid) + '/',
                            '-e', 'sched:sched_switch/next_pid==' + str(sleep_loop_tid) + '/',
                            '-i', '1000', '--order'])
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


@pytest.fixture
def sleep_loop_tid_100ms():
    loop = DeadLoop(lambda :time.sleep(0.1))
    yield loop.tid
    loop.stop()

def test_multi_trace_tid_sleep_100ms(runtime, memleak_check, sleep_loop_tid_100ms):
    multi_trace = PerfProf(["multi-trace",
                            '-e', 'sched:sched_switch/prev_pid==' + str(sleep_loop_tid_100ms) + '/,sched:sched_stat_runtime/runtime>0/untraced/',
                            '-e', 'sched:sched_wakeup/pid==' + str(sleep_loop_tid_100ms) + '/',
                            '-e', 'sched:sched_switch/next_pid==' + str(sleep_loop_tid_100ms) + '/',
                            '-i', '1000', '-m', '128', '--order', '--than', '105ms', '--detail=-1ms,samecpu'])
    for std, line in multi_trace.run(runtime, memleak_check, util_interval=5):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


