#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_sched_wakeup(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sched_wakeup_tsc(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '--tsc', '-N', '20'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sched_wakeup_tsc_offset(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '--tsc-offset', '0xff', '-N', '20'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_flame_graph(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0 -g
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '-g', '--flame-graph', 'wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_flame_graph(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0 -g
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '-g', '--flame-graph', '/dev/stdout'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_overwrite(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup,sched:sched_switch --overwrite
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup,sched:sched_switch', '-m', '1', '--overwrite'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_trace_profiler(runtime, memleak_check):
    #perf-prof trace -e 'task-state,page-faults/-N 10/,raw_syscalls:sys_enter,profile/-F 5000 -N 10/' --order -- cat /proc/self/maps
    prof = PerfProf(['trace', '-e', 'task-state,page-faults/-N 10/,raw_syscalls:sys_enter,profile/-F 5000 -N 10/', '--order', '--', 'cat', '/proc/self/maps'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_trace_attr_cpus0(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup/target_cpu==0/,sched:sched_migrate_task/dest_cpu==0/,sched:sched_switch//cpus=0/ -m 128 --order -i 1000 -N 100000
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup/target_cpu==0/,sched:sched_migrate_task/dest_cpu==0/,sched:sched_switch//cpus=0/', '-m', '128', '--order', '-i', '1000', '-N', '100000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_trace_attr_cpus1(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup/target_cpu==1/,sched:sched_migrate_task/dest_cpu==1/,sched:sched_switch//cpus=1/ -m 128 --order -i 1000 -N 100000
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup/target_cpu==1/,sched:sched_migrate_task/dest_cpu==1/,sched:sched_switch//cpus=1/', '-m', '128', '--order', '-i', '1000', '-N', '100000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)