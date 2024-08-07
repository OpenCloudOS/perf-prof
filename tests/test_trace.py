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

def test_sched_wakeup_clock_offset(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '--clock-offset', '0xff', '-N', '20'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_userspace_ftrace_filter(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup,sched:sched_switch -C 0
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup/pid<prio/stack/,sched:sched_switch/next_pid<next_prio&&next_pid>0/', '-C', '0', '-m', '64'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_flame_graph(runtime, memleak_check):
    #perf-prof trace -e sched:sched_wakeup -C 0 -g
    prof = PerfProf(['trace', '-e', 'sched:sched_wakeup', '-C', '0', '-m', '64', '-g', '--flame-graph', 'wakeup'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_flame_graph_stdout(runtime, memleak_check):
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

def test_trace_task_state1(runtime, memleak_check):
    #perf-prof trace -e 'syscalls:sys_enter_nanosleep,task-state/--perins/' --order -- ./pthread --loop 5 --depth 1
    prof = PerfProf(['trace', '-e', 'syscalls:sys_enter_nanosleep,task-state/--perins -m 64/', '-m', '128', '--order', '--', './pthread', '--loop', '5', '--depth', '1'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_trace_task_state2(runtime, memleak_check):
    #perf-prof trace -e 'syscalls:sys_enter_nanosleep,task-state/--perins/' --order -- ./pthread --daemonize --depth 2
    prof = PerfProf(['trace', '-e', 'syscalls:sys_enter_nanosleep,task-state/--perins -m 64/', '-m', '128', '--order', '--', './pthread', '--daemonize', '--depth', '2'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_trace_task_state3(runtime, memleak_check):
    #perf-prof trace -e 'syscalls:sys_enter_nanosleep,task-state/--perins/' --order -- ./pthread --depth 2
    prof = PerfProf(['trace', '-e', 'syscalls:sys_enter_nanosleep,task-state/--perins -m 64/', '-m', '128', '--order', '--', './pthread', '--depth', '2'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)