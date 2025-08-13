#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_task_state_mode0(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256
    task_state = PerfProf(['bpf:task-state', '-i', '1000'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode1(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 --filter 'python,sh,bash,ls,ps,awk,grep'
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '--filter', 'python,sh,bash,ls,ps,awk,grep'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode2(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 -SD
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '-SD'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode3(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 -SD --filter 'python,sh,bash,ls,ps,awk,grep'
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '-SD', '--filter', 'python,sh,bash,ls,ps,awk,grep'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode0_NOS(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 --no-interruptible
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '--no-interruptible'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode1_NOS(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 --filter 'python,sh,bash,ls,ps,awk,grep' --no-interruptible
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--no-interruptible'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode1_than(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 --filter 'python,sh,bash,ls,ps,awk,grep' --than 1s
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--than', '1s'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode1_than_perins(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 --filter 'python,sh,bash,ls,ps,awk,grep' --than 1s --perins
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--than', '1s', '--perins'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode3_than(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 -SD --filter 'python,sh,bash,ls,ps,awk,grep' --than 1s
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '-SD', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--than', '1s'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode3_than_perins(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 -m 256 -SD --filter 'python,sh,bash,ls,ps,awk,grep' --than 1s --perins
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '-m', '256', '-SD', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--than', '1s', '--perins'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_filter(runtime, memleak_check):
    # perf-prof bpf:task-state --filter 'java,python*' -S --than 100ms -g
    task_state = PerfProf(['bpf:task-state', '--filter', 'java,python*', '-S', '--than', '100ms', '-g'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_pthread1(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 --perins -m 64 -- ./pthread --loop 10 --depth 3
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '--perins', '-m', '64', '--', './pthread', '--loop', '10', '--depth', '3'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_pthread2(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 --perins -m 64 -- ./pthread --depth 2
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '--perins', '-m', '64', '--', './pthread', '--depth', '2'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_pthread3(runtime, memleak_check):
    # perf-prof bpf:task-state -i 1000 --perins -m 64 -- ./pthread --daemonize --depth 5
    task_state = PerfProf(['bpf:task-state', '-i', '1000', '--perins', '-m', '64', '--', './pthread', '--daemonize', '--depth', '5'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
