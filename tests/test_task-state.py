#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_task_state_mode0(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode1(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 --filter 'python,sh,bash,ls,ps,awk,grep'
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '--filter', 'python,sh,bash,ls,ps,awk,grep'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode2(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 -SD
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '-SD'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode3(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 -SD --filter 'python,sh,bash,ls,ps,awk,grep'
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '-SD', '--filter', 'python,sh,bash,ls,ps,awk,grep'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode0_NOD(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 --no-interruptible
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '--no-interruptible'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode1_NOD(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 --filter 'python,sh,bash,ls,ps,awk,grep' --no-interruptible
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--no-interruptible'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode1_than(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 --filter 'python,sh,bash,ls,ps,awk,grep' --than 1s
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--than', '1s'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode1_than_perins(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 --filter 'python,sh,bash,ls,ps,awk,grep' --than 1s --perins
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--than', '1s', '--perins'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode3_than(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 -SD --filter 'python,sh,bash,ls,ps,awk,grep' --than 1s
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '-SD', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--than', '1s'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_mode3_than_perins(runtime, memleak_check):
    # perf-prof task-state -i 1000 -m 256 -SD --filter 'python,sh,bash,ls,ps,awk,grep' --than 1s --perins
    task_state = PerfProf(['task-state', '-i', '1000', '-m', '256', '-SD', '--filter', 'python,sh,bash,ls,ps,awk,grep', '--than', '1s', '--perins'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_filter(runtime, memleak_check):
    # perf-prof task-state --filter 'java,python*' -S --than 100ms -g
    task_state = PerfProf(['task-state', '--filter', 'java,python*', '-S', '--than', '100ms', '-g'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_task_state_ip_link_show(runtime, memleak_check):
    # perf-prof task-state -- ip link show
    task_state = PerfProf(['task-state', '--', 'ip', 'link', 'show'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


