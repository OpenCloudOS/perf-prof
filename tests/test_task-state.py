#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

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


