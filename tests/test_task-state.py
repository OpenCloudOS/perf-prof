#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_task_state_filter(runtime, memleak_check):
    # perf-prof task-state --filter 'java,python*' -S --than 100ms -g
    task_state = PerfProf(['task-state', '--filter', 'java,python*', '-S', '--than', '100ms', '-g'])
    for std, line in task_state.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

def test_task_state_ip_link_show(runtime, memleak_check):
    # perf-prof task-state -- ip link show
    task_state = PerfProf(['task-state', '--', 'ip', 'link', 'show'])
    for std, line in task_state.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT
