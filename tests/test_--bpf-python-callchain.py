#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_bpf_pystack_taskstate(runtime, memleak_check):
    # perf-prof task-state --filter 'java,python*' -i 1000 --than 100ms -g --bpf-python-callchain /usr/local/lib/libpython3.6m.so.1.0
    task_state = PerfProf(['task-state', '--filter', 'java,python*', '-i', '1000', '--than', '100ms', '-g', '--bpf-python-callchain', '/usr/local/lib/libpython3.6m.so.1.0'])
    for std, line in task_state.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)