#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_syscalls(runtime, memleak_check):
    #perf-prof syscalls -e raw_syscalls:sys_enter -e raw_syscalls:sys_exit -k common_pid -i 1000 --order -m 128 -C 1
    prof = PerfProf(["syscalls", '-e', 'raw_syscalls:sys_enter', '-e', 'raw_syscalls:sys_exit', '-k', 'common_pid', '-i', '1000', '--order', '-m', '128', '-C', '1'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)