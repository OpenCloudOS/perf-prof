#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_breakpoint_try_to_wake_up(runtime, memleak_check):
    sym = PerfProf.kallsyms_lookup_name("try_to_wake_up")
    prof = PerfProf(["breakpoint", "" + hex(sym) + ":x", '-g', '-N', '2'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_breakpoint_try_to_wake_up_exclude_user(runtime, memleak_check):
    sym = PerfProf.kallsyms_lookup_name("try_to_wake_up")
    prof = PerfProf(["breakpoint", "" + hex(sym) + ":x", '-g', '-N', '2', '--exclude-user'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)
