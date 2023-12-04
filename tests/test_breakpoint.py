#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_breakpoint_try_to_wake_up(runtime, memleak_check):
    sym = PerfProf.kallsyms_lookup_name("try_to_wake_up")
    prof = PerfProf(["breakpoint", "" + hex(sym) + ":x", '-g', '-N', '2'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_breakpoint_try_to_wake_up_exclude_user(runtime, memleak_check):
    sym = PerfProf.kallsyms_lookup_name("try_to_wake_up")
    prof = PerfProf(["breakpoint", "" + hex(sym) + ":x", '-g', '-N', '2', '--exclude-user'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
