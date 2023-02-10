#!/usr/bin/env python3

from PerfProf import PerfProf

def test_breakpoint_try_to_wake_up(runtime, memleak_check):
    sym = PerfProf.kallsyms_lookup_name("try_to_wake_up")
    bp = PerfProf(["breakpoint", "" + hex(sym) + ":x", '-g', '-N', '2'])
    for std, line in bp.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT
