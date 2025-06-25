#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_kcore(runtime, memleak_check):
    #perf-prof kcore
    prof = PerfProf(["kcore", "--string", "linux_banner"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_kcore_64(runtime, memleak_check):
    #perf-prof kcore
    sym = PerfProf.kallsyms_lookup_name("linux_banner")
    prof = PerfProf(["kcore", "--64", "" + hex(sym), "2"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)