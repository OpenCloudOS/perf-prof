#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check
import pytest

def test_kvm_exit(runtime, memleak_check):
    exist, _ = PerfProf.tracepoint_exists('kvm:kvm_exit')
    if not exist:
        pytest.skip("'kvm:kvm_exit' does not exist")

    #perf-prof kvm-exit -i 1000
    prof = PerfProf(["kvm-exit", '-i', '1000'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)