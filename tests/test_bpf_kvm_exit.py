#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_bpf(runtime, memleak_check):
    #perf-prof bpf:kvm-exit --order -i 5000 --perins --detail
    prof = PerfProf(["bpf:kvm-exit", "-i", "1000", "--perins", "--detail", "--threshold", "2ms"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_order(runtime, memleak_check):
    prof = PerfProf(["bpf:kvm-exit", "-i", "1000", "--perins", "--detail", "--order"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)\

def test_bpf_1(runtime, memleak_check):
    prof = PerfProf(["bpf:kvm-exit", "-i", "1000", "--perins", "--detail", "-q"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_2(runtime, memleak_check):
    prof = PerfProf(["bpf:kvm-exit", "-i", "1000", "--perins", "--output2", "/dev/null"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_3(runtime, memleak_check):
    prof = PerfProf(["bpf:kvm-exit", "-i", "1000", "--perins", "-p", "1"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_3(runtime, memleak_check):
    prof = PerfProf(["bpf:kvm-exit", "-i", "1000", "--perins", "--detail", "--than", "10ms"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)