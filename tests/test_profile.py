#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check
import pytest

def test_profile_g(runtime, memleak_check):
    #perf-prof profile -F 997 -C 0 -m 32 -g
    prof = PerfProf(["profile", '-F', '997', '-C', '0', '-m', '32', '-g'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_profile_exclude_user(runtime, memleak_check):
    #perf-prof profile -F 997 -C 0 -m 32 --exclude-user --watermark 50 -g --flame-graph profile
    prof = PerfProf(["profile", '-F', '997', '-C', '0', '-m', '32', '--exclude-user', '--watermark', '50', '-g', '--flame-graph', 'profile'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_profile_bpf_irq_disabled(runtime, memleak_check):
    if not PerfProf.btf_exists():
        pytest.skip("'bpf' does not support")
    prof = PerfProf(["profile", '-F', '997', '-m', '32', '--irqs_disabled=1', '-g', '--flame-graph', 'profile'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_profile_bpf_tif_need_resched(runtime, memleak_check):
    if not PerfProf.btf_exists():
        pytest.skip("'bpf' does not support")
    prof = PerfProf(["profile", '-F', '997', '-m', '32', '--tif_need_resched=1', '-g', '--flame-graph', 'profile'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_profile_bpf_exclude_pid(runtime, memleak_check):
    if not PerfProf.btf_exists():
        pytest.skip("'bpf' does not support")
    prof = PerfProf(["profile", '-F', '997', '-m', '32', '--exclude_pid', '1', '-g', '--flame-graph', 'profile'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_profile_bpf_nr_running_min(runtime, memleak_check):
    if not PerfProf.btf_exists():
        pytest.skip("'bpf' does not support")
    prof = PerfProf(["profile", '-F', '997', '-m', '32', '--nr_running_min', '1', '-g', '--flame-graph', 'profile'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_profile_bpf_nr_running_max(runtime, memleak_check):
    if not PerfProf.btf_exists():
        pytest.skip("'bpf' does not support")
    prof = PerfProf(["profile", '-F', '997', '-m', '32', '--nr_running_max', '3', '-g', '--flame-graph', 'profile'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_profile_bpf_sched_policy(runtime, memleak_check):
    if not PerfProf.btf_exists():
        pytest.skip("'bpf' does not support")
    prof = PerfProf(["profile", '-F', '997', '-m', '32', '--sched_policy', '2', '-g', '--flame-graph', 'profile'])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
