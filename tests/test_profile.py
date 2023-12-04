#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

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

