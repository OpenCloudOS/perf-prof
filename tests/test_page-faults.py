#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_page_faults_exclude_user(runtime, memleak_check):
    #page-faults -C 0 --exclude-user -N 100
    prof = PerfProf(["page-faults", '-C', '0', '--exclude-user', '-N', '100'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_page_faults_exclude_user_g(runtime, memleak_check):
    #page-faults -C 0 -g --exclude-user -N 100
    prof = PerfProf(["page-faults", '-C', '0', '-g', '--exclude-user', '-N', '100'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_page_faults_exclude_kernel(runtime, memleak_check):
    #page-faults -C 0 --exclude-kernel -N 100 --watermark 20
    prof = PerfProf(["page-faults", '-C', '0', '--exclude-kernel', '-N', '100', '--watermark', '20'])
    for std, line in prof.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)
