#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest
import subprocess

def pytest_addoption(parser):
    parser.addoption("--memleak-check", action="store", default=0, type=int, dest="Bytes",
                     help="perf-prof tool allow leaked bytes check (default: %(default)s, disable memleak check)")
    parser.addoption("--runtime", action="store", default=10, type=int, help="perf-prof tool runtime (default: %(default)s)")

def pytest_sessionstart(session):
    subprocess.call(['make'])

def pytest_sessionfinish(session):
    subprocess.call(['make', 'clean'])

@pytest.fixture(scope="session")
def memleak_check(pytestconfig):
    '''perf-prof tool memleak check'''
    return pytestconfig.getoption("--memleak-check")

@pytest.fixture(scope="session")
def runtime(pytestconfig):
    '''perf-prof tool runtime'''
    return pytestconfig.getoption("--runtime")

def result_check(std, line, runtime, memleak_check):
    if not memleak_check:
        print(line, end='', flush=True)
        if std != PerfProf.STDOUT:
            pytest.fail(line)
        elif '<...>' in line:
            pytest.fail(line)
    else:
        if std == PerfProf.STDERR and not PerfProf.lost_events(line):
            print(line, end='', flush=True)
            if PerfProf.memleak(line, memleak_check):
                pytest.fail(line)
