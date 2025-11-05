#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest
import subprocess

def pytest_addoption(parser):
    parser.addoption("--memleak-check", action="store", default=0, type=str, dest="MemcheckType",
                     help="perf-prof tool memory leak check: numeric value for tcmalloc (default: %(default)s), 'valgrind' for valgrind memory check")
    parser.addoption("--runtime", action="store", default=10, type=int, help="perf-prof tool runtime (default: %(default)s)")

def pytest_sessionstart(session):
    subprocess.call(['make'])

def pytest_sessionfinish(session):
    subprocess.call(['make', 'clean'])

@pytest.fixture(scope="session")
def memleak_check(pytestconfig):
    '''perf-prof tool memleak check'''
    memcheck_type = pytestconfig.getoption("--memleak-check")

    # Handle default case where it's still an integer (0)
    if isinstance(memcheck_type, int):
        return memcheck_type

    # Check if it's "valgrind" string
    if memcheck_type.lower() == "valgrind":
        return memcheck_type.lower()

    # Try to parse as integer (existing functionality)
    try:
        return int(memcheck_type)
    except ValueError:
        # If parsing fails, default to 0 (no memleak check)
        return 0

@pytest.fixture(scope="session")
def runtime(pytestconfig):
    '''perf-prof tool runtime'''
    return pytestconfig.getoption("--runtime")

def result_check(std, line, runtime, memleak_check):
    # Check if memleak_check is set to "valgrind"
    is_valgrind = (memleak_check == "valgrind")

    if is_valgrind:
        # Special handling for valgrind output
        print(line, end='', flush=True)
        # Don't fail on valgrind stderr output - valgrind uses stderr for its messages
        if std == PerfProf.STDERR and 'ERROR SUMMARY:' in line:
            # Check if valgrind found any errors
            if 'ERROR SUMMARY: 0 errors' not in line:
                pytest.fail(f"Valgrind detected errors: {line}")
    elif not memleak_check:
        print(line, end='', flush=True)
        if std != PerfProf.STDOUT:
            pytest.fail(line)
        elif '<...>' in line:
            pytest.fail(line)
    else:
        # Numeric memleak check (existing functionality)
        if std == PerfProf.STDERR and not PerfProf.lost_events(line):
            print(line, end='', flush=True)
            if PerfProf.memleak(line, memleak_check):
                pytest.fail(line)
