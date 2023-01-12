#!/usr/bin/env python3

import pytest


def pytest_addoption(parser):
    parser.addoption("--memleak-check", action="store_true", default=False, help="perf-prof tool memleak check")
    parser.addoption("--runtime", action="store", default=10, type=int, help="perf-prof tool runtime")

@pytest.fixture(scope="session")
def memleak_check(pytestconfig):
    '''perf-prof tool memleak check'''
    return pytestconfig.getoption("--memleak-check")

@pytest.fixture(scope="session")
def runtime(pytestconfig):
    '''perf-prof tool runtime'''
    return pytestconfig.getoption("--runtime")

