#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_usdt_list(runtime, memleak_check):
    usdt = PerfProf(['usdt', 'list', 'pthread_create@/usr/lib64/libpthread.so.0'])
    usdt += ['setjmp@/usr/lib64/libc.so.6', 'longjmp@/usr/lib64/libc.so.6', '-v']
    for std, line in usdt.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_usdt_add(runtime, memleak_check):
    usdt = PerfProf(['usdt', 'add', 'libpthread:pthread_create@/usr/lib64/libpthread.so.0'])
    usdt += ['setjmp@/usr/lib64/libc.so.6']
    for std, line in usdt.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_usdt_trace_pthread_create(runtime, memleak_check):
    trace = PerfProf(['trace', '-e', 'libpthread:pthread_create,libc:setjmp', '-m', '8'])
    for std, line in trace.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)

def test_usdt_del(runtime, memleak_check):
    usdt = PerfProf(['usdt', 'del', 'pthread_create@/usr/lib64/libpthread.so.0'])
    usdt += ['setjmp@/usr/lib64/libc.so.6']
    for std, line in usdt.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            if std != PerfProf.STDOUT:
                pytest.fail(line)
