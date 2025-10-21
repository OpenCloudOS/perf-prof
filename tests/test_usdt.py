#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check
import pytest

def test_usdt_list(runtime, memleak_check):
    if memleak_check:
        pytest.skip("'perf-prof usdt' does not require '--memleak-check'")

    usdt = PerfProf(['usdt', 'list', 'pthread_create@/usr/lib64/libpthread.so.0'])
    usdt += ['setjmp@/usr/lib64/libc.so.6', 'longjmp@/usr/lib64/libc.so.6', '-v']
    for std, line in usdt.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_usdt_add(runtime, memleak_check):
    if memleak_check:
        pytest.skip("'perf-prof usdt' does not require '--memleak-check'")

    usdt = PerfProf(['usdt', 'add', 'libpthread:pthread_create@/usr/lib64/libpthread.so.0'])
    usdt += ['setjmp@/usr/lib64/libc.so.6']
    for std, line in usdt.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_usdt_trace_pthread_create(runtime, memleak_check):
    trace = PerfProf(['trace', '-e', 'libpthread:pthread_create,libc:setjmp', '-m', '8'])
    for std, line in trace.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_usdt_del(runtime, memleak_check):
    if memleak_check:
        pytest.skip("'perf-prof usdt' does not require '--memleak-check'")

    usdt = PerfProf(['usdt', 'del', 'pthread_create@/usr/lib64/libpthread.so.0'])
    usdt += ['setjmp@/usr/lib64/libc.so.6']
    for std, line in usdt.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_usdt_add_python1(runtime, memleak_check):
    if memleak_check:
        pytest.skip("'perf-prof usdt' does not require '--memleak-check'")

    arg = ['python:function__entry@/lib64/libpython3.6m.so.1.0 filename=+0(%s):string funcname=+0(%s):string lineno=%s:s32']
    arg += ['python:function__return@/lib64/libpython3.6m.so.1.0']
    usdt = PerfProf(['usdt', 'add'] + arg)
    for std, line in usdt.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
    usdt = PerfProf(['usdt', 'del'] + arg)
    for std, line in usdt.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_usdt_add_python2(runtime, memleak_check):
    if memleak_check:
        pytest.skip("'perf-prof usdt' does not require '--memleak-check'")

    arg = ['python:function__entry@/lib64/libpython3.6m.so.1.0 filename=+0(%s):string funcname=+0(%s):string']
    arg += ['python:function__return@/lib64/libpython3.6m.so.1.0 filename=+0(%s):string funcname=+0(error):string']
    usdt = PerfProf(['usdt', 'add'] + arg)
    for std, line in usdt.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
    usdt = PerfProf(['usdt', 'del'] + arg)
    for std, line in usdt.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
