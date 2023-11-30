#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test___symbols(runtime, memleak_check):
    if memleak_check:
        pytest.skip("'perf-prof --symbols' does not require '--memleak-check'")

    usdt = PerfProf(['--symbols', '/usr/lib64/libc.so.6'])
    input = '000000-1ba000 r-xp 00000000 08:01 401923                     /usr/lib64/libc.so.6\n'
    input += '0xf8870\n'
    input += '0xef900\n'
    for std, line in usdt.run(runtime, input=input):
        print(line, end='', flush=True)
        if std != PerfProf.STDOUT:
            pytest.fail(line)
        assert line != '??\n'
