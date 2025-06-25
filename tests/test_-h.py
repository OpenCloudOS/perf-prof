#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def get_profilers(args, runtime):
    profiler_start = False
    profilers = []
    perf_prof = PerfProf(args)
    for std, line in perf_prof.run():
        if runtime > 0:
            print(line, end='', flush=True)
        assert std == PerfProf.STDERR
        if line.find('Available Profilers:') >= 0:
            profiler_start = True
            continue
        if line.find('Available eBPF Profilers:') >= 0:
            profiler_start = True
            continue
        if profiler_start:
            if line == '\n':
                profiler_start = False
                continue
            profiler = line.split(maxsplit=1)
            assert len(profiler) == 2
            profilers.append(profiler[0])
    return profilers

def test_perf_prof__h(runtime, memleak_check):
    if memleak_check:
        pytest.skip("'perf-prof -h' does not require '--memleak-check'")

    profilers = get_profilers([], runtime)
    profilers_h = get_profilers(['-h'], runtime)

    assert profilers == profilers_h

    if runtime > 0:
        print(profilers)

    for profiler in profilers:
        profiler_h = PerfProf([profiler, '-h'])
        examples_exist = False
        for std, line in profiler_h.run(runtime):
            print(line, end='', flush=True)
            assert std == PerfProf.STDERR
            if line.find('Usage:') >= 0:
                usage = line.split()
                assert usage[1] == 'perf-prof'
                if profiler == 'help':
                    assert usage[-1] == profiler
                else:
                    assert usage[2] == profiler
            if line.strip() == 'EXAMPLES':
                examples_exist = True
        if runtime > 0:
            assert examples_exist
