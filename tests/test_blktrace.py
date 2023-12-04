#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_blktrace(runtime, memleak_check):
    #perf-prof blktrace -d /dev/sda -i 1000 --than 10ms
    block_devices = PerfProf.scan_block_devices('/dev')

    for device in block_devices:
        prof = PerfProf(["blktrace", '-d', '/dev/' + device, '-i', '1000', '--than', '10ms'])
        for std, line in prof.run(runtime, memleak_check):
            result_check(std, line, runtime, memleak_check)