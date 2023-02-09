#!/usr/bin/env python3

from PerfProf import PerfProf
import pytest

def test_kmemleak_kmalloc(runtime, memleak_check):
    kmemleak = PerfProf(['kmemleak',
                '--alloc', 'kmem:kmalloc//ptr=ptr/size=bytes_req/,kmem:kmalloc_node//ptr=ptr/size=bytes_req/',
                '--free', 'kmem:kfree//ptr=ptr/',
                '-m', '256', '--order', '--order-mem', '64M', '-g'])
    for std, line in kmemleak.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


def test_kmemleak_kmem_cache_alloc(runtime, memleak_check):
    kmemleak = PerfProf(['kmemleak',
                '--alloc', 'kmem:kmem_cache_alloc//ptr=ptr/size=bytes_req/stack/,kmem:kmem_cache_alloc_node//ptr=ptr/size=bytes_req/stack/',
                '--free', 'kmem:kmem_cache_free//ptr=ptr/',
                '-m', '256', '--order', '--order-mem', '64M'])
    for std, line in kmemleak.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


def test_kmemleak_mm_page_alloc(runtime, memleak_check):
    alloc_format = PerfProf.event_format('kmem:mm_page_alloc')
    free_format = PerfProf.event_format('kmem:mm_page_free')
    if alloc_format == None or free_format == None:
        pytest.skip("'kmem:mm_page_alloc' or 'kmem:mm_page_free' does not exist")

    if 'page' in alloc_format['field']:
        alloc_ptr = 'page'
    elif 'pfn' in alloc_format['field']:
        alloc_ptr = 'pfn'
    else:
        pytest.skip("'page' or 'pfn' not in 'kmem:mm_page_alloc'")

    if 'page' in free_format['field']:
        free_ptr = 'page'
    elif 'pfn' in free_format['field']:
        free_ptr = 'pfn'
    else:
        pytest.skip("'page' or 'pfn' not in 'kmem:mm_page_alloc'")

    kmemleak = PerfProf(['kmemleak',
                '--alloc', 'kmem:mm_page_alloc//ptr={ptr}/size=4096<<order/key={ptr}/stack/'.format(ptr=alloc_ptr),
                '--free', 'kmem:mm_page_free//ptr={ptr}/key={ptr}/stack/'.format(ptr=free_ptr),
                '-m', '256', '--order', '--order-mem', '64M'])
    for std, line in kmemleak.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT


def test_kmemprof_percpu_alloc(runtime, memleak_check):
    exist, _ = PerfProf.tracepoint_exists('percpu:percpu_alloc_percpu', 'percpu:percpu_free_percpu')
    if not exist:
        pytest.skip("'percpu:percpu_alloc_percpu' or 'percpu:percpu_free_percpu' does not exist")

    kmemleak = PerfProf(['kmemleak',
                '--alloc', 'percpu:percpu_alloc_percpu//ptr=ptr/size=size/stack/',
                '--free', 'percpu:percpu_free_percpu//ptr=ptr/stack/',
                '-m', '256', '--order', '--order-mem', '64M'])
    for std, line in kmemleak.run(runtime, memleak_check):
        if not memleak_check or (
            std == PerfProf.STDERR and not PerfProf.lost_events(line)):
            print(line, end='', flush=True)
        if not memleak_check:
            assert std == PerfProf.STDOUT

