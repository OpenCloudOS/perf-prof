#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check
import pytest

def test_kmemprof_kmalloc(runtime, memleak_check):
    kmemprof = PerfProf(['kmemprof',
                '-e', 'kmem:kmalloc//ptr=ptr/size=bytes_req/stack/,kmem:kmalloc_node//ptr=ptr/size=bytes_req/stack/',
                '-e', 'kmem:kfree//ptr=ptr/stack/',
                '-m', '512', '--order', '-i', '1000', '-k', 'ptr'])
    for std, line in kmemprof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_kmemprof_kmem_cache_alloc(runtime, memleak_check):
    kmemprof = PerfProf(['kmemprof',
                '-e', 'kmem:kmem_cache_alloc//ptr=ptr/size=bytes_req/stack/,kmem:kmem_cache_alloc_node//ptr=ptr/size=bytes_req/stack/',
                '-e', 'kmem:kmem_cache_free//ptr=ptr/stack/',
                '-m', '512', '--order', '-i', '1000', '-k', 'ptr'])
    for std, line in kmemprof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_kmemprof_mm_page_alloc(runtime, memleak_check):
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

    kmemprof = PerfProf(['kmemprof',
                '-e', 'kmem:mm_page_alloc//ptr={ptr}/size=4096<<order/key={ptr}/stack/'.format(ptr=alloc_ptr),
                '-e', 'kmem:mm_page_free//ptr={ptr}/key={ptr}/stack/'.format(ptr=free_ptr),
                '-m', '512', '--order', '-i', '1000'])
    for std, line in kmemprof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_kmemprof_percpu_alloc(runtime, memleak_check):
    exist, _ = PerfProf.tracepoint_exists('percpu:percpu_alloc_percpu', 'percpu:percpu_free_percpu')
    if not exist:
        pytest.skip("'percpu:percpu_alloc_percpu' or 'percpu:percpu_free_percpu' does not exist")

    kmemprof = PerfProf(['kmemprof',
                '-e', 'percpu:percpu_alloc_percpu//ptr=ptr/size=size/stack/',
                '-e', 'percpu:percpu_free_percpu//ptr=ptr/stack/',
                '-m', '512', '--order', '-i', '1000', '-k', 'ptr'])
    for std, line in kmemprof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

