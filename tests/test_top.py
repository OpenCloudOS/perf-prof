#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_sched_wakeup(runtime, memleak_check):
    #perf-prof top -e sched:sched_wakeup//comm=comm/ --only-comm -m 64
    top = PerfProf(['top', '-e', 'sched:sched_wakeup//comm=comm/', '--only-comm', '-m', '64'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_block_rq_issue(runtime, memleak_check):
    #perf-prof top -e block:block_rq_issue//top-by=nr_sector/comm=comm/ --only-comm -m 32
    top = PerfProf(['top', '-e', 'block:block_rq_issue//top-by=nr_sector/comm=comm/', '--only-comm', '-m', '32'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_block_rq_issue_filter(runtime, memleak_check):
    #perf-prof top -e 'block:block_rq_issue/rwbs==W&&nr_sector<4/top-by=nr_sector/comm=comm/' --only-comm -i 1000
    top = PerfProf(['top', '-e', 'block:block_rq_issue/rwbs=="W"&&nr_sector<4/top-by=nr_sector/comm=comm/', '--only-comm', '-m', '32'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_kvm_exit(runtime, memleak_check):
    exist, _ = PerfProf.tracepoint_exists('kvm:kvm_exit')
    if not exist:
        pytest.skip("'kvm:kvm_exit' does not exist")

    #perf-prof top -e kvm:kvm_exit//key=exit_reason/ -i 1000
    top = PerfProf(['top', '-e', 'kvm:kvm_exit//key=exit_reason/', '-i', '1000'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sched_stat_runtime(runtime, memleak_check):
    #perf-prof top -e sched:sched_stat_runtime//key=pid/comm=comm/top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/ -m 64
    top = PerfProf(['top', '-e', 'sched:sched_stat_runtime//key=pid/comm=comm/top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/', '-m', '64'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_sched_process_exec(runtime, memleak_check):
    #perf-prof top -e sched:sched_process_exec//comm=filename/ --only-comm
    top = PerfProf(['top', '-e', 'sched:sched_process_exec//comm="(char *)&common_type+filename_offset"/', '--only-comm'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_irq_handler_entry(runtime, memleak_check):
    #perf-prof top -e irq:irq_handler_entry//comm="(char *)&common_type+name_offset"/  --only-comm
    top = PerfProf(['top', '-e', 'irq:irq_handler_entry//comm="(char *)&common_type+name_offset"/', '--only-comm'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_workqueue_execute_start(runtime, memleak_check):
    #perf-prof top -e 'workqueue:workqueue_execute_start//key=common_pid/alias=NUM/comm=ksymbol(function)/' --only-comm
    top = PerfProf(['top', '-e', 'workqueue:workqueue_execute_start//key=common_pid/alias=NUM/comm=ksymbol(function)/', '--only-comm'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_kmem_cache_alloc(runtime, memleak_check):
    #perf-prof top -e 'kmem:kmem_cache_alloc//top-by=bytes_alloc/comm=ksymbol(call_site)/' --only-comm -m 64
    top = PerfProf(['top', '-e', 'kmem:kmem_cache_alloc//top-by=bytes_alloc/comm=ksymbol(call_site)/', '--only-comm', '-m', '64'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_3event(runtime, memleak_check):
    #perf-prof top -e sched:sched_switch//key=prev_pid/comm=prev_comm/,sched:sched_wakeup//key=pid/comm=comm/,sched:sched_stat_runtime//top-by="runtime/1000"/alias=run(us)/ -m 64
    top = PerfProf(['top', '-e', 'sched:sched_switch//key=prev_pid/comm=prev_comm/,sched:sched_wakeup//key=pid/comm=comm/,sched:sched_stat_runtime//top-by="runtime/1000"/alias=run(us)/', '-m', '64'])
    for std, line in top.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
