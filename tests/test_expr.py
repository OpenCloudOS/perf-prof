#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def expr(args, runtime, memleak_check):
    cmdline = ["expr"]
    cmdline.extend(args)
    expr = PerfProf(cmdline)
    for std, line in expr.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_expr_sched_wakeup0(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '&pid'], runtime, memleak_check)
def test_expr_sched_wakeup1(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '1#test//note'], runtime, memleak_check)
def test_expr_sched_wakeup2(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'sizeof(char)+sizeof(short)+sizeof(int)+sizeof(long)+sizeof(char *)+sizeof(short *)+sizeof(int *)+sizeof(long *)+sizeof(long **)'], runtime, memleak_check)
def test_expr_sched_wakeup3(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(char *)&pid + 1'], runtime, memleak_check)
def test_expr_sched_wakeup4(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("*(char *)&pid=%d, *comm=%c, comm=%s ", *(char *)&pid, *comm, comm)'], runtime, memleak_check)
def test_expr_sched_wakeup5(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("!success=%d, ~common_flags=%x, +pid=%d, -pid=%d ", !success, ~common_flags, +pid, -pid)'], runtime, memleak_check)
def test_expr_sched_wakeup6(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("++pid=%d, --pid=%d ", ++pid, --pid)'], runtime, memleak_check)
def test_expr_sched_wakeup7(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid=100,success=0,comm[0]=\'A\',printf("pid=%d, success=%d, comm=%s ", pid, success, comm)'], runtime, memleak_check)
def test_expr_sched_wakeup8(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("pid||sucess=%d, !success||0&&pid=%d, pid&&0=%d ", pid||success, !success||0&&pid, pid&&0)'], runtime, memleak_check)
def test_expr_sched_wakeup9(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("pid=%x, pid|0xff=0x%x, pid&0xf0=0x%x, pid^0xff=0x%x ", pid, pid|0xff, pid&0xf0, pid^0xff)'], runtime, memleak_check)
def test_expr_sched_wakeup10(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("pid>0:%d, pid>=0:%d, pid<0:%d, pid<=0:%d, pid==0:%d, pid!=0:%d ", pid>0, pid>=0, pid<0, pid<=0, pid==0, pid!=0)'], runtime, memleak_check)
def test_expr_sched_wakeup11(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("pid=0x%x, pid<<4=0x%x, pid>>8=0x%x ", pid, pid<<4, pid>>8)'], runtime, memleak_check)
def test_expr_sched_wakeup12(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("pid=%d, pid+5=%d, pid-10=%d, pid%10=%d, pid*10=%d, pid/10=%d ", pid, pid+5, pid-10, pid%10, pid*10, pid/10)'], runtime, memleak_check)
def test_expr_sched_wakeup13(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("pid=%d, pid++=%d, pid--=%d, pid=%d ", pid, pid++, pid--, pid)'], runtime, memleak_check)
def test_expr_sched_wakeup14(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("pid=%d, %s %s !", pid, "hello", "world")'], runtime, memleak_check)
def test_expr_sched_wakeup15(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("strcmp(%s, sap, 3) = %d", comm, strncmp(comm, "sap", 3))'], runtime, memleak_check)
def test_expr_sched_wakeup16(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup/pid<prio/', '(char *)&pid + 1'], runtime, memleak_check)

def test_expr_kfree_skb(runtime, memleak_check):
    expr(['-e', 'skb:kfree_skb', 'printf("protocol=%d ", ntohs(protocol))'], runtime, memleak_check)

def test_expr_mm_page_alloc(runtime, memleak_check):
    expr(['-e', 'kmem:mm_page_alloc/order>0/', '1<<order', '-v'], runtime, memleak_check)

def test_expr_workqueue_execute_start(runtime, memleak_check):
    expr(['-e', 'workqueue:workqueue_execute_start', 'printf("=%s=", ksymbol(function))', '-v'], runtime, memleak_check)

def test_expr_sched_process_exec(runtime, memleak_check):
    expr(['-e', 'sched:sched_process_exec', 'printf("=%s=", (char *)&common_type + filename_offset)'], runtime, memleak_check)
