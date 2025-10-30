#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def expr(args, runtime, memleak_check):
    cmdline = ["expr"]
    cmdline.extend(args)
    expr = PerfProf(cmdline)
    for std, line in expr.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_expr_sched_wakeup_u0(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid'], runtime, memleak_check)
def test_expr_sched_wakeup_u1(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned int)pid'], runtime, memleak_check)
def test_expr_sched_wakeup_u2(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned int *)comm'], runtime, memleak_check)
def test_expr_sched_wakeup_u3(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '*(unsigned int *)&pid'], runtime, memleak_check)
def test_expr_sched_wakeup_u4(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '++pid'], runtime, memleak_check)
def test_expr_sched_wakeup_u5(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '++(unsigned int)pid'], runtime, memleak_check)
def test_expr_sched_wakeup_u6(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned int)++pid'], runtime, memleak_check)
def test_expr_sched_wakeup_u7(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned int *)comm + 2'], runtime, memleak_check)
def test_expr_sched_wakeup_u8(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '&common_pid + 2'], runtime, memleak_check)
def test_expr_sched_wakeup_u9(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned int *)&pid - (unsigned int *)comm'], runtime, memleak_check)
def test_expr_sched_wakeup_u10(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned long *)&pid - (unsigned long *)comm'], runtime, memleak_check)
def test_expr_sched_wakeup_u11(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned long *)&pid - 2'], runtime, memleak_check)
def test_expr_sched_wakeup_u12(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid - 2'], runtime, memleak_check)
def test_expr_sched_wakeup_u13(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned int)pid++'], runtime, memleak_check)
def test_expr_sched_wakeup_u14(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '((unsigned long)pid)++'], runtime, memleak_check)
def test_expr_sched_wakeup_u15(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '((unsigned int *)pid)++'], runtime, memleak_check)
def test_expr_sched_wakeup_u16(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '((unsigned int **)pid)++'], runtime, memleak_check)
def test_expr_sched_wakeup_u17(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'comm[sizeof(int)]'], runtime, memleak_check)
def test_expr_sched_wakeup_u18(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'comm[sizeof(int *)]'], runtime, memleak_check)
def test_expr_sched_wakeup_u19(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '((unsigned int *)comm)[sizeof(int *)]'], runtime, memleak_check)

def test_expr_sched_wakeup0(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '&pid'], runtime, memleak_check)
def test_expr_sched_wakeup1(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '1#test//note'], runtime, memleak_check)
def test_expr_sched_wakeup2(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'sizeof(char)+sizeof(short)+sizeof(int)+sizeof(long)+sizeof(char *)+sizeof(short *)+sizeof(int *)+sizeof(long *)+sizeof(long **)'], runtime, memleak_check)
def test_expr_sched_wakeup2_u1(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'sizeof(unsigned char)+sizeof(unsigned short)+sizeof(unsigned)+sizeof(unsigned long)+sizeof(unsigned char *)+sizeof(unsigned short *)+sizeof(unsigned int *)+sizeof(unsigned long *)+sizeof(unsigned long **)'], runtime, memleak_check)
def test_expr_sched_wakeup3(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(char *)&pid + 1'], runtime, memleak_check)
def test_expr_sched_wakeup3_u1(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned int *)&pid + 2'], runtime, memleak_check)
def test_expr_sched_wakeup4(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("*(char *)&pid=%d, *comm=%c, comm=%s ", *(char *)&pid, *comm, comm)'], runtime, memleak_check)
def test_expr_sched_wakeup4_u1(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("*(unsigned char *)&pid=%d, *comm=%c, comm=%s ", *(unsigned char *)&pid, *comm, comm)'], runtime, memleak_check)
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
    expr(['-e', 'sched:sched_wakeup/pid<prio/', '(char *)&pid + 3'], runtime, memleak_check)

def test_expr_kfree_skb(runtime, memleak_check):
    expr(['-e', 'skb:kfree_skb', 'printf("protocol=%d ", ntohs(protocol))'], runtime, memleak_check)

def test_expr_mm_page_alloc(runtime, memleak_check):
    expr(['-e', 'kmem:mm_page_alloc/order>0/', '1<<order', '-v'], runtime, memleak_check)

def test_expr_workqueue_execute_start(runtime, memleak_check):
    expr(['-e', 'workqueue:workqueue_execute_start', 'printf("=%s=", ksymbol(function))', '-v'], runtime, memleak_check)

def test_expr_sched_process_exec(runtime, memleak_check):
    expr(['-e', 'sched:sched_process_exec', 'printf("=%s=", filename)'], runtime, memleak_check)

def test_expr_workqueue_execute_start_u0(runtime, memleak_check):
    expr(['-e', 'workqueue:workqueue_execute_start', 'printf("work=%ld work*2=%ld work*2=%ld work>0=%ld work<0=%ld", work, work*2, (long)work*2, (long)work>0, (long)work<0)'], runtime, memleak_check)

def test_expr_workqueue_execute_start_u1(runtime, memleak_check):
    expr(['-e', 'workqueue:workqueue_execute_start', 'printf("work=%ld work/2=%ld work/2=%ld work%55=%ld work%55=%ld", work, work/2, (long)work/2, work%55, (long)work%55)'], runtime, memleak_check)
