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
    expr(['-e', 'sched:sched_wakeup', 'printf("pid=%d, %s %s !", pid>100?pid:100, "hello", "world")'], runtime, memleak_check)
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

# Tests for event help functionality
def test_expr_help_sched_wakeup(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'help'], runtime, memleak_check)

def test_expr_help_kmem_kmalloc(runtime, memleak_check):
    expr(['-e', 'kmem:kmalloc', 'help'], runtime, memleak_check)

def test_expr_help_multiple_events(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup,sched:sched_switch', 'help'], runtime, memleak_check)

# Tests for built-in functions
def test_expr_builtin_ksymbol(runtime, memleak_check):
    expr(['-e', 'workqueue:workqueue_execute_start', 'ksymbol(function)'], runtime, memleak_check)

def test_expr_builtin_ntohl(runtime, memleak_check):
    expr(['-e', 'skb:kfree_skb', 'ntohl(protocol)'], runtime, memleak_check)

def test_expr_builtin_ntohs(runtime, memleak_check):
    expr(['-e', 'skb:kfree_skb', 'ntohs(protocol)'], runtime, memleak_check)

def test_expr_builtin_strncmp(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'strncmp(comm, "systemd", 6)'], runtime, memleak_check)

# Tests for complex expressions
def test_expr_complex_ternary(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'prio < 100 ? pid : 0'], runtime, memleak_check)

def test_expr_complex_bitwise(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(target_cpu & 0xF) | (prio << 4)'], runtime, memleak_check)

def test_expr_complex_logical(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid > 0 && prio < 100 && success == 1'], runtime, memleak_check)

def test_expr_complex_casting(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '(unsigned long)common_pid | ((unsigned long)target_cpu << 32)'], runtime, memleak_check)

def test_expr_complex_pointer_arithmetic(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '*(comm + 1)'], runtime, memleak_check)

def test_expr_complex_array_access(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'comm[sizeof(int)]'], runtime, memleak_check)

# Tests for operator precedence
def test_expr_precedence_1(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid++ + prio'], runtime, memleak_check)

def test_expr_precedence_2(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '!success + 1'], runtime, memleak_check)

def test_expr_precedence_3(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid * 10 + prio / 5'], runtime, memleak_check)

def test_expr_precedence_4(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid << 4 | target_cpu'], runtime, memleak_check)

def test_expr_precedence_5(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid & 0xFF ^ target_cpu'], runtime, memleak_check)

def test_expr_precedence_6(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid > 100 && prio < 50 || success'], runtime, memleak_check)

def test_expr_precedence_7(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid > 100 ? prio : target_cpu'], runtime, memleak_check)

def test_expr_precedence_8(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid = target_cpu = 1000'], runtime, memleak_check)

# Tests for memory operations
def test_expr_memory_dereference(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '*&pid'], runtime, memleak_check)

def test_expr_memory_address(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '&common_pid - &pid'], runtime, memleak_check)

def test_expr_constant_expression(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', '42'], runtime, memleak_check)

def test_expr_string_constant(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("constant string")'], runtime, memleak_check)

# Tests for multiple expressions with comma operator
def test_expr_comma_operator(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'pid = 100, prio = 50, target_cpu'], runtime, memleak_check)

# Tests for nested function calls
def test_expr_nested_function_calls(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup', 'printf("pid=%d, prio=%d", pid, prio)'], runtime, memleak_check)

# Tests with filtered events
def test_expr_with_filter_numeric(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup/pid>1000/', 'pid'], runtime, memleak_check)

def test_expr_with_filter_string(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup/comm~"systemd"/', 'prio'], runtime, memleak_check)

def test_expr_with_filter_complex(runtime, memleak_check):
    expr(['-e', 'sched:sched_wakeup/pid>100 && prio<50/', 'target_cpu'], runtime, memleak_check)

# Tests for different event types
def test_expr_kmem_events(runtime, memleak_check):
    expr(['-e', 'kmem:kmalloc', 'bytes_alloc'], runtime, memleak_check)

def test_expr_timer_events(runtime, memleak_check):
    expr(['-e', 'timer:hrtimer_expire_entry', 'function'], runtime, memleak_check)

def test_expr_irq_events(runtime, memleak_check):
    expr(['-e', 'irq:softirq_entry', 'vec'], runtime, memleak_check)

# Performance and stress tests
def test_expr_large_expression(runtime, memleak_check):
    large_expr = 'pid + prio + target_cpu + common_pid + success'
    for i in range(10):
        large_expr += f' + {i}'
    expr(['-e', 'sched:sched_wakeup', large_expr], runtime, memleak_check)

def test_expr_deep_nesting(runtime, memleak_check):
    nested_expr = 'pid > 0 ? (prio < 100 ? (success == 1 ? target_cpu : 0) : 1) : 2'
    expr(['-e', 'sched:sched_wakeup', nested_expr], runtime, memleak_check)

# Tests for userspace ftrace filter with __cpu and __pid variables
def test_expr_userspace_filter_cpu_variable(runtime, memleak_check):
    # Test __cpu variable in userspace ftrace filter
    expr(['-e', 'sched:sched_wakeup/__cpu==0/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_pid_variable(runtime, memleak_check):
    # Test __pid variable in userspace ftrace filter
    expr(['-e', 'sched:sched_wakeup/__pid>1/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_cpu_pid_combined(runtime, memleak_check):
    # Test __cpu and __pid variables combined in userspace ftrace filter
    expr(['-e', 'sched:sched_wakeup/__cpu==0&&__pid>100/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_cpu_range(runtime, memleak_check):
    # Test __cpu variable with range in userspace ftrace filter
    expr(['-e', 'sched:sched_wakeup/__cpu>=0&&__cpu<=3/', 'target_cpu'], runtime, memleak_check)

def test_expr_userspace_filter_pid_comparison(runtime, memleak_check):
    # Test __pid variable with comparison in userspace ftrace filter
    expr(['-e', 'sched:sched_wakeup/__pid!=common_pid/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_complex_cpu_pid(runtime, memleak_check):
    # Test complex expression with __cpu and __pid variables
    expr(['-e', 'sched:sched_wakeup/(__cpu&1)==0&&(__pid%2)==0/', 'prio'], runtime, memleak_check)

def test_expr_userspace_filter_cpu_with_event_fields(runtime, memleak_check):
    # Test __cpu variable combined with event fields
    expr(['-e', 'sched:sched_wakeup/__cpu==target_cpu/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_pid_with_event_fields(runtime, memleak_check):
    # Test __pid variable combined with event fields
    expr(['-e', 'sched:sched_wakeup/__pid==pid/', 'target_cpu'], runtime, memleak_check)

def test_expr_userspace_filter_cpu_ternary(runtime, memleak_check):
    # Test __cpu variable in ternary expression within filter
    expr(['-e', 'sched:sched_wakeup/__cpu>1?pid<1000:prio>50/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_pid_bitwise(runtime, memleak_check):
    # Test __pid variable with bitwise operations in filter
    expr(['-e', 'sched:sched_wakeup/(__pid&0xFF)>10/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_cpu_math_operations(runtime, memleak_check):
    # Test __cpu variable with math operations in filter
    expr(['-e', 'sched:sched_wakeup/__cpu*2<target_cpu/', 'target_cpu'], runtime, memleak_check)

def test_expr_userspace_filter_multiple_events_cpu(runtime, memleak_check):
    # Test __cpu variable with multiple events
    expr(['-e', 'sched:sched_wakeup/__cpu==0/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_multiple_events_pid(runtime, memleak_check):
    # Test __pid variable with multiple events
    expr(['-e', 'sched:sched_wakeup/__pid>100/', 'prio'], runtime, memleak_check)

def test_expr_userspace_filter_kmem_events_cpu(runtime, memleak_check):
    # Test __cpu variable with kmem events
    expr(['-e', 'kmem:kmalloc/__cpu==1/', 'bytes_alloc'], runtime, memleak_check)

def test_expr_userspace_filter_kmem_events_pid(runtime, memleak_check):
    # Test __pid variable with kmem events
    expr(['-e', 'kmem:kmalloc/__pid>1/', 'bytes_alloc'], runtime, memleak_check)

def test_expr_userspace_filter_timer_events_cpu(runtime, memleak_check):
    # Test __cpu variable with timer events
    expr(['-e', 'timer:hrtimer_expire_entry/__cpu<=3/', 'function'], runtime, memleak_check)

def test_expr_userspace_filter_irq_events_cpu(runtime, memleak_check):
    # Test __cpu variable with irq events
    expr(['-e', 'irq:softirq_entry/__cpu==0/', 'vec'], runtime, memleak_check)

def test_expr_userspace_filter_with_attributes_cpu(runtime, memleak_check):
    # Test __cpu variable with event attributes
    expr(['-e', 'sched:sched_wakeup/__cpu==0/alias=wakeup/stack/', 'pid'], runtime, memleak_check)

def test_expr_userspace_filter_with_attributes_pid(runtime, memleak_check):
    # Test __pid variable with event attributes
    expr(['-e', 'sched:sched_wakeup/__pid>100/alias=wakeup/comm=comm/', 'prio'], runtime, memleak_check)


# Tests for ~ operator (wildcard pattern matching)

def test_expr_match_basic(runtime, memleak_check):
    # Test basic match functionality
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*perf*"'], runtime, memleak_check)

def test_expr_match_star_wildcard(runtime, memleak_check):
    # Test * wildcard matches any characters
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*sh"'], runtime, memleak_check)

def test_expr_match_star_prefix(runtime, memleak_check):
    # Test * wildcard at end
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "sys*"'], runtime, memleak_check)

def test_expr_match_star_middle(runtime, memleak_check):
    # Test * wildcard in middle
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "s*p"'], runtime, memleak_check)

def test_expr_match_multiple_stars(runtime, memleak_check):
    # Test multiple * wildcards
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*a*e*"'], runtime, memleak_check)

def test_expr_match_question_mark(runtime, memleak_check):
    # Test ? wildcard matches single character
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "?ap*"'], runtime, memleak_check)

def test_expr_match_multiple_question_marks(runtime, memleak_check):
    # Test multiple ? wildcards
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "???"'], runtime, memleak_check)

def test_expr_match_char_class(runtime, memleak_check):
    # Test [abc] character class
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "[gsp]*"'], runtime, memleak_check)

def test_expr_match_char_range(runtime, memleak_check):
    # Test [a-z] character range
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "[a-z]*"'], runtime, memleak_check)

def test_expr_match_multiple_ranges(runtime, memleak_check):
    # Test multiple ranges in character class
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "[a-zA-Z0-9]*"'], runtime, memleak_check)

def test_expr_match_negated_char_class(runtime, memleak_check):
    # Test [^abc] negated character class with ^
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "[^0-9]*"'], runtime, memleak_check)

def test_expr_match_negated_char_class_exclaim(runtime, memleak_check):
    # Test [!abc] negated character class with !
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "[!0-9]*"'], runtime, memleak_check)

def test_expr_match_exact_match(runtime, memleak_check):
    # Test exact string matching
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "swapper"'], runtime, memleak_check)

def test_expr_match_match_all(runtime, memleak_check):
    # Test * matches everything
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*"'], runtime, memleak_check)

def test_expr_match_empty_pattern(runtime, memleak_check):
    # Test empty pattern
    expr(['-e', 'sched:sched_wakeup', 'comm ~ ""'], runtime, memleak_check)

def test_expr_match_with_printf(runtime, memleak_check):
    # Test match with printf for debugging
    expr(['-e', 'sched:sched_wakeup', 'printf("comm=%s match=%d ", comm, comm ~ "*perf*")'], runtime, memleak_check)

def test_expr_match_logical_or(runtime, memleak_check):
    # Test match with OR operator
    expr(['-e', 'sched:sched_wakeup', 'comm ~"*sh" || comm ~ "*de"'], runtime, memleak_check)

def test_expr_match_logical_and(runtime, memleak_check):
    # Test match with AND operator
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*s*" && comm ~ "*e*"'], runtime, memleak_check)

def test_expr_match_negation(runtime, memleak_check):
    # Test match with NOT operator
    expr(['-e', 'sched:sched_wakeup', '!(comm ~ "swapper")'], runtime, memleak_check)

def test_expr_match_ternary(runtime, memleak_check):
    # Test match in ternary expression
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*perf*" ? pid : 0'], runtime, memleak_check)

def test_expr_match_complex_pattern(runtime, memleak_check):
    # Test complex pattern with multiple wildcard types
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "[a-z]?p*"'], runtime, memleak_check)

def test_expr_match_multiple_patterns(runtime, memleak_check):
    # Test multiple match calls in one expression
    expr(['-e', 'sched:sched_wakeup', 'printf("perf:%d sys:%d ", comm ~ "*perf*", comm ~ "sys*")'], runtime, memleak_check)

def test_expr_match_with_filter(runtime, memleak_check):
    # Test match combined with event filter
    expr(['-e', 'sched:sched_wakeup/pid>100/', 'comm ~ "*sh"'], runtime, memleak_check)

def test_expr_match_userspace_filter(runtime, memleak_check):
    # Test match as userspace filter replacement
    expr(['-e', 'sched:sched_wakeup/comm ~ "*prof*"/', 'pid'], runtime, memleak_check)

def test_expr_match_userspace_filter_complex(runtime, memleak_check):
    # Test match in complex userspace filter
    expr(['-e', 'sched:sched_wakeup/(comm~"[gs]*"&&pid>100)/', 'target_cpu'], runtime, memleak_check)

def test_expr_match_with_cpu_variable(runtime, memleak_check):
    # Test match combined with __cpu variable
    expr(['-e', 'sched:sched_wakeup/__cpu==0&&comm~"*perf*"/', 'pid'], runtime, memleak_check)

def test_expr_match_with_pid_variable(runtime, memleak_check):
    # Test match combined with __pid variable
    expr(['-e', 'sched:sched_wakeup/__pid>1&&comm~"sys*"/', 'prio'], runtime, memleak_check)

def test_expr_match_different_events(runtime, memleak_check):
    # Test match with different event types
    expr(['-e', 'sched:sched_switch', 'prev_comm ~ "*perf*" || next_comm ~ "*perf*"'], runtime, memleak_check)

def test_expr_match_string_field(runtime, memleak_check):
    # Test match with different string fields
    expr(['-e', 'sched:sched_switch', 'prev_comm ~ "systemd*"'], runtime, memleak_check)

def test_expr_match_with_strncmp(runtime, memleak_check):
    # Test match combined with strncmp
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*sys*" && strncmp(comm, "sys", 3)==0'], runtime, memleak_check)

def test_expr_match_case_sensitive(runtime, memleak_check):
    # Test match is case-sensitive
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*PERF*"'], runtime, memleak_check)

def test_expr_match_char_class_mixed(runtime, memleak_check):
    # Test character class with both ranges and individual chars
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "[a-z0-9_-]*"'], runtime, memleak_check)

def test_expr_match_consecutive_stars(runtime, memleak_check):
    # Test consecutive stars behave like single star
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "***perf***"'], runtime, memleak_check)

def test_expr_match_star_question_combined(runtime, memleak_check):
    # Test * and ? combined
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "?*ap*"'], runtime, memleak_check)

def test_expr_match_result_as_condition(runtime, memleak_check):
    # Test match result directly as boolean condition
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*perf*" && pid > 0'], runtime, memleak_check)

def test_expr_match_with_assignment(runtime, memleak_check):
    # Test match result assigned to variable (uses expression side-effect)
    expr(['-e', 'sched:sched_wakeup', 'success = comm ~ "*perf*", success'], runtime, memleak_check)

def test_expr_match_nested_ternary(runtime, memleak_check):
    # Test match in nested ternary expressions
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*perf*" ? (pid > 100 ? 1 : 2) : 0'], runtime, memleak_check)

def test_expr_match_printf_formatted(runtime, memleak_check):
    # Test match with formatted printf output
    expr(['-e', 'sched:sched_wakeup', 'printf("%-16s | *perf*:%d [gs]*:%d ?ap*:%d ", comm, comm ~ "*perf*", comm ~ "[gs]*", comm ~ "?ap*")'], runtime, memleak_check)

def test_expr_match_three_patterns(runtime, memleak_check):
    # Test three different patterns simultaneously
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*sh" || comm ~ "*de" || comm ~ "sys*"'], runtime, memleak_check)

def test_expr_match_bitwise_result(runtime, memleak_check):
    # Test match result in bitwise operations
    expr(['-e', 'sched:sched_wakeup', '(comm ~ "*perf*") << 1) | comm ~ "[gs]*"'], runtime, memleak_check)

def test_expr_match_math_operations(runtime, memleak_check):
    # Test match result in math operations
    expr(['-e', 'sched:sched_wakeup', '(comm ~ "*perf*") * 100 + (comm ~ "[gs]*") * 10'], runtime, memleak_check)

def test_expr_match_comparison(runtime, memleak_check):
    # Test match result in comparison
    expr(['-e', 'sched:sched_wakeup', '(comm ~ "*perf*") == 1'], runtime, memleak_check)

def test_expr_match_wildcard_edge_cases(runtime, memleak_check):
    # Test edge case patterns
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "**"'], runtime, memleak_check)

def test_expr_match_question_star_combo(runtime, memleak_check):
    # Test ? followed by * in various positions
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "?*"'], runtime, memleak_check)

def test_expr_match_char_class_special_chars(runtime, memleak_check):
    # Test character class with special characters
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "[_-]*"'], runtime, memleak_check)

def test_expr_match_workqueue_events(runtime, memleak_check):
    # Test match with ksymbol function result
    expr(['-e', 'workqueue:workqueue_execute_start', 'ksymbol(function) ~ "*sched*"'], runtime, memleak_check)

def test_expr_match_exec_events(runtime, memleak_check):
    # Test match with filename field in exec events
    expr(['-e', 'sched:sched_process_exec', 'filename ~ "*/bin/*"'], runtime, memleak_check)

def test_expr_match_multiple_or_conditions(runtime, memleak_check):
    # Test match with multiple OR conditions (pattern matching multiple categories)
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*perf*" || comm ~ "*prof*" || comm ~ "claude"'], runtime, memleak_check)

def test_expr_match_complex_boolean_logic(runtime, memleak_check):
    # Test match with complex boolean logic
    expr(['-e', 'sched:sched_wakeup', '(comm ~ "*sys*" && pid > 100) || (comm ~ "[gs]*" && prio < 50)'], runtime, memleak_check)

def test_expr_match_with_comm_get(runtime, memleak_check):
    # Test match with comm_get function (if available)
    expr(['-e', 'sched:sched_wakeup', 'comm ~ comm_get(pid)'], runtime, memleak_check)

def test_expr_match_priority_lt(runtime, memleak_check):
    # Test ~ operator priority
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*perf*"+1 > 0'], runtime, memleak_check)

def test_expr_match_priority_equal(runtime, memleak_check):
    # Test ~ operator priority
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*perf*"+1 == 0'], runtime, memleak_check)

def test_expr_match_priority_equal1(runtime, memleak_check):
    # Test ~ operator priority
    expr(['-e', 'sched:sched_wakeup', '0 == comm+1 ~ "*perf*"+1'], runtime, memleak_check)


def test_expr_tilde_operator_ternary(runtime, memleak_check):
    # Test ~ operator in ternary expression
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*perf*" ? pid : 0'], runtime, memleak_check)

def test_expr_tilde_operator_userspace_filter(runtime, memleak_check):
    # Test ~ operator as userspace filter replacement
    expr(['-e', 'sched:sched_wakeup/comm ~ "*prof*"/', 'pid'], runtime, memleak_check)

def test_expr_tilde_operator_bitwise(runtime, memleak_check):
    # Test ~ operator result in bitwise operations
    expr(['-e', 'sched:sched_wakeup', '((comm ~ "*perf*") << 1) | (comm ~ "[gs]*")'], runtime, memleak_check)

def test_expr_tilde_operator_with_assignment(runtime, memleak_check):
    # Test ~ operator result assigned to variable
    expr(['-e', 'sched:sched_wakeup', 'success = (comm ~ "*perf*"), success'], runtime, memleak_check)


# Tests for string comparison operators (== and !=)

def test_expr_string_equality_basic(runtime, memleak_check):
    # Test == operator with string comparison
    expr(['-e', 'sched:sched_wakeup', 'comm == "systemd"'], runtime, memleak_check)

def test_expr_string_inequality_basic(runtime, memleak_check):
    # Test != operator with string comparison
    expr(['-e', 'sched:sched_wakeup', 'comm != "systemd"'], runtime, memleak_check)

def test_expr_string_equality_with_printf(runtime, memleak_check):
    # Test == operator with printf output
    expr(['-e', 'sched:sched_wakeup', 'printf("comm=%s match=%d ", comm, comm == "systemd")'], runtime, memleak_check)

def test_expr_string_inequality_with_printf(runtime, memleak_check):
    # Test != operator with printf output
    expr(['-e', 'sched:sched_wakeup', 'printf("comm=%s not_match=%d ", comm, comm != "systemd")'], runtime, memleak_check)

def test_expr_string_equality_exec_event(runtime, memleak_check):
    # Test == operator with process exec events
    expr(['-e', 'sched:sched_process_exec', 'filename == "/bin/sh"'], runtime, memleak_check)

def test_expr_string_inequality_exec_event(runtime, memleak_check):
    # Test != operator with process exec events
    expr(['-e', 'sched:sched_process_exec', 'filename != "/bin/sh"'], runtime, memleak_check)

def test_expr_string_equality_logical_and(runtime, memleak_check):
    # Test == operator with AND logic
    expr(['-e', 'sched:sched_wakeup', 'comm == "systemd" && pid > 1'], runtime, memleak_check)

def test_expr_string_inequality_logical_or(runtime, memleak_check):
    # Test != operator with OR logic
    expr(['-e', 'sched:sched_wakeup', 'comm != "systemd" || comm != "swapper"'], runtime, memleak_check)

def test_expr_string_equality_ternary(runtime, memleak_check):
    # Test == operator in ternary expression
    expr(['-e', 'sched:sched_wakeup', 'comm == "systemd" ? pid : 0'], runtime, memleak_check)

def test_expr_string_inequality_ternary(runtime, memleak_check):
    # Test != operator in ternary expression
    expr(['-e', 'sched:sched_wakeup', 'comm != "systemd" ? 1 : 0'], runtime, memleak_check)

def test_expr_string_equality_with_filter(runtime, memleak_check):
    # Test == operator combined with event filter
    expr(['-e', 'sched:sched_wakeup/pid>100/', 'comm == "systemd"'], runtime, memleak_check)

def test_expr_string_inequality_with_filter(runtime, memleak_check):
    # Test != operator combined with event filter
    expr(['-e', 'sched:sched_wakeup/prio<100/', 'comm != "swapper"'], runtime, memleak_check)

def test_expr_string_equality_userspace_filter(runtime, memleak_check):
    # Test == operator as userspace filter
    expr(['-e', 'sched:sched_wakeup/comm == "systemd"/', 'pid'], runtime, memleak_check)

def test_expr_string_inequality_userspace_filter(runtime, memleak_check):
    # Test != operator as userspace filter
    expr(['-e', 'sched:sched_wakeup/comm != "swapper"/', 'prio'], runtime, memleak_check)

def test_expr_string_equality_multiple_conditions(runtime, memleak_check):
    # Test == operator with multiple string comparisons
    expr(['-e', 'sched:sched_wakeup', 'comm == "systemd" || comm == "sshd"'], runtime, memleak_check)

def test_expr_string_inequality_multiple_conditions(runtime, memleak_check):
    # Test != operator with multiple string comparisons
    expr(['-e', 'sched:sched_wakeup', 'comm != "systemd" && comm != "swapper"'], runtime, memleak_check)

def test_expr_string_equality_sched_switch(runtime, memleak_check):
    # Test == operator with sched_switch event
    expr(['-e', 'sched:sched_switch', 'prev_comm == "systemd" || next_comm == "systemd"'], runtime, memleak_check)

def test_expr_string_inequality_sched_switch(runtime, memleak_check):
    # Test != operator with sched_switch event
    expr(['-e', 'sched:sched_switch', 'prev_comm != "swapper" && next_comm != "swapper"'], runtime, memleak_check)

def test_expr_string_equality_with_printf_formatted(runtime, memleak_check):
    # Test == operator with formatted printf
    expr(['-e', 'sched:sched_process_exec', 'printf("file=%s is_sh=%d ", filename, filename == "/bin/sh")'], runtime, memleak_check)

def test_expr_string_inequality_with_printf_formatted(runtime, memleak_check):
    # Test != operator with formatted printf
    expr(['-e', 'sched:sched_process_exec', 'printf("file=%s not_sh=%d ", filename, filename != "/bin/sh")'], runtime, memleak_check)

def test_expr_string_equality_negation(runtime, memleak_check):
    # Test == operator with NOT logic
    expr(['-e', 'sched:sched_wakeup', '!(comm == "swapper")'], runtime, memleak_check)

def test_expr_string_inequality_negation(runtime, memleak_check):
    # Test != operator with NOT logic
    expr(['-e', 'sched:sched_wakeup', '!(comm != "systemd")'], runtime, memleak_check)

def test_expr_string_equality_with_cpu_variable(runtime, memleak_check):
    # Test == operator combined with __cpu variable
    expr(['-e', 'sched:sched_wakeup/__cpu==0 && comm == "systemd"/', 'pid'], runtime, memleak_check)

def test_expr_string_inequality_with_pid_variable(runtime, memleak_check):
    # Test != operator combined with __pid variable
    expr(['-e', 'sched:sched_wakeup/__pid>1 && comm != "swapper"/', 'prio'], runtime, memleak_check)

def test_expr_string_equality_nested_ternary(runtime, memleak_check):
    # Test == operator in nested ternary expressions
    expr(['-e', 'sched:sched_wakeup', 'comm == "systemd" ? (pid > 100 ? 1 : 2) : 0'], runtime, memleak_check)

def test_expr_string_inequality_nested_ternary(runtime, memleak_check):
    # Test != operator in nested ternary expressions
    expr(['-e', 'sched:sched_wakeup', 'comm != "swapper" ? (prio < 100 ? 1 : 2) : 0'], runtime, memleak_check)

def test_expr_string_equality_assignment(runtime, memleak_check):
    # Test == operator result assigned to variable
    expr(['-e', 'sched:sched_wakeup', 'success = (comm == "systemd"), success'], runtime, memleak_check)

def test_expr_string_inequality_assignment(runtime, memleak_check):
    # Test != operator result assigned to variable
    expr(['-e', 'sched:sched_wakeup', 'success = (comm != "swapper"), success'], runtime, memleak_check)

def test_expr_string_equality_comparison_result(runtime, memleak_check):
    # Test == operator result in comparison
    expr(['-e', 'sched:sched_wakeup', '(comm == "systemd") == 1'], runtime, memleak_check)

def test_expr_string_inequality_comparison_result(runtime, memleak_check):
    # Test != operator result in comparison
    expr(['-e', 'sched:sched_wakeup', '(comm != "swapper") == 0'], runtime, memleak_check)

def test_expr_string_equality_with_match(runtime, memleak_check):
    # Test == operator combined with ~ operator
    expr(['-e', 'sched:sched_wakeup', 'comm == "systemd" || comm ~ "*perf*"'], runtime, memleak_check)

def test_expr_string_inequality_with_match(runtime, memleak_check):
    # Test != operator combined with ~ operator
    expr(['-e', 'sched:sched_wakeup', 'comm != "swapper" && comm ~ "*sh"'], runtime, memleak_check)

def test_expr_string_equality_empty_string(runtime, memleak_check):
    # Test == operator with empty string
    expr(['-e', 'sched:sched_wakeup', 'comm == ""'], runtime, memleak_check)

def test_expr_string_inequality_empty_string(runtime, memleak_check):
    # Test != operator with empty string
    expr(['-e', 'sched:sched_wakeup', 'comm != ""'], runtime, memleak_check)

def test_expr_string_equality_math_operations(runtime, memleak_check):
    # Test == operator result in math operations
    expr(['-e', 'sched:sched_wakeup', '(comm == "systemd") * 100 + (comm == "sshd") * 10'], runtime, memleak_check)

def test_expr_string_inequality_math_operations(runtime, memleak_check):
    # Test != operator result in math operations
    expr(['-e', 'sched:sched_wakeup', '(comm != "systemd") * 100 + pid'], runtime, memleak_check)

def test_expr_string_equality_bitwise_operations(runtime, memleak_check):
    # Test == operator result in bitwise operations
    expr(['-e', 'sched:sched_wakeup', '((comm == "systemd") << 1) | (comm == "sshd")'], runtime, memleak_check)

def test_expr_string_inequality_bitwise_operations(runtime, memleak_check):
    # Test != operator result in bitwise operations
    expr(['-e', 'sched:sched_wakeup', '((comm != "swapper") & 1) ^ (pid & 1)'], runtime, memleak_check)

def test_expr_string_equality_complex_boolean(runtime, memleak_check):
    # Test == operator with complex boolean logic
    expr(['-e', 'sched:sched_wakeup', '(comm == "systemd" && pid > 1) || (comm == "sshd" && prio < 100)'], runtime, memleak_check)

def test_expr_string_inequality_complex_boolean(runtime, memleak_check):
    # Test != operator with complex boolean logic
    expr(['-e', 'sched:sched_wakeup', '(comm != "swapper" || pid > 100) && (comm != "idle" || prio < 50)'], runtime, memleak_check)

def test_expr_string_equality_three_way(runtime, memleak_check):
    # Test == operator with three string comparisons
    expr(['-e', 'sched:sched_wakeup', 'comm+1 == "systemd" || comm == "sshd"+1 || comm == "cron"'], runtime, memleak_check)

def test_expr_string_inequality_three_way(runtime, memleak_check):
    # Test != operator with three string comparisons
    expr(['-e', 'sched:sched_wakeup', 'comm != "swapper" && comm != "idle" && comm != "migration"'], runtime, memleak_check)


# Tests for syscall_name() built-in function

def test_expr_syscall_name_basic(runtime, memleak_check):
    # Test basic syscall_name functionality with raw_syscalls events
    expr(['-e', 'raw_syscalls:sys_enter', 'printf("syscall %d: %s\\n", id, syscall_name(id))'], runtime, memleak_check)

def test_expr_syscall_name_invalid_number(runtime, memleak_check):
    # Test syscall_name with invalid syscall number
    expr(['-e', 'raw_syscalls:sys_enter', 'printf("invalid syscall %d: %s\\n", 9999, syscall_name(9999))'], runtime, memleak_check)

def test_expr_syscall_name_complex_expression(runtime, memleak_check):
    # Test syscall_name in complex expression with filtering
    expr(['-e', 'raw_syscalls:sys_enter', 'syscall_name(id) ~ "*write*" && comm_get(__pid) ~ "*perf*"'], runtime, memleak_check)


# Tests for system() built-in function

def test_expr_system_simple_command(runtime, memleak_check):
    # Test basic system() with a simple echo command
    expr(['-e', 'sched:sched_wakeup', 'system("echo test > /dev/null")'], runtime, memleak_check)

def test_expr_system_format_single_arg(runtime, memleak_check):
    # Test system() with one formatted argument
    expr(['-e', 'sched:sched_wakeup', 'system("echo pid=%d > /dev/null", pid)'], runtime, memleak_check)

def test_expr_system_format_multiple_args(runtime, memleak_check):
    # Test system() with multiple formatted arguments
    expr(['-e', 'sched:sched_wakeup', 'system("echo pid=%d comm=%s > /dev/null", pid, comm)'], runtime, memleak_check)

def test_expr_system_return_value(runtime, memleak_check):
    # Test system() return value - exit 0 should return 0
    expr(['-e', 'sched:sched_wakeup', 'system("exit 0")'], runtime, memleak_check)

def test_expr_system_conditional(runtime, memleak_check):
    # Test system() in conditional expression
    expr(['-e', 'sched:sched_wakeup', 'pid > 100 ? system("true") : 0'], runtime, memleak_check)

def test_expr_system_assignment(runtime, memleak_check):
    # Test system() result assignment
    expr(['-e', 'sched:sched_wakeup', 'success = system("true"), success'], runtime, memleak_check)

def test_expr_system_with_printf(runtime, memleak_check):
    # Test system() combined with printf
    expr(['-e', 'sched:sched_wakeup', 'printf("result=%d ", system("exit 0"))'], runtime, memleak_check)

def test_expr_system_complex_format(runtime, memleak_check):
    # Test system() with complex format string
    expr(['-e', 'sched:sched_wakeup', 'system("test %d -eq %d", pid, pid)'], runtime, memleak_check)

def test_expr_system_boolean_logic(runtime, memleak_check):
    # Test system() in boolean logic
    expr(['-e', 'sched:sched_wakeup', 'system("true") == 0 && pid > 0'], runtime, memleak_check)

def test_expr_system_with_match(runtime, memleak_check):
    # Test system() combined with wildcard match operator
    expr(['-e', 'sched:sched_wakeup', 'comm ~ "*sh" ? system("true") : 1'], runtime, memleak_check)

def test_expr_system_string_comparison(runtime, memleak_check):
    # Test system() combined with string comparison
    expr(['-e', 'sched:sched_wakeup', 'comm == "systemd" && system("true") == 0'], runtime, memleak_check)

def test_expr_system_nested_ternary(runtime, memleak_check):
    # Test system() in nested ternary expressions
    expr(['-e', 'sched:sched_wakeup', 'pid > 100 ? (system("true") == 0 ? 1 : 0) : 0'], runtime, memleak_check)

def test_expr_system_with_variables(runtime, memleak_check):
    # Test system() with __cpu and __pid variables
    expr(['-e', 'sched:sched_wakeup', 'system("test %d -ge 0 && test %d -ge 0", __cpu, __pid)'], runtime, memleak_check)

def test_expr_system_arithmetic(runtime, memleak_check):
    # Test system() result in arithmetic operations
    expr(['-e', 'sched:sched_wakeup', 'system("true") + pid'], runtime, memleak_check)

def test_expr_system_bitwise(runtime, memleak_check):
    # Test system() result in bitwise operations
    expr(['-e', 'sched:sched_wakeup', '(system("true") == 0) << 1'], runtime, memleak_check)

def test_expr_system_read_proc(runtime, memleak_check):
    # Test system() result in read operations
    expr(['-e', 'sched:sched_wakeup', 'system("cat /proc/%d/status", pid)'], runtime, memleak_check)