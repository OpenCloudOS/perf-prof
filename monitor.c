#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <argp.h>
#include <signal.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/time.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include <linux/thread_map.h>
#include <trace_helpers.h>
#include <monitor.h>
#include <tep.h>

struct monitor *monitors_list = NULL;
struct monitor *monitor = NULL;

void monitor_register(struct monitor *m)
{
    m->next = monitors_list;
    monitors_list = m;
}

struct monitor * monitor_find(char *name)
{
    struct monitor *m = monitors_list;
    while(m) {
        if (!strcmp(m->name, name))
            return m;
        m = m->next;
    }
    return NULL;
}

struct monitor *monitor_next(struct monitor *m)
{
    if (!m)
        return monitors_list;
    else
        return m->next;
}

int monitor_nr_instance(void)
{
    int nr_ins;

    nr_ins = perf_cpu_map__nr(monitor->cpus);
    if (perf_cpu_map__empty(monitor->cpus))
        nr_ins = perf_thread_map__nr(monitor->threads);

    return nr_ins;
}

int monitor_instance_cpu(int ins)
{
    return perf_cpu_map__cpu(monitor->cpus, ins);
}

int monitor_instance_thread(int ins)
{
    return perf_thread_map__pid(monitor->threads, ins);
}

int monitor_instance_oncpu(void)
{
    return !perf_cpu_map__empty(monitor->cpus);
}

struct monitor *current_monitor(void)
{
    return monitor;
}

/******************************************************
perf-prof argc argv
******************************************************/

struct env env = {
    .trigger_freq = 1000,
    .guest = 0,
    .latency = 20000,
    .freq = 100,
    .verbose = 0,
};

static volatile bool exiting;


const char *argp_program_version = PROGRAME " 0.6";
const char *argp_program_bug_address = "<corcpp@foxmail.com>";
const char argp_program_args_doc[] =
    "profiler [PROFILER OPTION...] [help]\n"
    "--symbols /path/to/bin";
const char argp_program_doc[] =
"\nProfiling based on perf_event\n\n"
"Most Used Profilers:\n"
"  perf-prof trace -e EVENT[...] [--overwrite] [-g [--flame-graph file [-i INT]]]\n"
"  perf-prof task-state [-S] [-D] [--than ns] [--filter comm] [-g [--flame-graph file]]\n"
"  perf-prof kvm-exit [--perins] [--than ns] [--heatmap file]\n"
"  perf-prof mpdelay -e EVENT[...] [--perins] [--than ns] [--heatmap file]\n"
"  perf-prof multi-trace -e EVENT [-e ...] [-k str] [--impl impl] [--than ns] [--detail] [--perins] [--heatmap file]\n"
"  perf-prof kmemleak --alloc EVENT[...] --free EVENT[...] [-g [--flame-graph file]] [-v]\n"
"  perf-prof kmemprof -e EVENT [-e ...] [-k str]\n"
"  perf-prof syscalls -e raw_syscalls:sys_enter -e raw_syscalls:sys_exit [-k common_pid] [--than ns] [--perins] [--heatmap file]\n"
"  perf-prof hrtimer [-e EVENT[...]] [-F freq] [--period ns] [-g] [--precise] [-v]\n"
"  perf-prof percpu-stat [--syscalls]\n"
"  perf-prof top -e EVENT[...] [-i INT] [-v]\n"
"  perf-prof stat -e EVENT[...] [--perins]\n"
"  perf-prof blktrace -d device [--than ns]\n"
"  perf-prof profile [-F freq] [-g [--flame-graph file [-i INT]]] [--exclude-*] [-G] [--than PCT]\n"
"  perf-prof cpu-util [--exclude-*] [-G]\n"
"  perf-prof ldlat-loads [--ldlat cycles] [-T trigger]\n"
"  perf-prof ldlat-stores [-T trigger]\n"
"Use Fewer Profilers:\n"
"  perf-prof split-lock [-T trigger] [-G] [--test]\n"
"  perf-prof irq-off [--than ns] [-g] [--precise]\n"
"  perf-prof signal [--filter comm] [-g]\n"
"  perf-prof watchdog [-F freq] [-g]\n"
"  perf-prof llcstat\n"
"  perf-prof sched-migrate [--detail] [--filter filter] [-g [--flame-graph file]] [-v]\n"
"  perf-prof oncpu -p PID [--detail] [--filter filter]\n"
"  perf-prof page-faults [-g]\n"
"\n"
"Event selector. use 'perf list tracepoint' to list available tp events.\n"
"  EVENT,EVENT,...\n"
"  EVENT: sys:name[/filter/ATTR/ATTR/.../]\n"
"  filter: ftrace filter\n"
"  ATTR:\n"
"      stack: sample_type PERF_SAMPLE_CALLCHAIN\n"
"      max-stack=int : sample_max_stack\n"
"      alias=str: event alias\n"
"      top-by=field: add to top, sort by this field\n"
"      top-add=field: add to top\n"
"      ptr=field: kmemleak, ptr field, Dflt: ptr=ptr\n"
"      size=field: kmemleak, size field, Dflt: size=bytes_alloc\n"
"      delay=field: mpdelay, delay field\n"
"      key=field: multi-trace, key for two-event\n"
;

enum {
    LONG_OPT_test = 500,
    LONG_OPT_precise,
    LONG_OPT_filter,
    LONG_OPT_exclude_user,
    LONG_OPT_exclude_kernel,
    LONG_OPT_exclude_guest,
    LONG_OPT_than,
    LONG_OPT_alloc,
    LONG_OPT_free,
    LONG_OPT_syscalls,
    LONG_OPT_perins,
    LONG_OPT_symbols,
    LONG_OPT_flame_graph,
    LONG_OPT_heatmap,
    LONG_OPT_order,
    LONG_OPT_order_mem,
    LONG_OPT_detail,
    LONG_OPT_impl,
    LONG_OPT_ldlat,
    LONG_OPT_overwrite,
    LONG_OPT_period,
};
static const struct argp_option opts[] = {
    { NULL, 0, NULL, 0, "OPTION:" },
    { "cpu", 'C', "CPU[-CPU],...", 0, "Monitor the specified CPU, Dflt: all cpu" },
    { "pids", 'p', "PID,...", 0, "Attach to processes" },
    { "tids", 't', "TID,...", 0, "Attach to thread" },
    { "interval", 'i', "ms", 0, "Interval, Unit: ms" },
    { "order", LONG_OPT_order, NULL, 0, "Order events by timestamp." },
    { "order-mem", LONG_OPT_order_mem, "Bytes", 0, "Maximum memory used by ordering events. Unit: GB/MB/KB/*B." },
    { "mmap-pages", 'm', "pages", 0, "Number of mmap data pages and AUX area tracing mmap pages" },
    { "verbose", 'v', NULL, 0, "Verbose debug output" },

    { NULL, 0, NULL, 0, "PROFILER OPTION:" },
    { "event", 'e', "EVENT,...", 0, "Event selector" },
    { "trigger", 'T', "T", 0, "Trigger Threshold, Dflt: 1000, No trigger: 0" },
    { "guest", 'G', NULL, 0, "Monitor GUEST, Dflt: false" },
    { "test", LONG_OPT_test, NULL, 0, "Split-lock test verification" },
    { "latency", 'L', "LAT", 0, "Interrupt off latency, Unit: us, Dflt: 20ms" },
    { "freq", 'F', "n", 0, "Profile at this frequency, Dflt: 100, No profile: 0" },
    { "period", LONG_OPT_period, "ns", 0, "Sample period, Unit: s/ms/us/*ns" },
    { "filter", LONG_OPT_filter, "filter", 0, "Event filter/comm filter", },
    { "key", 'k', "str", 0, "Key for series events" },
    { "impl", LONG_OPT_impl, "impl", 0, "Implementation of two-event analysis class. Dflt: delay.\n"
                                        "    delay: latency distribution between two events\n"
                                        "    pair: determine if two events are paired\n"
                                        "    kmemprof: profile memory allocated and freed bytes\n"
                                        "    syscalls: syscall delay"
                                        },
    { "interruptible", 'S', NULL, 0, "TASK_INTERRUPTIBLE" },
    { "uninterruptible", 'D', NULL, 0, "TASK_UNINTERRUPTIBLE" },
    { "exclude-user", LONG_OPT_exclude_user, NULL, 0, "exclude user" },
    { "exclude-kernel", LONG_OPT_exclude_kernel, NULL, 0, "exclude kernel" },
    { "exclude-guest", LONG_OPT_exclude_guest, NULL, 0, "exclude guest" },
    { "than", LONG_OPT_than, "ns", 0, "Greater than specified time, Unit: s/ms/us/*ns/percent" },
    { "alloc", LONG_OPT_alloc, "EVENT,...", 0, "Memory alloc tracepoint/kprobe" },
    { "free", LONG_OPT_free, "EVENT,...", 0, "Memory free tracepoint/kprobe" },
    { "syscalls", LONG_OPT_syscalls, NULL, 0, "Trace syscalls" },
    { "perins", LONG_OPT_perins, NULL, 0, "Print per instance stat" },
    { "call-graph", 'g', NULL, 0, "Enable call-graph recording" },
    { "precise", LONG_OPT_precise, NULL, 0, "Generate precise interrupt" },
    { "symbols", LONG_OPT_symbols, "symbols", 0, "Maps addresses to symbol names.\n"
                                                 "Similar to pprof --symbols." },
    { "flame-graph", LONG_OPT_flame_graph, "file", 0, "Specify the folded stack file." },
    { "heatmap", LONG_OPT_heatmap, "file", 0, "Specify the output latency file." },
    { "detail", LONG_OPT_detail, NULL, 0, "More detailed information output" },
    { "device", 'd', "device", 0, "Block device, /dev/sdx" },
    { "ldlat", LONG_OPT_ldlat, "cycles", 0, "mem-loads latency, Unit: cycles" },
    { "overwrite", LONG_OPT_overwrite, NULL, 0, "use overwrite mode" },

    { "version", 'V', NULL, 0, "Version info" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "" },
    {},
};

/**
 *  Parses a string into a number.  The number stored at @ptr is
 *  potentially suffixed with K, M, G, T, P, E.
 */
static unsigned long memparse(const char *ptr, char **retptr)
{
    char *endptr;   /* local pointer to end of parsed string */

    unsigned long ret = strtoul(ptr, &endptr, 10);

    switch (*endptr) {
    case 'E':
    case 'e':
        ret <<= 10;
        /* fall through */
    case 'P':
    case 'p':
        ret <<= 10;
        /* fall through */
    case 'T':
    case 't':
        ret <<= 10;
        /* fall through */
    case 'G':
    case 'g':
        ret <<= 10;
        /* fall through */
    case 'M':
    case 'm':
        ret <<= 10;
        /* fall through */
    case 'K':
    case 'k':
        ret <<= 10;
        /* fall through */
    case 'B':
    case 'b':
        endptr++;
    default:
        break;
    }

    if (retptr)
        *retptr = endptr;

    return ret;
}

/**
 *  Parses a string into ns.  The number stored at @ptr is
 *  potentially suffixed with s, ms, us, ns.
 */
static unsigned long nsparse(const char *ptr, char **retptr)
{
    char *endptr;   /* local pointer to end of parsed string */

    unsigned long ret = strtoul(ptr, &endptr, 10);
    unsigned long tmp = ret;

    switch (*endptr) {
    case 'S':
    case 's':
        tmp *= 1000;
        endptr--;
        /* fall through */
    case 'M':
    case 'm':
        tmp *= 1000;
        /* fall through */
    case 'U':
    case 'u':
        tmp *= 1000;
        /* fall through */
    case 'N':
    case 'n':
        endptr++;
        if (*endptr == 's') {
            endptr++;
            ret = tmp;
        }
    default:
        break;
    }

    if (retptr)
        *retptr = endptr;

    return ret;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    int latency;

    switch (key) {
    case 'h':
        argp_help((const struct argp *__restrict)state->root_argp, stderr, ARGP_HELP_STD_HELP, (char *__restrict)"perf-prof");
        exit(0);
    case 'T':
        env.trigger_freq = strtol(arg, NULL, 10);
        break;
    case 'C':
        env.cpumask = strdup(arg);
        break;
    case 'G':
        env.guest = 1;
        break;
    case 'i':
        env.interval = strtol(arg, NULL, 10);
        break;
    case 'p':
        env.pids = strdup(arg);
        break;
    case 't':
        env.tids = strdup(arg);
        break;
    case LONG_OPT_test:
        env.test = 1;
        break;
    case 'L':
        latency = strtol(arg, NULL, 10);
        if (latency > 1)
            env.latency = latency;
        break;
    case 'F':
        env.freq = strtol(arg, NULL, 10);
        break;
    case 'e':
        env.events = realloc(env.events, (env.nr_events + 1) * sizeof(*env.events));
        env.events[env.nr_events] = strdup(arg);
        if (env.nr_events == 0)
            env.event = env.events[0];
        env.nr_events ++;
        break;
    case LONG_OPT_filter:
        env.filter = strdup(arg);
        break;
    case 'k':
        env.key = strdup(arg);
        break;
    case LONG_OPT_impl:
        env.impl = strdup(arg);
        break;
    case 'S':
        env.interruptible = 1;
        break;
    case 'D':
        env.uninterruptible = 1;
        break;
    case LONG_OPT_exclude_user:
        env.exclude_user = 1;
        break;
    case LONG_OPT_exclude_kernel:
        env.exclude_kernel = 1;
        break;
    case LONG_OPT_exclude_guest:
        env.exclude_guest = 1;
        break;
    case LONG_OPT_than:
        env.greater_than = nsparse(arg, NULL);
        break;
    case LONG_OPT_alloc:
        env.tp_alloc = strdup(arg);
        break;
    case LONG_OPT_free:
        env.tp_free = strdup(arg);
        break;
    case LONG_OPT_syscalls:
        env.syscalls = 1;
        break;
    case LONG_OPT_perins:
        env.perins = 1;
        break;
    case 'g':
        env.callchain = 1;
        break;
    case 'm':
        env.mmap_pages = strtol(arg, NULL, 10);
        break;
    case LONG_OPT_precise:
        env.precise = 1;
        break;
    case LONG_OPT_symbols:
        env.symbols = strdup(arg);
        break;
    case LONG_OPT_flame_graph:
        env.flame_graph = strdup(arg);
        break;
    case LONG_OPT_heatmap:
        env.heatmap = strdup(arg);
        break;
    case LONG_OPT_order:
        env.order = true;
        break;
    case LONG_OPT_order_mem:
        env.order_mem = memparse(arg, NULL);
        break;
    case LONG_OPT_detail:
        env.detail = true;
        break;
    case 'd':
        env.device = strdup(arg);
        break;
    case LONG_OPT_ldlat:
        env.ldlat = strtol(arg, NULL, 10);
        break;
    case LONG_OPT_overwrite:
        env.overwrite = true;
        break;
    case LONG_OPT_period:
        env.sample_period = nsparse(arg, NULL);
        break;
    case 'v':
        env.verbose++;
        break;
    case 'V':
        printf("%s\n", argp_program_version);
        exit(0);
        break;
    case ARGP_KEY_ARG:
        switch (state->arg_num) {
            case 0:
                monitor = monitor_find(arg);
                if (monitor == NULL && env.symbols == NULL)
                    argp_usage (state);
                break;
            case 1:
                env.help_monitor = monitor;
                monitor = monitor_find(arg);
                if (monitor)
                    break;
            default:
                argp_usage (state);
                break;
        };
        break;
    case ARGP_KEY_END:
        if (env.symbols == NULL && state->arg_num < 1)
            argp_usage (state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static void sig_handler(int sig)
{
    exiting = 1;
}

int get_present_cpus(void)
{
    struct perf_cpu_map *cpumap = NULL;
    FILE *f;
    int cpus;

    f = fopen("/sys/devices/system/cpu/present", "r");
    if (!f)
        f = fopen("/sys/devices/system/cpu/online", "r");
    cpumap = perf_cpu_map__read(f);
    fclose(f);

    cpus = perf_cpu_map__max(cpumap);
    perf_cpu_map__put(cpumap);
    return cpus + 1;
}

int get_tsc_khz(void)
{
    int kvm, vm, vcpu;
    int tsc_khz = 0;

    kvm = open("/dev/kvm", O_RDWR);
    if (kvm < 0) {
        fprintf(stderr, "open kvm failed\n");
        return 0;
    }
    vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (kvm < 0) {
        fprintf(stderr, "create vm failed\n");
        close(kvm);
        return 0;
    }
    vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    if (vcpu < 0) {
        fprintf(stderr, "create vm failed\n");
        close(vm);
        close(kvm);
        return 0;
    }
    if (ioctl(vm, KVM_CHECK_EXTENSION, KVM_CAP_GET_TSC_KHZ) == 1) {
        tsc_khz = ioctl(vcpu, KVM_GET_TSC_KHZ, 0);
        if (tsc_khz < 0)
            tsc_khz = 0;
    }
    close(vcpu);
    close(vm);
    close(kvm);
    return tsc_khz;
}

int get_cpuinfo(struct cpuinfo_x86 *info)
{
#if defined(__i386__) || defined(__x86_64__)
    __u32 eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;
    __get_cpuid(0, &eax, &ebx, &ecx, &edx);

    if (info)
        memset(info, 0, sizeof(*info));
    if (ebx == 0x756e6547 && ecx == 0x6c65746e && edx == 0x49656e69) {
        if (info && eax > 1) {
            int family, model, stepping;
            __get_cpuid(1, &eax, &ebx, &ecx, &edx);
            family = (eax >> 8) & 0xf;
            model = (eax >> 4) & 0xf;
            stepping = eax & 0xf;
            if (family == 0x6 || family == 0xf)
                model += ((eax > 16) & 0xf) << 4;
            if (family == 0xf)
                family += (eax >> 20) & 0xff;
            info->vendor = X86_VENDOR_INTEL;
            info->family = family;
            info->model = model;
            info->stepping = stepping;
        }
        return X86_VENDOR_INTEL;
    } else if (ebx == 0x68747541 && ecx == 0x444d4163 && edx == 0x69746e65) {
        if (info && eax > 1) {
            int family, model, stepping;
            __get_cpuid(1, &eax, &ebx, &ecx, &edx);
            family = (eax >> 8) & 0xf;
            model = (eax >> 4) & 0xf;
            stepping = eax & 0xf;
            if (family == 0xf) {
                model += ((eax > 16) & 0xf) << 4;
                family += (eax >> 20) & 0xff;
            }
            info->vendor = X86_VENDOR_AMD;
            info->family = family;
            info->model = model;
            info->stepping = stepping;
        }
        return X86_VENDOR_AMD;
    } else if (ebx == 0x6f677948 && ecx == 0x656e6975 && edx == 0x6e65476e) {
        return X86_VENDOR_HYGON;
    } else
        return -1;
#else
    if (info)
        memset(info, 0, sizeof(*info));
    return -1;
#endif
}

#define CPUID_EXT_HYPERVISOR  (1U << 31)
int in_guest(void)
{
#if defined(__i386__) || defined(__x86_64__)

    __u32 eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);

    return !!(ecx & CPUID_EXT_HYPERVISOR);
#else
    return 0;
#endif
}

void print_time(FILE *fp)
{
    char timebuff[64];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    strftime(timebuff, sizeof(timebuff), "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
    fprintf(fp, "%s.%06u ", timebuff, (unsigned int)tv.tv_usec);
}

static uint64_t time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}

void print_lost_fn(union perf_event *event, int ins)
{
    int oncpu = monitor_instance_oncpu();
    print_time(stderr);
    fprintf(stderr, "lost %llu events on %s #%d\n", event->lost.lost,
                    oncpu ? "CPU" : "thread",
                    oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
}

static void print_fork_exit_fn(union perf_event *event, int ins, int exit)
{
    if (env.verbose >= 2) {
        int oncpu = monitor_instance_oncpu();
        print_time(stderr);
        fprintf(stderr, "%s ppid %u ptid %u pid %u tid %u on %s #%d\n",
                        exit ? "exit" : "fork",
                        event->fork.ppid, event->fork.ptid,
                        event->fork.pid,  event->fork.tid,
                        oncpu ? "CPU" : "thread",
                        oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
    }
}

static void print_comm_fn(union perf_event *event, int ins)
{
    if (env.verbose >= 2) {
        int oncpu = monitor_instance_oncpu();
        print_time(stderr);
        fprintf(stderr, "comm pid %u tid %u %s on %s #%d\n",
                        event->comm.pid,  event->comm.tid,
                        event->comm.comm,
                        oncpu ? "CPU" : "thread",
                        oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
    }
}

static void print_context_switch_fn(union perf_event *event, int ins)
{
    if (env.verbose >= 2) {
        int oncpu = monitor_instance_oncpu();
        print_time(stderr);
        fprintf(stderr, "switch on %s #%d\n", oncpu ? "CPU" : "thread",
                        oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
    }
}

static void print_context_switch_cpu_fn(union perf_event *event, int ins)
{
    if (env.verbose >= 2) {
        int oncpu = monitor_instance_oncpu();
        print_time(stderr);
        fprintf(stderr, "switch next pid %u tid %u on %s #%d\n",
                        event->context_switch.next_prev_pid, event->context_switch.next_prev_tid,
                        oncpu ? "CPU" : "thread",
                        oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
    }
}

static int perf_event_process_record(union perf_event *event, int instance)
{
    switch (event->header.type) {
    case PERF_RECORD_LOST:
        if (monitor->lost)
            monitor->lost(event, instance);
        else
            print_lost_fn(event, instance);
        break;
    case PERF_RECORD_FORK:
        if (monitor->fork)
            monitor->fork(event, instance);
        else
            print_fork_exit_fn(event, instance, 0);
        break;
    case PERF_RECORD_COMM:
        if (monitor->comm)
            monitor->comm(event, instance);
        else
            print_comm_fn(event, instance);
        break;
    case PERF_RECORD_EXIT:
        if (monitor->exit)
            monitor->exit(event, instance);
        else
            print_fork_exit_fn(event, instance, 1);
        break;
    case PERF_RECORD_THROTTLE:
        if (monitor->throttle)
            monitor->throttle(event, instance);
        break;
    case PERF_RECORD_UNTHROTTLE:
        if (monitor->unthrottle)
            monitor->unthrottle(event, instance);
        break;
    case PERF_RECORD_SAMPLE:
        if (monitor->sample)
            monitor->sample(event, instance);
        break;
    case PERF_RECORD_SWITCH:
        if (monitor->context_switch)
            monitor->context_switch(event, instance);
        else
            print_context_switch_fn(event, instance);
        break;
    case PERF_RECORD_SWITCH_CPU_WIDE:
        if (monitor->context_switch_cpu)
            monitor->context_switch_cpu(event, instance);
        else
            print_context_switch_cpu_fn(event, instance);
        break;
    default:
        fprintf(stderr, "unknown perf sample type %d\n", event->header.type);
        return -1;
    }
    return 0;
}

static int libperf_print(enum libperf_print_level level,
                         const char *fmt, va_list ap)
{
    if (level > LIBPERF_WARN)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

int main(int argc, char *argv[])
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .args_doc = argp_program_args_doc,
        .doc = argp_program_doc,
    };
    int err;
    struct perf_evlist *evlist = NULL;
    struct perf_cpu_map *cpus = NULL, *online;
    struct perf_thread_map *threads = NULL;
    uint64_t time_end;
    int time_left;
    bool deinited;

    if (isatty(STDOUT_FILENO)) {
        struct winsize size;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0) {
            char buff[16];
            snprintf(buff, sizeof(buff), "rmargin=%u", size.ws_col);
            setenv("ARGP_HELP_FMT", buff, 1);
        }
    }

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.symbols) {
        syms__convert(stdin, stdout);
        return 0;
    }

    if (env.order || monitor->order)
        monitor = order(monitor);
    if (env.mmap_pages)
        monitor->pages = env.mmap_pages;

    setlinebuf(stdout);
    libperf_init(libperf_print);

reinit:
    deinited = false;
    monitor->reinit = 0;

    evlist = perf_evlist__new();
    if (!evlist) {
        fprintf(stderr, "failed to create evlist\n");
        return -1;
    }

    if (env.pids || env.tids) {
        // attach to processes
        threads = thread_map__new_str(env.pids, env.tids, 0, 0);
        cpus = perf_cpu_map__dummy_new();
        if (!threads || !cpus) {
            fprintf(stderr, "failed to create pids\n");
            goto out_delete;
        }
    } else {
        // attach to cpus
        cpus = perf_cpu_map__new(env.cpumask);
        threads = perf_thread_map__new_dummy();
        if (!cpus || !threads) {
            fprintf(stderr, "failed to create cpus\n");
            goto out_delete;
        }
        online = perf_cpu_map__new(NULL);
        if (!online) {
            fprintf(stderr, "failed to create online\n");
            goto out_delete;
        }
        cpus = perf_cpu_map__and(cpus, online);
        if (!cpus) {
            fprintf(stderr, "failed to create cpus\n");
            goto out_delete;
        }
        perf_cpu_map__put(online);
    }
    monitor->cpus = cpus;
    monitor->threads = threads;

    if(monitor->init(evlist, &env) < 0) {
        fprintf(stderr, "monitor(%s) init failed\n", monitor->name);
        goto out_delete;
    }
    /* monitor->init allows reassignment of cpus and threads */
    cpus = monitor->cpus;
    threads = monitor->threads;
    perf_evlist__set_maps(evlist, cpus, threads);

    err = perf_evlist__open(evlist);
    if (err) {
        fprintf(stderr, "failed to open evlist, %d\n", err);
        goto out_exit;
    }

    if (monitor->filter && monitor->filter(evlist, &env) < 0) {
        fprintf(stderr, "monitor(%s) filter failed\n", monitor->name);
        goto out_close;
    }

    if (monitor->pages)
        err = perf_evlist__mmap(evlist, monitor->pages);
    if (err) {
        fprintf(stderr, "failed to mmap evlist\n");
        goto out_close;
    }

    perf_evlist__enable(evlist);

    signal(SIGINT, sig_handler);
    if (monitor->sigusr1)
        signal(SIGUSR1, monitor->sigusr1);

    time_end = env.interval ? time_ms() + env.interval : -1;
    time_left = env.interval ? : -1;
    while (!exiting && !monitor->reinit) {
        struct perf_mmap *map;
        union perf_event *event;
        int fds = 0;

        if (env.overwrite == false)
            fds = perf_evlist__poll(evlist, time_left);
        else if (time_left) {
            usleep(time_left * 1000);
        }

        if (monitor->pages && (fds || time_left == 0 || exiting))
        perf_evlist__for_each_mmap(evlist, map, env.overwrite) {
            if (perf_mmap__read_init(map) < 0)
                continue;
            while ((event = perf_mmap__read_event(map)) != NULL) {
                /* process event */
                perf_event_process_record(event, perf_mmap__idx(map));
                perf_mmap__consume(map);
            }
            perf_mmap__read_done(map);
        }

        if (monitor->read && time_left == 0) {
            struct perf_evsel *evsel;
            int cpu, ins, tins;
            perf_cpu_map__for_each_cpu(cpu, ins, cpus) {
                for (tins = 0; tins < perf_thread_map__nr(threads); tins++) {
                    perf_evlist__for_each_evsel(evlist, evsel) {
                        struct perf_counts_values count;
                        if (perf_evsel__read(evsel, ins, tins, &count) == 0)
                            monitor->read(evsel, &count, cpu != -1 ? ins : tins);
                    }
                }
            }
        }

        if (monitor->interval && time_left == 0)
            monitor->interval();

        if (env.interval) {
            time_left = time_end - time_ms();
            if (time_left <= 0) {
                time_end = time_ms() + env.interval + time_left;
                time_left = 0;
            }
        }
    }

    perf_evlist__disable(evlist);
    if (!deinited) {
        deinited = true;
        /*
         * deinit before perf_evlist__munmap.
         * When order is enabled, some events are also cached inside the order,
         * and then deinit will refresh all events.
         * Order::base profiler handles events and may call perf_evlist__id_to_evsel,
         * which requires id_hash. But perf_evlist__munmap will reset id_hash.
         * Therefore, deinit must be executed first.
        **/
        monitor->deinit(evlist);
    }
    perf_evlist__munmap(evlist);
out_close:
    perf_evlist__close(evlist);
out_exit:
    if (!deinited) {
        deinited = true;
        monitor->deinit(evlist);
    }
out_delete:
    perf_evlist__set_maps(evlist, NULL, NULL);
    perf_evlist__delete(evlist);
    perf_cpu_map__put(cpus);
    perf_thread_map__put(threads);

    if (monitor->reinit)
        goto reinit;

    return err;
}

