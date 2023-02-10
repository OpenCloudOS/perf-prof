#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/time.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include <linux/thread_map.h>
#include <linux/cgroup.h>
#include <trace_helpers.h>
#include <monitor.h>
#include <tep.h>

static int daylight_active;


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
    .freq = 100,
    .irqs_disabled = -1,
    .tif_need_resched = -1,
    .exclude_pid = -1,
    .nr_running_min = -1,
    .nr_running_max = -1,
};

static volatile bool exiting;
static volatile bool child_finished;

const char *main_program_version = PROGRAME " 0.13";

enum {
    LONG_OPT_start = 500,
    LONG_OPT_than,
    LONG_OPT_only_than,
    LONG_OPT_order_mem,
    LONG_OPT_detail,
    LONG_OPT_period,
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

static void detail_parse(const char *s)
{
    if (strcmp(s, "samecpu") == 0)
        env.samecpu = true;
    else if (strcmp(s, "samepid") == 0)
        env.samepid = true;
    else if (s[0] == '-')
        env.before_event1 = nsparse(s+1, NULL);
    else
        env.after_event2 = nsparse(s, NULL);
}

static int parse_arg(int key, char *arg)
{
    switch (key) {
    case 'e':
        env.events = realloc(env.events, (env.nr_events + 1) * sizeof(*env.events));
        env.events[env.nr_events] = strdup(arg);
        if (env.nr_events == 0)
            env.event = env.events[0];
        env.nr_events ++;
        break;
    case LONG_OPT_only_than:
        env.only_print_greater_than = true;
        // fall through
    case LONG_OPT_than:
        env.greater_than = nsparse(arg, NULL);
        break;
    case LONG_OPT_order_mem:
        env.order_mem = memparse(arg, NULL);
        break;
    case LONG_OPT_detail:
        env.detail = true;
        if (arg) {
            char *ss = strdup(arg);
            char *sep, *s = ss;
            while ((sep = strchr(s, ',')) != NULL) {
                *sep = '\0';
                detail_parse(s);
                s = sep + 1;
            }
            if (*s)
                detail_parse(s);
            free(ss);
        }
        break;
    case LONG_OPT_period:
        env.sample_period = nsparse(arg, NULL);
        break;
    case 'V':
        printf("%s\n", main_program_version);
        exit(0);
    default:
        break;
    }
    return 0;
}

static int parse_help_cb(const struct option *opt, const char *arg, int unset)
{
    help();
    return 0;
}

static int parse_arg_cb(const struct option *opt, const char *arg, int unset)
{
    return parse_arg(opt->short_name, (char *)arg);
}

#define OPT_BOOL_NONEG(s, l, v, h)       { .type = OPTION_BOOLEAN, .short_name = (s), .long_name = (l), .value = check_vtype(v, bool *), .help = (h), .flags = PARSE_OPT_NONEG }
#define OPT_INT_NONEG(s, l, v, a, h)     { .type = OPTION_INTEGER, .short_name = (s), .long_name = (l), .value = check_vtype(v, int *), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG }
#define OPT_UINT_NONEG(s, l, v, a, h)    { .type = OPTION_UINTEGER, .short_name = (s), .long_name = (l), .value = check_vtype(v, unsigned int *), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG }
#define OPT_LONG_NONEG(s, l, v, a, h)    { .type = OPTION_LONG, .short_name = (s), .long_name = (l), .value = check_vtype(v, long *), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG }
#define OPT_ULONG_NONEG(s, l, v, a, h)   { .type = OPTION_ULONG, .short_name = (s), .long_name = (l), .value = check_vtype(v, unsigned long *), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG }
#define OPT_U64_NONEG(s, l, v, a, h)     { .type = OPTION_U64, .short_name = (s), .long_name = (l), .value = check_vtype(v, u64 *), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG }
#define OPT_STRDUP_NONEG(s, l, v, a, h)  { .type = OPTION_STRING,  .short_name = (s), .long_name = (l), .value = check_vtype(v, char **), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG | PARSE_OPT_NOEMPTY }
#define OPT_PARSE_NONEG(s, l, v, a, h) \
    { .type = OPTION_CALLBACK, .short_name = (BUILD_BUG_ON_ZERO(s==0) + s), .long_name = (l), .value = (v), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG, .callback = (parse_arg_cb) }
#define OPT_PARSE_NOARG(s, l, v, a, h) \
    { .type = OPTION_CALLBACK, .short_name = (BUILD_BUG_ON_ZERO(s==0) + s), .long_name = (l), .value = (v), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG | PARSE_OPT_NOARG, .callback = (parse_arg_cb) }
#define OPT_PARSE_OPTARG(s, l, v, a, h) \
    { .type = OPTION_CALLBACK, .short_name = (BUILD_BUG_ON_ZERO(s==0) + s), .long_name = (l), .value = (v), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG | PARSE_OPT_OPTARG, .callback = (parse_arg_cb) }
#define OPT_INT_OPTARG(s, l, v, d, a, h) \
    { .type = OPTION_INTEGER, .short_name = (s), .long_name = (l), .value = check_vtype(v, int *), .argh = (a), .defval = (intptr_t)(d), .help = (h), .flags = PARSE_OPT_NONEG | PARSE_OPT_OPTARG }
#define OPT_HELP() \
    { .type = OPTION_CALLBACK, .short_name = ('h'), .long_name = ("help"), .help = ("Give this help list"), .flags = PARSE_OPT_NONEG | PARSE_OPT_NOARG, .callback = (parse_help_cb) }

struct option main_options[] = {
    OPT_GROUP("OPTION:"),
    OPT_STRDUP_NONEG('C',        "cpus", &env.cpumask,    "CPU[-CPU],...", "Monitor the specified CPU, Dflt: all cpu"),
    OPT_STRDUP_NONEG('p',        "pids", &env.pids,       "PID,...",       "Attach to processes"),
    OPT_STRDUP_NONEG('t',        "tids", &env.tids,       "TID,...",       "Attach to threads"),
    OPT_STRDUP_NONEG( 0 ,     "cgroups", &env.cgroups,    "cgroup,...",    "Attach to cgroups, support regular expression."),
    OPT_INT_NONEG   ('i',    "interval", &env.interval,   "ms",            "Interval, Unit: ms"),
    OPT_STRDUP_NONEG('o',      "output", &env.output,     "file",          "Output file name"),
    OPT_BOOL_NONEG  ( 0 ,       "order", &env.order,                       "Order events by timestamp."),
    OPT_PARSE_NONEG (LONG_OPT_order_mem, "order-mem", &env.order_mem, "Bytes", "Maximum memory used by ordering events. Unit: GB/MB/KB/*B."),
    OPT_INT_NONEG   ('m',  "mmap-pages", &env.mmap_pages, "pages",         "Number of mmap data pages and AUX area tracing mmap pages"),
    OPT_LONG_NONEG  ('N',      "exit-N", &env.exit_n, "N",                 "Exit after N events have been sampled."),
    OPT_PARSE_NOARG ('V',     "version", NULL,             NULL,           "Version info"),
    OPT__VERBOSITY(&env.verbose),
    OPT_HELP(),

    OPT_GROUP("FILTER OPTION:"),
    OPT_BOOL_NONEG  ('G',     "exclude-host", &env.exclude_host,                "Monitor GUEST, exclude host"),
    OPT_BOOL_NONEG  ( 0 ,    "exclude-guest", &env.exclude_guest,               "exclude guest"),
    OPT_BOOL_NONEG  ( 0 ,     "exclude-user", &env.exclude_user,                "exclude user"),
    OPT_BOOL_NONEG  ( 0 ,   "exclude-kernel", &env.exclude_kernel,              "exclude kernel"),
    OPT_INT_OPTARG  ( 0 ,    "irqs_disabled", &env.irqs_disabled,    1, "0|1",  "ebpf, irqs disabled or not."),
    OPT_INT_OPTARG  ( 0 , "tif_need_resched", &env.tif_need_resched, 1, "0|1",  "ebpf, TIF_NEED_RESCHED is set or not."),
    OPT_INT_NONEG   ( 0 ,      "exclude_pid", &env.exclude_pid,         "PID",  "ebpf, exclude pid"),
    OPT_INT_NONEG   ( 0 ,   "nr_running_min", &env.nr_running_min,       NULL,  "ebpf, minimum number of running processes for CPU runqueue."),
    OPT_INT_NONEG   ( 0 ,   "nr_running_max", &env.nr_running_max,       NULL,  "ebpf, maximum number of running processes for CPU runqueue."),

    OPT_GROUP("PROFILER OPTION:"),
    OPT_PARSE_NONEG ('e', "event", NULL,    "EVENT,...",        "Event selector. use 'perf list tracepoint' to list available tp events.\n"
                                                                "  EVENT,EVENT,...\n"
                                                                "  EVENT: sys:name[/filter/ATTR/ATTR/.../]\n"
                                                                "  filter: ftrace filter\n"
                                                                "  ATTR:\n"
                                                                "      stack: sample_type PERF_SAMPLE_CALLCHAIN\n"
                                                                "      max-stack=int : sample_max_stack\n"
                                                                "      alias=str: event alias\n"
                                                                "      top-by=EXPR: add to top, sort by this field\n"
                                                                "      top-add=EXPR: add to top\n"
                                                                "      comm=EXPR: top, show COMM\n"
                                                                "      ptr=EXPR: kmemleak, ptr field, Dflt: ptr=ptr\n"
                                                                "      size=EXPR: kmemleak, size field, Dflt: size=bytes_alloc\n"
                                                                "      num=EXPR: num-dist, num field\n"
                                                                "      key=EXPR: key for multiple events: top, multi-trace\n"
                                                                "      untraced: multi-trace, auxiliary, no two-event analysis\n"
                                                                "      trigger: multi-trace, use events to trigger interval output\n"
                                                                "  EXPR:\n"
                                                                "      C expression. See `"PROGRAME" expr -h` for more information."
                                                                ),
    OPT_INT_NONEG   ('F',            "freq", &env.freq,                  NULL,  "Profile at this frequency, Dflt: 100, No profile: 0"),
    OPT_STRDUP_NONEG('k',             "key", &env.key,                  "str",  "Key for series events"),
    OPT_STRDUP_NONEG( 0 ,          "filter", &env.filter,            "filter",  "Event filter/comm filter"),
    OPT_PARSE_NONEG (LONG_OPT_period, "period", &env.sample_period,      "ns",   "Sample period, Unit: s/ms/us/*ns"),
    OPT_STRDUP_NONEG(0, "impl", &env.impl,    "impl",       "Implementation of two-event analysis class. Dflt: delay.\n"
                                                                "    delay: latency distribution between two events\n"
                                                                "    pair: determine if two events are paired\n"
                                                                "    kmemprof: profile memory allocated and freed bytes\n"
                                                                "    syscalls: syscall delay\n"
                                                                "    call: analyze function calls, only for nested-trace.\n"
                                                                "    call-delay: call + delay, only for nested-trace."),
    OPT_BOOL_NONEG  ('S',   "interruptible", &env.interruptible,                "TASK_INTERRUPTIBLE"),
    OPT_BOOL_NONEG  ('D', "uninterruptible", &env.uninterruptible,              "TASK_UNINTERRUPTIBLE"),
    OPT_PARSE_NONEG ( LONG_OPT_than, "than", &env.greater_than,          "ns",  "Greater than specified time, Unit: s/ms/us/*ns/percent"),
    OPT_PARSE_NONEG ( LONG_OPT_only_than, "only-than", &env.greater_than,"ns",  "Only print those that are greater than the specified time."),
    OPT_STRDUP_NONEG( 0 ,           "alloc", &env.tp_alloc,           "EVENT",  "Memory alloc tracepoint/kprobe/uprobe"),
    OPT_STRDUP_NONEG( 0 ,            "free", &env.tp_free,            "EVENT",  "Memory free tracepoint/kprobe/uprobe"),
    OPT_BOOL_NONEG  ( 0 ,        "syscalls", &env.syscalls,                     "Trace syscalls"),
    OPT_BOOL_NONEG  ( 0 ,          "perins", &env.perins,                       "Print per instance stat"),
    OPT_BOOL_NONEG  ('g',      "call-graph", &env.callchain,                    "Enable call-graph recording"),
    OPT_STRDUP_NONEG( 0 ,     "flame-graph", &env.flame_graph,         "file",  "Specify the folded stack file."),
    OPT_STRDUP_NONEG( 0 ,         "heatmap", &env.heatmap,             "file",  "Specify the output latency file."),
    OPT_PARSE_OPTARG( LONG_OPT_detail, "detail", NULL, "-N,+N,samecpu,samepid",
                                                       "More detailed information output.\n"
                                                       "For multi-trace profiler:\n"
                                                       "   -N: Before event1, print events within N nanoseconds.\n"
                                                       "   +N: After event2, print events within N nanoseconds.\n"
                                                       "samecpu: Only show events with the same cpu as event1 or event2.\n"
                                                       "samepid: Only show events with the same pid as event1 or event2."),
    OPT_INT_NONEG   ('T',         "trigger", &env.trigger_freq,          NULL,  "Trigger Threshold, Dflt: 1000, No trigger: 0"),
    OPT_BOOL_NONEG  ( 0 ,            "test", &env.test,                         "Split-lock test verification"),
    OPT_STRDUP_NONEG( 0 ,         "symbols", &env.symbols,               NULL,  "Maps addresses to symbol names.\n"
                                                                                "Similar to pprof --symbols."),
    OPT_STRDUP_NONEG('d',          "device", &env.device,            "device",  "Block device, /dev/sdx"),
    OPT_INT_NONEG   ( 0 ,           "ldlat", &env.ldlat,             "cycles",  "mem-loads latency, Unit: cycles"),
    OPT_BOOL_NONEG  ( 0 ,       "overwrite", &env.overwrite,                    "use overwrite mode"),
    OPT_BOOL_NONEG  ( 0 ,            "spte", &env.spte,                         "kvmmmu: enable kvmmmu:kvm_mmu_set_spte"),
    OPT_BOOL_NONEG  ( 0 ,            "mmio", &env.mmio,                         "kvmmmu: enable kvmmmu:mark_mmio_spte"),
    OPT_BOOL_NONEG  ( 0 ,       "only-comm", &env.only_comm,                    "top: only show comm but not key"),

    OPT_END()
};

const char * const main_usage[] = {
    PROGRAME " profiler [PROFILER OPTION...] [help] [cmd [args...]]",
    PROGRAME " --symbols /path/to/bin",
    "",
    "Profiling based on perf_event and ebpf",
    NULL
};

void help(void)
{
    int argc = 2;
    const char *argv[] = {PROGRAME, "--help"};
    const char * const *usagestr = main_usage;
    struct monitor *m = monitor;

    if (m) {
        if (monitor->argv && monitor->desc) {
            argc = 0;
            while (monitor->argv[argc++] != NULL);
            parse_options(argc - 1, monitor->argv, main_options, monitor->desc, PARSE_OPT_INTERNAL_HELP_NO_ORDER);
        } else
            parse_options(argc, argv, main_options, main_usage, PARSE_OPT_INTERNAL_HELP_NO_ORDER);
    }

    fprintf(stderr, "\n Usage: %s\n", *usagestr++);
    while (*usagestr && **usagestr)
        fprintf(stderr, "    or: %s\n", *usagestr++);
    while (*usagestr) {
        fprintf(stderr, "%s%s\n",
                **usagestr ? "    " : "",
                *usagestr);
        usagestr++;
    }

    fprintf(stderr, "\n Available Profilers:\n");
    while((m = monitor_next(m))) {
        fprintf(stderr, "   %-20s", m->name);
        if (m->desc && m->desc[2] && m->desc[2][0])
            fprintf(stderr, " %s\n", m->desc[2]);
        else
            fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n See '%s profiler -h' for more information on a specific profiler.\n\n", PROGRAME);
    exit(129);
}

static void disable_help(void)
{
    struct option *opts = main_options;
    for (; opts->type != OPTION_END; opts++) {
        if (opts->short_name == 'h') {
            opts->short_name = 0;
            opts->long_name = "disable-help";
        }
    }
}

#ifndef CONFIG_LIBBPF
static const char *LIBBPF_BUILD = "NO CONFIG_LIBBPF=y";
#endif

static int parse_main_options(int argc, char *argv[])
{
    bool stop_at_non_option = true;
    bool dashdash = false;

#ifndef CONFIG_LIBBPF
    set_option_nobuild(main_options, 0,    "irqs_disabled", LIBBPF_BUILD, true);
    set_option_nobuild(main_options, 0, "tif_need_resched", LIBBPF_BUILD, true);
    set_option_nobuild(main_options, 0,      "exclude_pid", LIBBPF_BUILD, true);
    set_option_nobuild(main_options, 0,   "nr_running_min", LIBBPF_BUILD, true);
    set_option_nobuild(main_options, 0,   "nr_running_max", LIBBPF_BUILD, true);
#endif

    while (argc > 0) {
        argc = parse_options(argc, (const char **)argv, main_options, main_usage,
                             PARSE_OPT_NO_INTERNAL_HELP | PARSE_OPT_KEEP_DASHDASH |
                             (stop_at_non_option ? PARSE_OPT_STOP_AT_NON_OPTION :
                                                   PARSE_OPT_KEEP_ARGV0 | PARSE_OPT_KEEP_UNKNOWN));
        if (argc && argv[0][0] != '-' && argv[0][1] != '-') {
            struct monitor *m = monitor_find(argv[0]);
            if (m != NULL) {
                env.help_monitor = monitor;
                monitor = m;
                continue;
            } else if (stop_at_non_option) {
                stop_at_non_option = false;
                disable_help();
                continue;
            }
        }
        // --
        if (argc && argv[0][0] == '-' && argv[0][1] == '-') {
            argc--;
            memmove(argv, argv + 1, argc * sizeof(argv[0]));
            argv[argc] = NULL;
            dashdash = true;
        }
        break;
    }

    if (monitor == NULL && env.symbols == NULL)
        help();

    if (!dashdash) {
        if (monitor && monitor->argc_init)
            argc = monitor->argc_init(argc, argv);
        else if (argc && env.verbose > 0) {
            int i;
            printf("Unparsed options:");
            for (i = 0; i < argc; i ++)
                printf(" %s", argv[i]);
            printf("\n");
        }
    }

    return argc;
}

static void sig_handler(int sig)
{
    if (sig == SIGCHLD)
        child_finished = 1;
    exiting = 1;
}

static void sigusr2_handler(int sig)
{
    static unsigned long utime = 0, stime = 0;
    static struct timeval tv;
    static bool init = 0;
    struct rusage usage;

    if (init == 0) {
        tzset(); /* Now 'timezone' global is populated. */
        daylight_active = daylight;
        gettimeofday(&tv, NULL);
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
            utime = usage.ru_utime.tv_sec * 1000000UL + usage.ru_utime.tv_usec;
            stime = usage.ru_stime.tv_sec * 1000000UL + usage.ru_stime.tv_usec;
        } else
            return ;
        init = 1;
        return ;
    }

    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        unsigned long user, sys, us;
        struct timeval t;
        char timebuff[64];
        struct tm result;

        gettimeofday(&t, NULL);
        us = t.tv_sec * 1000000UL + t.tv_usec - tv.tv_sec * 1000000UL - tv.tv_usec;
        user = usage.ru_utime.tv_sec * 1000000UL + usage.ru_utime.tv_usec - utime;
        sys = usage.ru_stime.tv_sec * 1000000UL + usage.ru_stime.tv_usec - stime;

        nolocks_localtime(&result, t.tv_sec, timezone, daylight_active);
        strftime(timebuff, sizeof(timebuff), "%Y-%m-%d %H:%M:%S", &result);
        printf("%s.%06u CPU %%usr %.2f %%sys %.2f MAXRSS %luk\n", timebuff, (unsigned int)tv.tv_usec,
                user*100.0/us, sys*100.0/us, usage.ru_maxrss);

        utime += user;
        stime += sys;
        tv = t;
    }
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

struct workload {
    int cork_fd;
    pid_t pid;
};

static int workload_prepare(struct workload *workload, char *argv[])
{
    int child_ready_pipe[2], go_pipe[2];
    char bf;

    if (pipe(child_ready_pipe) < 0) {
        perror("failed to create 'ready' pipe");
        return -1;
    }

    if (pipe(go_pipe) < 0) {
        perror("failed to create 'go' pipe");
        goto out_close_ready_pipe;
    }

    workload->pid = fork();
    if (workload->pid < 0) {
        perror("failed to fork");
        goto out_close_pipes;
    }

    if (!workload->pid) {
        int ret;

        signal(SIGTERM, SIG_DFL);

        close(child_ready_pipe[0]);
        close(go_pipe[1]);
        fcntl(go_pipe[0], F_SETFD, FD_CLOEXEC);

        /*
         * Change the name of this process not to confuse --exclude-perf users
         * that sees 'perf' in the window up to the execvp() and thinks that
         * perf samples are not being excluded.
         */
        prctl(PR_SET_NAME, "perf-exec");

        /*
         * Tell the parent we're ready to go
         */
        close(child_ready_pipe[1]);

        /*
         * Wait until the parent tells us to go.
         */
        ret = read(go_pipe[0], &bf, 1);
        /*
         * The parent will ask for the execvp() to be performed by
         * writing exactly one byte, in workload.cork_fd, usually via
         * evlist__start_workload().
         *
         * For cancelling the workload without actually running it,
         * the parent will just close workload.cork_fd, without writing
         * anything, i.e. read will return zero and we just exit()
         * here.
         */
        if (ret != 1) {
            if (ret == -1)
                perror("unable to read pipe");
            exit(ret);
        }

        execvp(argv[0], (char **)argv);

        exit(-1);
    }

    close(child_ready_pipe[1]);
    close(go_pipe[0]);
    /*
     * wait for child to settle
     */
    if (read(child_ready_pipe[0], &bf, 1) == -1) {
        perror("unable to read pipe");
        goto out_close_pipes;
    }

    fcntl(go_pipe[1], F_SETFD, FD_CLOEXEC);
    workload->cork_fd = go_pipe[1];
    close(child_ready_pipe[0]);
    return 0;

out_close_pipes:
    close(go_pipe[0]);
    close(go_pipe[1]);
out_close_ready_pipe:
    close(child_ready_pipe[0]);
    close(child_ready_pipe[1]);
    return -1;
}

static int workload_start(struct workload *workload)
{
    if (workload->cork_fd > 0) {
        char bf = 0;
        int ret;
        /*
         * Remove the cork, let it rip!
         */
        ret = write(workload->cork_fd, &bf, 1);
        if (ret < 0)
            perror("unable to write to pipe");

        close(workload->cork_fd);
        return ret;
    }

    return 0;
}

void print_time(FILE *fp)
{
    char timebuff[64];
    struct timeval tv;
    struct tm *result;

    gettimeofday(&tv, NULL);
    result = localtime(&tv.tv_sec);
    daylight_active = result->tm_isdst;
    strftime(timebuff, sizeof(timebuff), "%Y-%m-%d %H:%M:%S", result);
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
    int oncpu;

    if (env.exit_n) return;
    oncpu = monitor_instance_oncpu();
    print_time(stderr);
    fprintf(stderr, "lost %llu events on %s #%d\n", event->lost.lost,
                    oncpu ? "CPU" : "thread",
                    oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
}

static void print_fork_exit_fn(union perf_event *event, int ins, int exit)
{
    if (env.verbose >= VERBOSE_ALL) {
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
    if (env.verbose >= VERBOSE_ALL) {
        int oncpu = monitor_instance_oncpu();
        print_time(stderr);
        fprintf(stderr, "comm pid %u tid %u %s on %s #%d\n",
                        event->comm.pid,  event->comm.tid,
                        event->comm.comm,
                        oncpu ? "CPU" : "thread",
                        oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
    }
}

static void print_throttle_unthrottle_fn(union perf_event *event, int ins, int unthrottle)
{
    if (env.verbose >= VERBOSE_NOTICE) {
        int oncpu = monitor_instance_oncpu();
        print_time(stderr);
        fprintf(stderr, "%llu.%06llu: %s events on %s #%d\n",
                        event->throttle.time / NSEC_PER_SEC, (event->throttle.time % NSEC_PER_SEC)/1000,
                        unthrottle ? "unthrottle" : "throttle",
                        oncpu ? "CPU" : "thread",
                        oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
    }
}

static void print_context_switch_fn(union perf_event *event, int ins)
{
    if (env.verbose >= VERBOSE_ALL) {
        int oncpu = monitor_instance_oncpu();
        print_time(stderr);
        fprintf(stderr, "switch on %s #%d\n", oncpu ? "CPU" : "thread",
                        oncpu ? monitor_instance_cpu(ins) : monitor_instance_thread(ins));
    }
}

static void print_context_switch_cpu_fn(union perf_event *event, int ins)
{
    if (env.verbose >= VERBOSE_ALL) {
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
    static long sampled_events = 0;

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
        else
            print_throttle_unthrottle_fn(event, instance, 0);
        break;
    case PERF_RECORD_UNTHROTTLE:
        if (monitor->unthrottle)
            monitor->unthrottle(event, instance);
        else
            print_throttle_unthrottle_fn(event, instance, 1);
        break;
    case PERF_RECORD_SAMPLE:
        if (!env.exit_n || ++sampled_events <= env.exit_n) {
            if (monitor->sample)
                monitor->sample(event, instance);
        } else
            exiting = 1;
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
    int err = 0;
    struct workload workload = {0, 0};
    struct perf_evlist *evlist = NULL;
    struct perf_cpu_map *cpus = NULL, *online;
    struct perf_thread_map *threads = NULL;
    int max_read_size;
    uint64_t time_end;
    int time_left;
    bool deinited;

    sigusr2_handler(0);

    argc = parse_main_options(argc, argv);

    if (env.symbols) {
        syms__convert(stdin, stdout);
        return 0;
    }

    if (argc) {
        workload_prepare(&workload, argv);
    }

    // workload output to stdout & stderr
    // perf-prof output to env.output file
    if (env.output) {
        freopen(env.output, "w+", stdout);
        dup2(STDOUT_FILENO, STDERR_FILENO);
    }

    if (env.order || monitor->order)
        monitor = order(monitor);
    if (env.mmap_pages)
        monitor->pages = env.mmap_pages;

    setlinebuf(stdout);
    setlinebuf(stderr);
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
    } else if (workload.pid) {
        // attach to workload
        threads = thread_map__new_by_pid(workload.pid);
        cpus = perf_cpu_map__dummy_new();
        if (!threads || !cpus) {
            fprintf(stderr, "failed attach to workload\n");
            goto out_delete;
        }
    } else {
        // attach to cpus
        cpus = perf_cpu_map__new(env.cpumask);
        if (env.cgroups)
            // attach to cgroups
            threads = thread_map__cgroups(env.cgroups);
        else
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

    signal(SIGCHLD, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGUSR1, monitor->sigusr1 ? : SIG_IGN);
    signal(SIGUSR2, sigusr2_handler);

    workload_start(&workload);

    max_read_size = perf_evlist__max_read_size(evlist);
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
                        static struct perf_counts_values *count = NULL;
                        static struct perf_counts_values static_count;
                        if (!count) {
                            if (max_read_size <= sizeof(static_count))
                                count = &static_count;
                            else
                                count = malloc(max_read_size);
                            memset(count, 0, max_read_size);
                        }
                        if (perf_evsel__read(evsel, ins, tins, count) == 0)
                            monitor->read(evsel, count, cpu != -1 ? ins : tins);
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

    cgroup_list__delete();

    if (workload.pid && !child_finished)
        kill(workload.pid, SIGTERM);

    return err;
}

