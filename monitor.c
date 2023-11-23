#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/time.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include <linux/thread_map.h>
#include <linux/cgroup.h>
#include <trace_helpers.h>
#include <monitor.h>
#include <tep.h>
#include <timer.h>
#include <stack_helpers.h>


static int daylight_active;

struct event_poll *main_epoll = NULL;

struct list_head prof_dev_list = LIST_HEAD_INIT(prof_dev_list);

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

int prof_dev_nr_ins(struct prof_dev *dev)
{
    int nr_ins;

    nr_ins = perf_cpu_map__nr(dev->cpus);
    if (perf_cpu_map__empty(dev->cpus))
        nr_ins = perf_thread_map__nr(dev->threads);

    return nr_ins;
}

int prof_dev_ins_cpu(struct prof_dev *dev, int ins)
{
    return perf_cpu_map__cpu(dev->cpus, ins);
}

int prof_dev_ins_thread(struct prof_dev *dev, int ins)
{
    return perf_thread_map__pid(dev->threads, ins);
}

int prof_dev_ins_oncpu(struct prof_dev *dev)
{
    return !perf_cpu_map__empty(dev->cpus);
}

int main_epoll_add(int fd, unsigned int events, void *ptr, handle_event handle)
{
    return event_poll__add(main_epoll, fd, events, ptr, handle);
}

int main_epoll_del(int fd)
{
    return event_poll__del(main_epoll, fd);
}

/******************************************************
perf-prof argc argv
******************************************************/

struct env env;

static volatile bool exiting;

const char *main_program_version = PROGRAME " 0.18";

enum {
    LONG_OPT_start = 500,
    LONG_OPT_than,
    LONG_OPT_only_than,
    LONG_OPT_lower,
    LONG_OPT_order_mem,
    LONG_OPT_detail,
    LONG_OPT_period,
};

static int workload_prepare(struct workload *workload, char *argv[]);

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
    else if (strcmp(s, "sametid") == 0)
        env.sametid = true;
    else if (strcmp(s, "samekey") == 0)
        env.samekey = true;
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
    case LONG_OPT_lower:
        env.lower_than = nsparse(arg, NULL);
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
#define OPT_INT_NONEG_SET(s, l, v, os, a, h) { .type = OPTION_INTEGER, .short_name = (s), .long_name = (l), .value = check_vtype(v, int *), .set = check_vtype(os, bool *), .argh = (a), .help = (h), .flags = PARSE_OPT_NONEG }
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
#define OPT_INT_OPTARG_SET(s, l, v, os, d, a, h) \
        { .type = OPTION_INTEGER, .short_name = (s), .long_name = (l), .value = check_vtype(v, int *), .set = check_vtype(os, bool *), .argh = (a), .defval = (intptr_t)(d), .help = (h), .flags = PARSE_OPT_NONEG | PARSE_OPT_OPTARG }
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
    OPT_BOOL_NONEG  ( 0 ,         "tsc", &env.tsc,                         "Convert perf time to tsc time."),
    OPT_U64_NONEG   ( 0 ,  "tsc-offset", &env.tsc_offset,  NULL,           "Sum with tsc-offset to get the final tsc time."),
    OPT_INT_NONEG   ( 0 ,  "usage-self", &env.usage_self,  "ms",           "Periodically output the CPU usage of perf-prof itself, Unit: ms"),
    OPT_PARSE_NOARG ('V',     "version", NULL,             NULL,           "Version info"),
    OPT__VERBOSITY(&env.verbose),
    OPT_HELP(),

    OPT_GROUP("FILTER OPTION:"),
    OPT_BOOL_NONEG  ('G',     "exclude-host", &env.exclude_host,                "Monitor GUEST, exclude host"),
    OPT_BOOL_NONEG  ( 0 ,    "exclude-guest", &env.exclude_guest,               "exclude guest"),
    OPT_BOOL_NONEG  ( 0 ,     "exclude-user", &env.exclude_user,                "exclude user"),
    OPT_BOOL_NONEG  ( 0 ,   "exclude-kernel", &env.exclude_kernel,              "exclude kernel"),
    OPT_BOOLEAN_SET ( 0 ,   "user-callchain", &env.user_callchain,   &env.user_callchain_set,   "include user callchains, no- prefix to exclude"),
    OPT_BOOLEAN_SET ( 0 , "kernel-callchain", &env.kernel_callchain, &env.kernel_callchain_set, "include kernel callchains, no- prefix to exclude"),
    OPT_INT_OPTARG_SET( 0 ,    "irqs_disabled", &env.irqs_disabled,    &env.irqs_disabled_set,    1, "0|1",  "ebpf, irqs disabled or not."),
    OPT_INT_OPTARG_SET( 0 , "tif_need_resched", &env.tif_need_resched, &env.tif_need_resched_set, 1, "0|1",  "ebpf, TIF_NEED_RESCHED is set or not."),
    OPT_INT_NONEG_SET ( 0 ,      "exclude_pid", &env.exclude_pid,      &env.exclude_pid_set,         "PID",  "ebpf, exclude pid"),
    OPT_INT_NONEG_SET ( 0 ,   "nr_running_min", &env.nr_running_min,   &env.nr_running_min_set,       NULL,  "ebpf, minimum number of running processes for CPU runqueue."),
    OPT_INT_NONEG_SET ( 0 ,   "nr_running_max", &env.nr_running_max,   &env.nr_running_max_set,       NULL,  "ebpf, maximum number of running processes for CPU runqueue."),

    OPT_GROUP("PROFILER OPTION:"),
    OPT_PARSE_NONEG ('e', "event", NULL,    "EVENT,...",        "Event selector. use 'perf list tracepoint' to list available tp events.\n"
                                                                "  EVENT,EVENT,...\n"
                                                                "  EVENT: sys:name[/filter/ATTR/ATTR/.../]\n"
                                                                "  filter: ftrace filter\n"
                                                                "  ATTR:\n"
                                                                "      stack: sample_type PERF_SAMPLE_CALLCHAIN\n"
                                                                "      max-stack=int : sample_max_stack\n"
                                                                "      alias=str: event alias\n"
                                                                "      exec=EXPR: a public expression executed by any profiler\n"
                                                                "      top-by=EXPR: add to top, sort by this field\n"
                                                                "      top-add=EXPR: add to top\n"
                                                                "      comm=EXPR: top, show COMM\n"
                                                                "      ptr=EXPR: kmemleak, ptr field, Dflt: ptr=ptr\n"
                                                                "      size=EXPR: kmemleak, size field, Dflt: size=bytes_alloc\n"
                                                                "      num=EXPR: num-dist, num field\n"
                                                                "      key=EXPR: key for multiple events: top, multi-trace\n"
                                                                "      untraced: multi-trace, auxiliary, no two-event analysis\n"
                                                                "      trigger: multi-trace, use events to trigger interval output\n"
                                                                "      vm=uuid: get the mapping from Guest vcpu to Host tid\n"
                                                                "      push=[IP]:PORT: push events to the local broadcast server IP:PORT\n"
                                                                "      push=chardev: push events to chardev, e.g., /dev/virtio-ports/*\n"
                                                                "      push=file: push events to file\n"
                                                                "      pull=[IP]:PORT: pull events from server IP:PORT\n"
                                                                "      pull=chardev: pull events from chardev\n"
                                                                "      pull=file: pull events from file\n"
                                                                "  EXPR:\n"
                                                                "      C expression. See `"PROGRAME" expr -h` for more information."
                                                                ),
    OPT_INT_NONEG   ('F',            "freq", &env.freq,                  NULL,  "Profile at this frequency, No profile: 0"),
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
    OPT_PARSE_NONEG ( LONG_OPT_lower, "lower", &env.lower_than,          "ns",  "Lower than specified time, Unit: s/ms/us/*ns"),
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
                                                       "samepid: Only show events with the same pid as event1 or event2.\n"
                                                       "sametid: Only show events with the same tid as event1 or event2.\n"
                                                       "samekey: Only show events with the same key as event1 or event2."),
    OPT_INT_NONEG   ('T',         "trigger", &env.trigger_freq,          NULL,  "Trigger Threshold, No trigger: 0"),
    OPT_BOOL_NONEG  ( 0 ,            "test", &env.test,                         "Split-lock test verification"),
    OPT_STRDUP_NONEG( 0 ,         "symbols", &env.symbols,               NULL,  "Maps addresses to symbol names.\n"
                                                                                "Similar to pprof --symbols."),
    OPT_STRDUP_NONEG('d',          "device", &env.device,            "device",  "Block device, /dev/sdx"),
    OPT_INT_NONEG   ( 0 ,           "ldlat", &env.ldlat,             "cycles",  "mem-loads latency, Unit: cycles"),
    OPT_BOOL_NONEG  ( 0 ,       "overwrite", &env.overwrite,                    "use overwrite mode"),
    OPT_BOOL_NONEG  ( 0 ,            "spte", &env.spte,                         "kvmmmu: enable kvmmmu:kvm_mmu_set_spte"),
    OPT_BOOL_NONEG  ( 0 ,            "mmio", &env.mmio,                         "kvmmmu: enable kvmmmu:mark_mmio_spte"),
    OPT_BOOL_NONEG  ( 0 ,       "only-comm", &env.only_comm,                    "top: only show comm but not key"),
    OPT_BOOL_NONEG  ( 0 ,           "cycle", &env.cycle,                        "multi-trace: event cycle, from the last one back to the first."),

    OPT_END()
};

const char * const main_usage[] = {
    PROGRAME " profiler [PROFILER OPTION...] [help] [cmd [args...]]",
    PROGRAME " --symbols /path/to/bin",
    "",
    "Profiling based on perf_event and ebpf",
    NULL
};

static void free_env(struct env *e)
{
    if (e->nr_events) {
        while (e->nr_events--) free(e->events[e->nr_events]);
        free(e->events);
    }
    if (e->cpumask) free(e->cpumask);
    if (e->pids) free(e->pids);
    if (e->tids) free(e->tids);
    if (e->cgroups) free(e->cgroups);
    if (e->output) free(e->output);
    if (e->key) free(e->key);
    if (e->filter) free(e->filter);
    if (e->impl) free(e->impl);
    if (e->tp_alloc) free(e->tp_alloc);
    if (e->tp_free) free(e->tp_free);
    if (e->flame_graph) free(e->flame_graph);
    if (e->heatmap) free(e->heatmap);
    if (e->symbols) free(e->symbols);
    if (e->device) free(e->device);
    if (e->workload.pid > 0) {
        kill(e->workload.pid, SIGTERM);
    }
    if (e != &env) free(e);
    else
        memset(e, 0, sizeof(*e));
}

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

static void flush_main_options(profiler *p)
{
    struct option *opts;
    int i;

    if (!p->argv)
        return ;

    // disable all opts
    opts = main_options;
    for (; opts->type != OPTION_END; opts++) {
        opts->flags |= PARSE_OPT_DISABLED;
    }

    // enable profiler opts
    opts = main_options;
    for (; opts->type != OPTION_END; opts++) {
        for (i = 2/*PROGRAME, "-h"*/; p->argv[i]; i ++) {
            if (p->argv[i][1] == '\0' &&
                opts->short_name < 256 && isalnum(opts->short_name) && /* isshort */
                p->argv[i][0] == opts->short_name)
                goto enable;
            if (opts->long_name && strcmp(opts->long_name, p->argv[i]) == 0)
                goto enable;
            if (opts->type == OPTION_GROUP && strcmp(opts->help, p->argv[i]) == 0)
                goto enable;
        }
        continue;
    enable:
        opts->flags &= (~PARSE_OPT_DISABLED);
    }
}

#ifndef CONFIG_LIBBPF
static const char *LIBBPF_BUILD = "NO CONFIG_LIBBPF=y";
#endif

static int parse_main_options(int argc, char *argv[])
{
    bool stop_at_non_option = true;
    bool dashdash = false;
    char *COMP_TYPE = getenv("COMP_TYPE"); // Bash Completion COMP_TYPE variable
    int comp_type = COMP_TYPE ? atoi(COMP_TYPE) : 0;
    bool enable_optcomp = false;

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
                             (enable_optcomp ? PARSE_OPT_BASH_COMPLETION : 0) |
                             (stop_at_non_option ? PARSE_OPT_STOP_AT_NON_OPTION :
                                                   PARSE_OPT_KEEP_ARGV0 | PARSE_OPT_KEEP_UNKNOWN));
        if (argc && argv[0][0] != '\0' && argv[0][0] != '-') {
            struct monitor *m = monitor_find(argv[0]);
            if (m != NULL) {
                env.help_monitor = monitor;
                monitor = m;
                flush_main_options(m);
                enable_optcomp = comp_type ? true : false;
                continue;
            } else if (comp_type) {
                break;
            } else if (stop_at_non_option) {
                stop_at_non_option = false;
                disable_help();
                continue;
            }
        }
        if (comp_type)
            break;
        // --
        if (argc && argv[0][0] == '-' && argv[0][1] == '-') {
            argc--;
            memmove(argv, argv + 1, argc * sizeof(argv[0]));
            argv[argc] = NULL;
            dashdash = true;
        }
        break;
    }

    if (comp_type) {
        if (monitor) {
            if (argc == 0)
                printf(monitor->compgen ? "\"%s %s\"\n" : "%s%s\n", monitor->name, monitor->compgen ?: "");
        } else {
            struct monitor *m = NULL;
            while((m = monitor_next(m))) {
                if (!argc || argv[0][0] == '\0' ||
                    strncmp(m->name, argv[0], strlen(argv[0])) == 0) {
                    if (m->compgen && comp_type != '?')
                        printf("\"%s %s\"\n", m->name, m->compgen);
                    else
                        printf("%s\n", m->name);
                }
            }
        }
        exit(0);
    }

    if (env.symbols) {
        syms__convert(stdin, stdout);
        exit(0);
    }

    if (monitor == NULL)
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

    if (argc > 0) {
        if (workload_prepare(&env.workload, argv) < 0)
            goto failed;
    }

    return 0;

failed:
    free_env(&env);
    return -1;
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

static void usage_self_handle(struct timer *timer)
{
    sigusr2_handler(0);
}

static void prof_dev_winsize(struct prof_dev *new)
{
    struct prof_dev *dev, *next;
    struct winsize size;
    int n;
    bool shared;

    if (isatty(STDOUT_FILENO) &&
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0) {
        n = new && list_empty(&new->dev_link);
        list_for_each_entry(dev, &prof_dev_list, dev_link)
            n ++;
        shared = n > 1;
        list_for_each_entry_safe(dev, next, &prof_dev_list, dev_link) {
            if (dev != new && dev->prof->sigusr) {
                dev->tty.shared = shared;
                dev->tty.row = size.ws_row;
                dev->tty.col = size.ws_col;
                dev->prof->sigusr(dev, SIGWINCH); // May cause disable the alternative buffer.
            }
            n ++;
        }
        dev = new;
        if (dev && dev->prof->sigusr) {
            dev->tty.istty = true;
            dev->tty.shared = shared;
            dev->tty.row = size.ws_row;
            dev->tty.col = size.ws_col;
        }
    }
}

static void handle_signal(int fd, unsigned int revents, void *ptr)
{
    struct prof_dev *dev, *next;
    struct signalfd_siginfo fdsi;
    int s;

    s = read(fd, &fdsi, sizeof(struct signalfd_siginfo));
    if (s != sizeof(fdsi)) return ;

    switch (fdsi.ssi_signo) {
        case SIGCHLD:
            if (fdsi.ssi_code == CLD_EXITED ||
                fdsi.ssi_code == CLD_KILLED ||
                fdsi.ssi_code == CLD_DUMPED) {
                int status;
                int pid = waitpid(fdsi.ssi_pid, &status, WNOHANG);
                if (pid > 0) {
                    list_for_each_entry_safe(dev, next, &prof_dev_list, dev_link)
                        if (dev->env->workload.pid == pid) {
                            dev->env->workload.pid = 0;
                            // Automatically close prof_dev after the workload exits.
                            prof_dev_close(dev);
                        }
                }
            }
            break;
        case SIGINT:
        case SIGTERM:
            exiting = true;
            break;
        case SIGUSR1: {
                list_for_each_entry_safe(dev, next, &prof_dev_list, dev_link)
                    if (dev->prof->sigusr)
                        dev->prof->sigusr(dev, SIGUSR1);
            }
            break;
        case SIGUSR2:
            sigusr2_handler(SIGUSR2);
            break;
        case SIGWINCH:
            prof_dev_winsize(NULL);
            break;
        default:
            break;
    }
}

static int epoll_wait_signal(int signum, ...)
{
    va_list ap;
    sigset_t mask;
    int sfd = -1;

    sigemptyset(&mask);
    sigaddset(&mask, signum);

    va_start(ap, signum);
    while ((signum = va_arg(ap, int)))
        sigaddset(&mask, signum);
    va_end(ap);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    if ((sfd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) goto e1;
    if (main_epoll_add(sfd, EPOLLIN, NULL, handle_signal) < 0) goto e2;
    return 0;

e2: close(sfd);
e1: sigprocmask(SIG_UNBLOCK, &mask, NULL);
    return -1;
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

int callchain_flags(struct prof_dev *dev, int dflt_flags)
{
    int flags = dflt_flags;

    if (dev->env->user_callchain_set) {
        if (dev->env->user_callchain)
            flags |= CALLCHAIN_USER;
        else
            flags &= ~CALLCHAIN_USER;
    }
    if (dev->env->kernel_callchain_set) {
        if (dev->env->kernel_callchain)
            flags |= CALLCHAIN_KERNEL;
        else
            flags &= ~CALLCHAIN_KERNEL;
    }
    return flags;
}

int exclude_callchain_user(struct prof_dev *dev, int dflt_flags)
{
    int flags = callchain_flags(dev, dflt_flags);
    return flags & CALLCHAIN_USER ? 0 : 1;
}

int exclude_callchain_kernel(struct prof_dev *dev, int dflt_flags)
{
    int flags = callchain_flags(dev, dflt_flags);
    return flags & CALLCHAIN_KERNEL ? 0 : 1;
}

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
         * Kill me when my parent dies.
         */
        prctl(PR_SET_PDEATHSIG, SIGKILL);

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

void print_lost_fn(struct prof_dev *dev, union perf_event *event, int ins)
{
    int oncpu;

    if (env.exit_n) return;
    oncpu = prof_dev_ins_oncpu(dev);
    print_time(stderr);
    fprintf(stderr, "lost %llu events on %s #%d\n", event->lost.lost,
                    oncpu ? "CPU" : "thread",
                    oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
}

static void print_fork_exit_fn(struct prof_dev *dev, union perf_event *event, int ins, int exit)
{
    if (env.verbose >= VERBOSE_ALL) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "%s ppid %u ptid %u pid %u tid %u on %s #%d\n",
                        exit ? "exit" : "fork",
                        event->fork.ppid, event->fork.ptid,
                        event->fork.pid,  event->fork.tid,
                        oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static void print_comm_fn(struct prof_dev *dev, union perf_event *event, int ins)
{
    if (env.verbose >= VERBOSE_ALL) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "comm pid %u tid %u %s on %s #%d\n",
                        event->comm.pid,  event->comm.tid,
                        event->comm.comm,
                        oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static void print_throttle_unthrottle_fn(struct prof_dev *dev, union perf_event *event, int ins, int unthrottle)
{
    if (env.verbose >= VERBOSE_NOTICE) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "%llu.%06llu: %s events on %s #%d\n",
                        event->throttle.time / NSEC_PER_SEC, (event->throttle.time % NSEC_PER_SEC)/1000,
                        unthrottle ? "unthrottle" : "throttle",
                        oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static void print_context_switch_fn(struct prof_dev *dev, union perf_event *event, int ins)
{
    if (env.verbose >= VERBOSE_ALL) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "switch on %s #%d\n", oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static void print_context_switch_cpu_fn(struct prof_dev *dev, union perf_event *event, int ins)
{
    if (env.verbose >= VERBOSE_ALL) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "switch next pid %u tid %u on %s #%d\n",
                        event->context_switch.next_prev_pid, event->context_switch.next_prev_tid,
                        oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

int perf_event_process_record(struct prof_dev *dev, union perf_event *event, int instance, bool writable, bool converted)
{
    profiler *prof = dev->prof;
    struct env *env = dev->env;

    switch (event->header.type) {
    case PERF_RECORD_LOST:
        if (prof->lost)
            prof->lost(dev, event, instance, 0);
        else
            print_lost_fn(dev, event, instance);
        break;
    case PERF_RECORD_FORK:
        if (prof->fork)
            prof->fork(dev, event, instance);
        else
            print_fork_exit_fn(dev, event, instance, 0);
        break;
    case PERF_RECORD_COMM:
        if (prof->comm)
            prof->comm(dev, event, instance);
        else
            print_comm_fn(dev, event, instance);
        break;
    case PERF_RECORD_EXIT:
        if (prof->exit)
            prof->exit(dev, event, instance);
        else
            print_fork_exit_fn(dev, event, instance, 1);
        break;
    case PERF_RECORD_THROTTLE:
        if (prof->throttle)
            prof->throttle(dev, event, instance);
        else
            print_throttle_unthrottle_fn(dev, event, instance, 0);
        break;
    case PERF_RECORD_UNTHROTTLE:
        if (prof->unthrottle)
            prof->unthrottle(dev, event, instance);
        else
            print_throttle_unthrottle_fn(dev, event, instance, 1);
        break;
    case PERF_RECORD_SAMPLE:
        if (likely(!env->exit_n) || ++dev->sampled_events <= env->exit_n) {
            if (prof->sample)
                prof->sample(dev, unlikely(converted) ? event : perf_event_convert(dev, event, writable), instance);
        }
        if (unlikely(env->exit_n) && dev->sampled_events >= env->exit_n)
            dev->close = true;
        break;
    case PERF_RECORD_SWITCH:
        if (prof->context_switch)
            prof->context_switch(dev, event, instance);
        else
            print_context_switch_fn(dev, event, instance);
        break;
    case PERF_RECORD_SWITCH_CPU_WIDE:
        if (prof->context_switch_cpu)
            prof->context_switch_cpu(dev, event, instance);
        else
            print_context_switch_cpu_fn(dev, event, instance);
        break;
    default:
        if (likely(!env->exit_n) || ++dev->sampled_events <= env->exit_n)
            fprintf(stderr, "unknown perf sample type %d\n", event->header.type);
        if (unlikely(env->exit_n) && dev->sampled_events >= env->exit_n)
            dev->close = true;
        return -1;
    }
    return 0;
}

static void perf_event_handle_mmap(struct prof_dev *dev, struct perf_mmap *map)
{
    union perf_event *event;
    bool writable = false;
    int idx = perf_mmap__idx(map);

    if (perf_mmap__read_init(map) < 0)
        return;

    perf_event_convert_read_tsc_conversion(dev, map);
    while ((event = perf_mmap__read_event(map, &writable)) != NULL) {
        /* process event */
        perf_event_process_record(dev, event, idx, writable, false);
        perf_mmap__consume(map);
    }
    perf_mmap__read_done(map);
}

static void perf_event_handle(int fd, unsigned int revents, void *ptr)
{
    struct prof_dev *dev = perf_evlist_poll__get_external(NULL, ptr);

    perf_event_handle_mmap(dev, ptr);
    if (revents & EPOLLHUP) {
        main_epoll_del(fd);
        dev->nr_pollfd --;
    }
    // dev->nr_pollfd == 0, All attached processes exit.
    // dev->close, Actively close. -N 100 etc.
    if (dev->nr_pollfd == 0 || dev->close)
        prof_dev_close(dev);
}

static int __addfn(int fd, unsigned events, struct perf_mmap *mmap)
{
    struct prof_dev *dev = perf_evlist_poll__get_external(NULL, mmap);
    dev->nr_pollfd ++;
    return main_epoll_add(fd, events, mmap, perf_event_handle);
}

static int __delfn(int fd, unsigned events, struct perf_mmap *mmap)
{
    main_epoll_del(fd);
    return 0;
}

static void interval_handle(struct timer *timer)
{
    struct prof_dev *dev = container_of(timer, struct prof_dev, timer);
    struct perf_evlist *evlist = dev->evlist;
    struct perf_cpu_map *cpus = dev->cpus;
    struct perf_thread_map *threads = dev->threads;
    int max_read_size = dev->max_read_size;
    profiler *prof = dev->prof;

    if (dev->pages) {
        struct perf_mmap *map;
        perf_evlist__for_each_mmap(evlist, map, dev->env->overwrite) {
            perf_event_handle_mmap(dev, map);
        }
    }

    if (prof->read) {
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
                    if (perf_evsel__read(evsel, ins, tins, count) == 0 &&
                        prof->read(dev, evsel, count, cpu != -1 ? ins : tins))
                        break;
                }
            }
        }
    }

    if (prof->interval)
        prof->interval(dev);

    if (dev->close)
        prof_dev_close(dev);
}

struct prof_dev *prof_dev_open(profiler *prof, struct env *env)
{
    struct perf_evlist *evlist = NULL;
    struct perf_cpu_map *cpus = NULL, *online;
    struct perf_thread_map *threads = NULL;
    struct prof_dev *dev;
    int reinit = 0;
    int err = 0;

    dev = malloc(sizeof(*dev));
    if (!dev)
        return NULL;

    memset(dev, 0, sizeof(*dev));
    dev->prof = prof;
    dev->env = env;
    INIT_LIST_HEAD(&dev->dev_link);

    if (env->order || prof->order) {
        order(dev);
        prof = dev->prof;
    }

    dev->pages = prof->pages;
    if (env->mmap_pages)
        dev->pages = env->mmap_pages;

    dev->auto_enable = true;
    prof_dev_winsize(dev);

reinit:
    reinit = 0;

    evlist = perf_evlist__new();
    if (!evlist) {
        fprintf(stderr, "failed to create evlist\n");
        goto out_free;
    }
    dev->evlist = evlist;
    perf_evlist_poll__external(evlist, dev);

    if (env->pids || env->tids) {
        // attach to processes
        threads = thread_map__new_str(env->pids, env->tids, 0, 0);
        cpus = perf_cpu_map__dummy_new();
        if (!threads || !cpus) {
            fprintf(stderr, "failed to create pids\n");
            goto out_delete;
        }
    } else if (env->workload.pid) {
        // attach to workload
        threads = thread_map__new_by_pid(env->workload.pid);
        cpus = perf_cpu_map__dummy_new();
        if (!threads || !cpus) {
            fprintf(stderr, "failed attach to workload\n");
            goto out_delete;
        }
    } else {
        // attach to cpus
        cpus = perf_cpu_map__new(env->cpumask);
        if (env->cgroups)
            // attach to cgroups
            threads = thread_map__cgroups(env->cgroups);
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
    dev->cpus = cpus;
    dev->threads = threads;

    if(prof->init(dev) < 0) {
        fprintf(stderr, "monitor(%s) init failed\n", prof->name);
        goto out_delete;
    }
    if(perf_event_convert_init(dev) < 0) {
        fprintf(stderr, "monitor(%s) convert failed\n", prof->name);
        goto out_deinit;
    }
    /* prof->init allows reassignment of cpus and threads */
    perf_evlist__set_maps(evlist, dev->cpus, dev->threads);

    err = perf_evlist__open(evlist);
    if (err) {
        if (err == -ESRCH && !env->cgroups) {
            int idx, thread;
            perf_thread_map__for_each_thread(thread, idx, dev->threads) {
                if (thread >= 0) {
                    if (kill(thread, 0) < 0 && errno == ESRCH) {
                        fprintf(stderr, "thread %d %s. reinit.\n", thread, strerror(errno));
                        reinit = 1;
                    }
                }
            }
        }
        if (!reinit)
            fprintf(stderr, "failed to open evlist, %d\n", err);
        goto out_deinit;
    }

    if (prof->filter && prof->filter(dev) < 0) {
        fprintf(stderr, "monitor(%s) filter failed\n", prof->name);
        goto out_close;
    }

    if (dev->pages) {
        err = perf_evlist__mmap(evlist, dev->pages);
        if (err) {
            fprintf(stderr, "monitor(%s) mmap failed\n", prof->name);
            goto out_close;
        }
        err = perf_evlist_poll__foreach_fd(evlist, __addfn);
        if (err) {
            fprintf(stderr, "monitor(%s) poll failed\n", prof->name);
            goto out_delfn;
        }
    }

    if (dev->auto_enable) {
        perf_evlist__enable(evlist);
        if (prof->enabled)
            prof->enabled(dev);
    }

    if (env->interval) {
        dev->max_read_size = perf_evlist__max_read_size(evlist);
        timer_init(&dev->timer, interval_handle);
        if (dev->auto_enable)
            timer_start(&dev->timer, env->interval * 1000000UL, false);
    }

    if (dev->auto_enable)
        workload_start(&env->workload);

    list_add(&dev->dev_link, &prof_dev_list);

    return dev;

out_delfn:
    if (dev->pages) {
        perf_evlist_poll__foreach_fd(evlist, __delfn);
        perf_evlist__munmap(evlist);
    }
out_close:
    perf_evlist__close(evlist);
out_deinit:
    perf_event_convert_deinit(dev);
    prof->deinit(dev);
out_delete:
    perf_evlist__set_maps(evlist, NULL, NULL);
    perf_evlist__delete(evlist);
    perf_cpu_map__put(dev->cpus);
    perf_thread_map__put(dev->threads);

    if (env->cgroups)
        cgroup_list__delete();

    if (reinit)
        goto reinit;

out_free:
    free_env(env);
    free(dev);

    return NULL;
}

void prof_dev_enable(struct prof_dev *dev)
{
    profiler *prof;
    struct env *env;
    struct perf_evlist *evlist;

    if (!dev || dev->auto_enable)
        return;

    prof = dev->prof;
    env = dev->env;
    evlist = dev->evlist;
    dev->auto_enable = true;

    perf_evlist__enable(evlist);
    if (prof->enabled)
        prof->enabled(dev);

    if (env->interval)
        timer_start(&dev->timer, env->interval * 1000000UL, false);

    workload_start(&env->workload);
}

void prof_dev_close(struct prof_dev *dev)
{
    profiler *prof = dev->prof;
    struct perf_evlist *evlist = dev->evlist;

    list_del(&dev->dev_link);

    // Flush remaining perf events.
    if (dev->pages) {
        struct perf_mmap *map;
        perf_evlist__for_each_mmap(evlist, map, dev->env->overwrite) {
            perf_event_handle_mmap(dev, map);
        }
    }

    if (dev->env->interval) {
        timer_destroy(&dev->timer);
    }

    perf_evlist__disable(evlist);

    /*
     * deinit before perf_evlist__munmap.
     * When order is enabled, some events are also cached inside the order,
     * and then deinit will refresh all events.
     * Order::base profiler handles events and may call perf_evlist__id_to_evsel,
     * which requires id_hash. But perf_evlist__munmap will reset id_hash.
     * Therefore, deinit must be executed first.
    **/
    prof->deinit(dev);
    perf_event_convert_deinit(dev);

    if (dev->pages) {
        perf_evlist_poll__foreach_fd(evlist, __delfn);
        perf_evlist__munmap(evlist);
    }

    perf_evlist__close(evlist);

    perf_evlist__set_maps(evlist, NULL, NULL);
    perf_evlist__delete(evlist);
    perf_cpu_map__put(dev->cpus);
    perf_thread_map__put(dev->threads);

    if (dev->env && dev->env->cgroups)
        cgroup_list__delete();

    if (dev->env)
        free_env(dev->env);

    free(dev);

    if (list_empty(&prof_dev_list))
        exiting = true;
}

static void prof_dev_list_close(void)
{
    struct prof_dev *dev, *next;

    list_for_each_entry_safe(dev, next, &prof_dev_list, dev_link)
        prof_dev_close(dev);
}

static void print_marker_and_interval(int fd, unsigned int revents, void *ptr)
{
    char buf[512];

    if (revents & EPOLLIN) {
        char *line = fgets(buf, sizeof(buf), stdin);
        if (line) {
            struct prof_dev *dev, *next;
            list_for_each_entry_safe(dev, next, &prof_dev_list, dev_link)
                interval_handle(&dev->timer);
            print_time(stdout);
            printf("%s", line);
        }
    }
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
    int err = -1;
    struct timer usage_self;

    sigusr2_handler(0);

    setlinebuf(stdin);
    setlinebuf(stdout);
    setlinebuf(stderr);
    libperf_init(libperf_print);

    main_epoll = event_poll__alloc(64);
    if (!main_epoll) {
        return -1;
    }

    err = parse_main_options(argc, argv);
    if (err < 0)
        return err;

    // workload output to stdout & stderr
    // perf-prof output to env.output file
    if (env.output) {
        if (!freopen(env.output, "a", stdout))
            return -1;
        dup2(STDOUT_FILENO, STDERR_FILENO);
    }

    if (epoll_wait_signal(SIGCHLD, SIGINT, SIGTERM, SIGUSR1, SIGUSR2, SIGWINCH, 0) < 0)
        return -1;
    if (!isatty(STDIN_FILENO))
        main_epoll_add(STDIN_FILENO, EPOLLIN, NULL, print_marker_and_interval);
    if (env.usage_self) {
        timer_init(&usage_self, usage_self_handle);
        timer_start(&usage_self, env.usage_self * 1000000UL, false);
    }

    if (!prof_dev_open(monitor, &env))
        return -1;

    while (!exiting) {
        int fds = event_poll__poll(main_epoll, -1);

        // -ENOENT means there are no file descriptors in event_poll.
        if (fds == -ENOENT)
            exiting = true;
    }
    err = 0;

    prof_dev_list_close();

    if (env.usage_self)
        timer_destroy(&usage_self);
    if (!isatty(STDIN_FILENO))
        main_epoll_del(STDIN_FILENO);

    return err;
}

