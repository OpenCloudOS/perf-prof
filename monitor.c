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
#include <sys/utsname.h>
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

struct monitor * monitor_find(const char *name)
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

static volatile int running = 0;

const char *main_program_version = PROGRAME " 1.1";

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
    OPT_STRDUP_NONEG('C',        "cpus", &env.cpumask,    "cpu[-cpu],...", "Monitor the specified CPU, Dflt: all cpu"),
    OPT_STRDUP_NONEG('p',        "pids", &env.pids,       "pid,...",       "Attach to processes"),
    OPT_STRDUP_NONEG('t',        "tids", &env.tids,       "tid,...",       "Attach to threads"),
    OPT_STRDUP_NONEG( 0 ,     "cgroups", &env.cgroups,    "cgroup,...",    "Attach to cgroups, support regular expression."),
    OPT_BOOL_NONEG  ( 0 ,     "inherit", &env.inherit,                     "Child tasks do inherit counters."),
    OPT_INT_NONEG_SET( 0 ,  "watermark", &env.watermark,  &env.watermark_set, "0-100",  "Wake up "PROGRAME" watermark."),
    OPT_INT_NONEG   ('i',    "interval", &env.interval,   "ms",            "Interval, Unit: ms"),
    OPT_STRDUP_NONEG('o',      "output", &env.output,     "file",          "Output file name"),
    OPT_BOOL_NONEG  ( 0 ,       "order", &env.order,                       "Order events by timestamp."),
    OPT_PARSE_NONEG (LONG_OPT_order_mem, "order-mem", &env.order_mem, "bytes", "Maximum memory used by ordering events. Unit: GB/MB/KB/*B."),
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
    OPT_INT_NONEG_SET ( 0 ,      "exclude_pid", &env.exclude_pid,      &env.exclude_pid_set,         "pid",  "ebpf, exclude pid"),
    OPT_INT_NONEG_SET ( 0 ,   "nr_running_min", &env.nr_running_min,   &env.nr_running_min_set,       NULL,  "ebpf, minimum number of running processes for CPU runqueue."),
    OPT_INT_NONEG_SET ( 0 ,   "nr_running_max", &env.nr_running_max,   &env.nr_running_max_set,       NULL,  "ebpf, maximum number of running processes for CPU runqueue."),

    OPT_GROUP("PROFILER OPTION:"),
    OPT_PARSE_NONEG ('e', "event", NULL,    "EVENT,...",        "Event selector. use 'perf list tracepoint' to list available tp events.\n"
                                                                "  EVENT,EVENT,...\n"
                                                                "  EVENT: sys:name[/filter/ATTR/ATTR/.../]\n"
                                                                "         profiler[/option/ATTR/ATTR/.../]\n"
                                                                "  filter: trace events filter\n"
                                                                "  ATTR:\n"
                                                                "      stack: sample_type PERF_SAMPLE_CALLCHAIN\n"
                                                                "      max-stack=int : sample_max_stack\n"
                                                                "      alias=str: event alias\n"
                                                                "      exec=EXPR: a public expression executed by any profiler\n"
                                                                "      cpus=cpu[-cpu]: attach to a different cpu list.\n"
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
                                                                "      push=[IP:]PORT: push events to the local broadcast server IP:PORT\n"
                                                                "      push=chardev: push events to chardev, e.g., /dev/virtio-ports/*\n"
                                                                "      push=file: push events to file\n"
                                                                "      pull=[IP:]PORT: pull events from server IP:PORT\n"
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
    OPT_BOOLEAN_SET ('S',   "interruptible", &env.interruptible, &env.interruptible_set, "TASK_INTERRUPTIBLE, no- prefix to exclude"),
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
        if (m->argv && m->desc) {
            argc = 0;
            while (m->argv[argc++] != NULL);
            parse_options(argc - 1, m->argv, main_options, m->desc, PARSE_OPT_INTERNAL_HELP_NO_ORDER);
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

static profiler *parse_main_options(int argc, char *argv[])
{
    profiler *prof = NULL;
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
                if (strcmp(m->name, "help") == 0)
                    env.help_monitor = prof;
#ifdef MULTI_PROF
                else if (prof) {
                    struct env *e = zalloc(sizeof(struct env));
                    if (e) {
                        *e = env;
                        prof_dev_open(prof, e);
                    }
                    memset(&env, 0, sizeof(struct env));
                }
#endif
                prof = m;
                monitor = m; // monitor only used in help();
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
        if (prof) {
            if (argc == 0)
                printf(prof->compgen ? "\"%s %s\"\n" : "%s%s\n", prof->name, prof->compgen ?: "");
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
        syms__convert(stdin, stdout, env.symbols);
        exit(0);
    }

    if (prof == NULL)
        help();

    if (!dashdash) {
        if (prof && prof->argc_init)
            argc = prof->argc_init(argc, argv);
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

    return prof;

failed:
    free_env(&env);
    return NULL;
}

struct env *parse_string_options(char *str)
{
    char *token;
    int argc = 1; // argv[0] = "perf-prof"
    char **argv = malloc((argc + 1)*sizeof(char*));
    struct env *e = NULL;

    token = strtok(str, " ");
    while (token && argv) {
        argv[argc++] = token;
        argv = realloc(argv, (argc + 1)*sizeof(char*));
        token = strtok(NULL, " ");
    }
    if (!argv)
        return NULL;

    memset(&env, 0, sizeof(struct env));
    if (parse_main_options(argc, argv)) {
        e = malloc(sizeof(*e));
        if (e) *e = env;
    }
    free(argv);
    return e;
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
                        if (prof_dev_is_final(dev) && dev->env->workload.pid == pid) {
                            dev->env->workload.pid = 0;
                            // Automatically close prof_dev after the workload exits.
                            prof_dev_close(dev);
                            break;
                        }
                }
            }
            break;
        case SIGINT:
        case SIGTERM:
            running = 0;
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

int kernel_release(void)
{
    struct utsname kernel_info;
    int major, minor, patch;

    if (uname(&kernel_info) == 0 &&
        sscanf(kernel_info.release, "%d.%d.%d", &major, &minor, &patch) == 3) {
        return KERNEL_VERSION(major, minor, patch);
    }
    return -1;
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

        // Disable HEAPCHECK.
        // See: https://gperftools.github.io/gperftools/heap_checker.html
        unsetenv("HEAPCHECK");

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
        else
            global_comm_flush(workload->pid); // flush pid's comm, "perf-exec" is temporary.

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

    if (dev->env->exit_n) return;
    oncpu = prof_dev_ins_oncpu(dev);
    print_time(stderr);
    fprintf(stderr, "%s: lost %llu events on %s #%d\n", dev->prof->name, event->lost.lost,
                    oncpu ? "CPU" : "thread",
                    oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
}

static void print_fork_exit_fn(struct prof_dev *dev, union perf_event *event, int ins, int exit)
{
    if (dev->env->verbose >= VERBOSE_ALL) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "%s: %s ppid %u ptid %u pid %u tid %u on %s #%d\n", dev->prof->name,
                        exit ? "exit" : "fork",
                        event->fork.ppid, event->fork.ptid,
                        event->fork.pid,  event->fork.tid,
                        oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static void print_comm_fn(struct prof_dev *dev, union perf_event *event, int ins)
{
    if (dev->env->verbose >= VERBOSE_ALL) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "%s: comm pid %u tid %u %s on %s #%d\n", dev->prof->name,
                        event->comm.pid,  event->comm.tid,
                        event->comm.comm,
                        oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static void print_throttle_unthrottle_fn(struct prof_dev *dev, union perf_event *event, int ins, int unthrottle)
{
    if (dev->env->verbose >= VERBOSE_NOTICE) {
        int oncpu = prof_dev_ins_oncpu(dev);
        prof_dev_print_time(dev, event->throttle.time, stderr);
        fprintf(stderr, "%s: %llu.%06llu: %s events on %s #%d\n", dev->prof->name,
                        event->throttle.time / NSEC_PER_SEC, (event->throttle.time % NSEC_PER_SEC)/1000,
                        unthrottle ? "unthrottle" : "throttle",
                        oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static void print_context_switch_fn(struct prof_dev *dev, union perf_event *event, int ins)
{
    if (dev->env->verbose >= VERBOSE_ALL) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "%s: switch on %s #%d\n", oncpu ? "CPU" : "thread", dev->prof->name,
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static void print_context_switch_cpu_fn(struct prof_dev *dev, union perf_event *event, int ins)
{
    if (dev->env->verbose >= VERBOSE_ALL) {
        int oncpu = prof_dev_ins_oncpu(dev);
        print_time(stderr);
        fprintf(stderr, "%s: switch next pid %u tid %u on %s #%d\n", dev->prof->name,
                        event->context_switch.next_prev_pid, event->context_switch.next_prev_tid,
                        oncpu ? "CPU" : "thread",
                        oncpu ? prof_dev_ins_cpu(dev, ins) : prof_dev_ins_thread(dev, ins));
    }
}

static inline union perf_event *
perf_event_forward(struct prof_dev *dev, union perf_event *event, int *instance, bool writable, bool converted)
{
    struct perf_record_dev *event_dev = (void *)dev->forward.event_dev;
    void *data;

    memset(event_dev, 0, offsetof(struct perf_record_dev, event));
    event_dev->header.size = offsetof(struct perf_record_dev, event) + event->header.size;
    event_dev->header.type = PERF_RECORD_DEV;

    memcpy(&event_dev->event, event, event->header.size);
    if (!converted)
        perf_event_convert(dev, &event_dev->event, true);

    // Build perf_event with sample_type, PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU.
    data = (void *)event_dev->event.sample.array;
    event_dev->pid = *(u32 *)(data + dev->forward.tid_pos);
    event_dev->tid = *(u32 *)(data + dev->forward.tid_pos + sizeof(u32));
    event_dev->time = *(u64 *)(data + dev->forward.time_pos);
    if (dev->forward.id_pos >= 0)
        event_dev->id = *(u64 *)(data + dev->forward.id_pos);
    event_dev->cpu = *(u32 *)(data + dev->forward.cpu_pos);
    event_dev->instance = *instance;
    event_dev->dev = dev;

    if (dev->forward.ins_reset)
        *instance = 0;

    return (union perf_event *)event_dev;
}

int perf_event_process_record(struct prof_dev *dev, union perf_event *event, int instance, bool writable, bool converted)
{
    profiler *prof;
    struct env *env;

    if (dev->forward.target) {
        // Forward upward.
        if (event->header.type == PERF_RECORD_SAMPLE) {
            struct perf_record_dev *event_dev;

            event = perf_event_forward(dev, event, &instance, writable, converted);
            converted = true;

            // The source device forwards events after its `enabled_after' to the target device.
            event_dev = (void *)event;
            if (unlikely(event_dev->time < dev->time_ctx.enabled_after)) {
                return 0;
            }
        }
        // Only PERF_RECORD_SAMPLE events are forwarded.
        if (event->header.type == PERF_RECORD_DEV)
            dev = dev->forward.target;
    } else if (event->header.type == PERF_RECORD_DEV) {
        // Return down.
        struct perf_record_dev *event_dev = (void *)event;
        event = &event_dev->event;
        dev = event_dev->dev;
        instance = event_dev->instance;
        converted = true;
    }
    prof = dev->prof;
    env = dev->env;

    switch (event->header.type) {
    case PERF_RECORD_LOST:
        if (prof->lost)
            prof->lost(dev, event, instance, 0, 0);
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
    case PERF_RECORD_DEV:
    case PERF_RECORD_SAMPLE:
        if (likely(!env->exit_n) || ++dev->sampled_events <= env->exit_n) {
            if (prof->sample) {
                if (likely(!converted))
                    event = perf_event_convert(dev, event, writable);

                if (dev->time_ctx.sample_type & PERF_SAMPLE_TIME) {
                    dev->time_ctx.last_evtime = *(u64 *)((void *)event->sample.array + dev->time_ctx.time_pos);
                    if (unlikely(dev->time_ctx.last_evtime < dev->time_ctx.enabled_after)) {
                        if (dev->sampled_events > 0)
                            dev->sampled_events --;
                        break;
                    }
                }

                prof->sample(dev, event, instance);
            }
        }
        if (unlikely(env->exit_n) && dev->sampled_events >= env->exit_n)
            prof_dev_disable(dev);
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
            prof_dev_disable(dev);
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
        // dev->nr_pollfd == 0, All attached processes exit.
        if (dev->nr_pollfd == 0)
            prof_dev_disable(dev);
    }
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
    profiler *prof = dev->prof;
    struct prof_dev *source, *next;

    // Do not use prof_dev_flush().
    if (dev->pages) {
        struct perf_mmap *map;
        perf_evlist__for_each_mmap(evlist, map, dev->env->overwrite) {
            perf_event_handle_mmap(dev, map);
        }
    }

    // Recursively execute the interval_handle() of the source prof_dev, including: flush, read, interval.
    for_each_source_dev_safe(source, next, dev)
        interval_handle(&source->timer);

    if (prof->read && dev->values) {
        struct perf_evsel *evsel;
        int cpu, ins, tins;
        perf_cpu_map__for_each_cpu(cpu, ins, cpus) {
            for (tins = 0; tins < perf_thread_map__nr(threads); tins++) {
                perf_evlist__for_each_evsel(evlist, evsel) {
                    struct perf_counts_values *count = dev->values;
                    struct perf_cpu_map *evsel_cpus = perf_evsel__cpus(evsel);

                    if (unlikely(evsel_cpus != cpus) &&
                        perf_cpu_map__idx(evsel_cpus, cpu) < 0) {
                        continue;
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
}

struct prof_dev *prof_dev_open_cpu_thread_map(profiler *prof, struct env *env,
                 struct perf_cpu_map *cpu_map, struct perf_thread_map *thread_map, struct prof_dev *parent)
{
    struct perf_evlist *evlist = NULL;
    struct perf_cpu_map *cpus = NULL, *online;
    struct perf_thread_map *threads = NULL;
    struct prof_dev *dev;
    int reinit = 0;
    int err = 0;

    dev = malloc(sizeof(*dev));
    if (!dev)
        goto out_free;

    memset(dev, 0, sizeof(*dev));
    dev->prof = prof;
    dev->env = env;
    INIT_LIST_HEAD(&dev->dev_link);
    dev->type = PROF_DEV_TYPE_NORMAL;
    dev->state = parent ? PROF_DEV_STATE_OFF : PROF_DEV_STATE_INACTIVE;
    dev->print_title = true;
    INIT_LIST_HEAD(&dev->links.child_list);
    INIT_LIST_HEAD(&dev->links.link_to_parent);
    INIT_LIST_HEAD(&dev->forward.source_list);
    INIT_LIST_HEAD(&dev->forward.link_to_target);

    // workload output to stdout & stderr
    // perf-prof output to env.output file
    // TODO per prof_dev output
    if (env->output) {
        if (!freopen(env->output, "a", stdout))
            goto out_free;
        dup2(STDOUT_FILENO, STDERR_FILENO);
        setlinebuf(stdin);
        setlinebuf(stdout);
        setlinebuf(stderr);
    }

    if (env->order || prof->order) {
        order(dev);
        prof = dev->prof;
    }

    dev->pages = prof->pages;
    if (env->mmap_pages)
        dev->pages = env->mmap_pages;

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

    if (cpu_map || thread_map) {
        cpus = cpu_map ? perf_cpu_map__get(cpu_map) : perf_cpu_map__dummy_new();
        threads = thread_map ? perf_thread_map__get(thread_map) : perf_thread_map__new_dummy();
    } else if (env->pids || env->tids) {
        // attach to processes
        threads = thread_map__new_str(env->pids, env->tids, 0, 0);
        cpus = env->inherit ? perf_cpu_map__new(NULL) : perf_cpu_map__dummy_new();
        if (!threads || !cpus) {
            fprintf(stderr, "failed to create pids\n");
            goto out_delete;
        }
    } else if (env->workload.pid) {
        // attach to workload
        threads = thread_map__new_by_pid(env->workload.pid);
        cpus = env->inherit ? perf_cpu_map__new(NULL) : perf_cpu_map__dummy_new();
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
        if (err == -ESRCH && !env->cgroups && dev->threads != thread_map) {
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
    }

    if (dev->env->interval) {
        dev->max_read_size = perf_evlist__max_read_size(evlist);
        dev->values = zalloc(dev->max_read_size);
        if (!dev->values)
            goto out_close;

        err = timer_init(&dev->timer, interval_handle);
        if (err) {
            fprintf(stderr, "monitor(%s) timer init failed\n", prof->name);
            goto out_close;
        }
    }

    if (dev->state == PROF_DEV_STATE_INACTIVE)
        if (prof_dev_enable(dev) < 0)
            goto out_disable;

    if (parent) {
        dev->links.parent = parent;
        list_add_tail(&dev->links.link_to_parent, &parent->links.child_list);
    }
    list_add(&dev->dev_link, &prof_dev_list);

    return dev;

out_disable:
    if (dev->env->interval)
        timer_destroy(&dev->timer);

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
    if (dev) free(dev);

    return NULL;
}

struct prof_dev *prof_dev_open(profiler *prof, struct env *env)
{
    return prof_dev_open_cpu_thread_map(prof, env, NULL, NULL, NULL);
}

static int prof_dev_atomic_enable(struct prof_dev *dev, u64 enable_cost)
{
    struct perf_evlist *evlist = dev->evlist;
    struct perf_mmap *map;
    union perf_event *event;
    bool writable = false;
    u64 enabled_after_ns;

    if (prof_dev_nr_ins(dev) <= 1)
        return 0;

    if (dev->env->overwrite)
        return -1;

    if (!(dev->time_ctx.sample_type & PERF_SAMPLE_TIME))
        return -1;

    perf_evlist__for_each_mmap(evlist, map, dev->env->overwrite) {
        if (perf_mmap__read_init(map) < 0)
            continue;

        while ((event = perf_mmap__read_event(map, &writable)) != NULL) {
            perf_mmap__consume(map);
            enabled_after_ns = enable_cost + *(u64 *)((void *)event->sample.array + dev->time_ctx.time_pos);
            goto enabled_after;
        }
        if (!event)
            perf_mmap__read_done(map);
    }
    return 0;

enabled_after:
    /*
     * Start sampling after the events is fully enabled.
     *
     * -e sched:sched_wakeup -e sched:sched_switch -C 0-95
     * A sched_wakeup occurs on CPU0, possibly sched_switch occurs on CPU95. When enabling, CPU0 is
     * enabled first, and CPU95 is enabled last. It is possible that the sched_wakeup event is only
     * sampled on CPU0, and the sched_switch event is not sampled on CPU95.
     *
     * Events after `enabled_after_ns' are safe and there is no enablement loss.
    **/
    perf_event_convert_read_tsc_conversion(dev, map);
    dev->time_ctx.enabled_after = perf_time_to_tsc(dev, enabled_after_ns);
    if (dev->env->verbose) {
        printf("%s: enabled after %lu.%06lu\n", dev->prof->name, dev->time_ctx.enabled_after/NSEC_PER_SEC,
                    (dev->time_ctx.enabled_after%NSEC_PER_SEC)/1000);
    }
    return 0;
}

int prof_dev_enable(struct prof_dev *dev)
{
    profiler *prof;
    struct env *env;
    struct perf_evlist *evlist;
    struct prof_dev *child;
    struct timespec before_enable, after_enable;
    u64 enable_cost;
    int err;

    if (!dev || dev->state == PROF_DEV_STATE_ACTIVE)
        return 0;

    prof = dev->prof;
    env = dev->env;
    evlist = dev->evlist;

    perf_timespec_init(dev);

    err = perf_evlist_poll__foreach_fd(evlist, __addfn);
    if (err) {
        fprintf(stderr, "monitor(%s) poll failed\n", prof->name);
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &before_enable);
    perf_evlist__enable(evlist);
    clock_gettime(CLOCK_MONOTONIC, &after_enable);

    enable_cost = (after_enable.tv_sec - before_enable.tv_sec) * NSEC_PER_SEC +
                  (after_enable.tv_nsec - before_enable.tv_nsec);
    prof_dev_atomic_enable(dev, enable_cost);

    if (prof->enabled)
        prof->enabled(dev);

    if (env->interval)
        timer_start(&dev->timer, env->interval * 1000000UL, false);

    // Enable child dev before workload_start().
    for_each_child_dev(child, dev)
        prof_dev_enable(child);

    workload_start(&env->workload);

    dev->state = PROF_DEV_STATE_ACTIVE;
    if (dev->type == PROF_DEV_TYPE_NORMAL)
        running ++;

    return 0;
}

int prof_dev_disable(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct prof_dev *child;

    for_each_child_dev(child, dev)
        prof_dev_disable(child);

    if (dev->state < PROF_DEV_STATE_ACTIVE)
        return 0;

    dev->state = PROF_DEV_STATE_INACTIVE;
    if (dev->type == PROF_DEV_TYPE_NORMAL)
        running --;

    /*
     * Flush remaining perf events.
     */
    if (dev->pages && prof_dev_is_final(dev)) {
        // The forwarding source will also be refreshed.
        prof_dev_flush(dev);
    }

    // Disable subsequent interval_handle() calls.
    if (dev->env->interval)
        timer_cancel(&dev->timer);

    perf_evlist__disable(evlist);

    // Disable subsequent perf_event_handle() calls.
    if (dev->pages)
        perf_evlist_poll__foreach_fd(evlist, __delfn);

    return 0;
}

int prof_dev_forward(struct prof_dev *dev, struct prof_dev *target)
{
    if (perf_sample_forward_init(dev) == 0) {
        if (using_order(target) && perf_sample_time_init(target) == 0 &&
            target->time_ctx.time_pos != dev->forward.forwarded_time_pos) {
            fprintf(stderr, "%s cannot forward to %s: time_pos is different.\n", dev->prof->name, target->prof->name);
            return -1;
        }
        dev->forward.event_dev = malloc(PERF_SAMPLE_MAX_SIZE);
        if (dev->forward.event_dev) {
            dev->forward.target = target;
            list_add_tail(&dev->forward.link_to_target, &target->forward.source_list);
            if (using_order(target))
                ordered_events(dev);
            /*
             * Like this command:
             *   perf-prof multi-trace -e XX:YYY -e XX:ZZZ,task-state//untraced/ -p 1234 --order \
             *             --than 10ms --detail=sametid
             *
             * multi-trace is attached to pid 1234, task-state is also attached to pid 1234, but
             * internally it switches to the cpu.
             *
             * In this scenario, forwarding will reset the instance. Task-state events are forwarded
             * to multi-trace, but the instance seen is 0.
             */
            if (prof_dev_ins_oncpu(dev) != prof_dev_ins_oncpu(target) ||
                prof_dev_nr_ins(dev) != prof_dev_nr_ins(target)) {
                dev->forward.ins_reset = true;
                printf("%s events are forwarded to %s, reset instance.\n", dev->prof->name, target->prof->name);
            }
            return 0;
        }
    }
    return -1;
}

void prof_dev_flush(struct prof_dev *dev)
{
    struct prof_dev *source, *next;

    if (dev->pages) {
        struct perf_evlist *evlist = dev->evlist;
        struct perf_mmap *map;
        perf_evlist__for_each_mmap(evlist, map, dev->env->overwrite) {
            perf_event_handle_mmap(dev, map);
        }
    }

    // Recursively flush the source prof_dev.
    for_each_source_dev_safe(source, next, dev)
        prof_dev_flush(source);
}

void prof_dev_close(struct prof_dev *dev)
{
    profiler *prof = dev->prof;
    struct perf_evlist *evlist = dev->evlist;

    list_del(&dev->dev_link);

    prof_dev_disable(dev);

    if (dev->env->interval) {
        timer_destroy(&dev->timer);
        if (dev->values)
            free(dev->values);
    }

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

    if (dev->pages)
        perf_evlist__munmap(evlist);

    perf_evlist__close(evlist);

    perf_evlist__set_maps(evlist, NULL, NULL);
    perf_evlist__delete(evlist);
    perf_cpu_map__put(dev->cpus);
    perf_thread_map__put(dev->threads);

    if (dev->env->cgroups)
        cgroup_list__delete();

    list_del(&dev->links.link_to_parent);
    if (dev->forward.target) {
        free(dev->forward.event_dev);
        list_del(&dev->forward.link_to_target);
    }

    free_env(dev->env);
    free(dev);
}

void prof_dev_print_time(struct prof_dev *dev, u64 evtime, FILE *fp)
{
    s64 off_ns;
    char timebuff[64];
    struct timeval tv;
    struct tm *result;

    if (likely(dev->time_ctx.base_evtime > 0 && evtime > 0)) {
        if (likely(!dev->convert.need_tsc_conv))
            off_ns = evtime - dev->time_ctx.base_evtime;
        else
            off_ns = perf_time_to_ns(dev, evtime) - perf_time_to_ns(dev, dev->time_ctx.base_evtime);
        off_ns += dev->time_ctx.base_timespec.tv_nsec;

        tv.tv_sec = dev->time_ctx.base_timespec.tv_sec + off_ns / NSEC_PER_SEC;
        tv.tv_usec = (off_ns % NSEC_PER_SEC) / 1000;
    } else
        gettimeofday(&tv, NULL);

    result = localtime(&tv.tv_sec);
    strftime(timebuff, sizeof(timebuff), "%Y-%m-%d %H:%M:%S", result);
    fprintf(fp, "%s.%06u ", timebuff, (unsigned int)tv.tv_usec);
}

static u64 prof_dev_minevtime(struct prof_dev *dev)
{
    u64 minevtime = ULLONG_MAX;

    /*
     * The minimum event time is taken from the ringbuffer, order buffer, and profiler.
     */

    // profiler
    if (dev->prof->minevtime)
        minevtime = dev->prof->minevtime(dev);

    // order buffer
    if (using_order(dev))
        minevtime = min(dev->order.oe.last_flush, minevtime); // maybe 0

    // ringbuffer
    // The minevtime of profiler and order must be smaller than that of ringbuffer.
    // Therefore, ringbuffer is judged only when minevtime == ULLONG_MAX.
    if (minevtime == ULLONG_MAX &&
        dev->pages && !dev->env->overwrite) {
        struct perf_evlist *evlist = dev->evlist;
        struct perf_mmap *map;

        perf_evlist__for_each_mmap(evlist, map, dev->env->overwrite) {
            union perf_event *event;
            bool writable = false;
            int idx = perf_mmap__idx(map);

            if (perf_mmap__read_init(map) < 0)
                continue;

            perf_event_convert_read_tsc_conversion(dev, map);
            while ((event = perf_mmap__read_event(map, &writable)) != NULL) {
                /* process event */
                perf_event_process_record(dev, event, idx, writable, false);
                perf_mmap__consume(map);
                if (event->header.type == PERF_RECORD_SAMPLE) {
                    u64 last_evtime;

                    if (dev->forward.target) // last_evtime is stored on the target prof_dev.
                        last_evtime = dev->forward.target->time_ctx.last_evtime;
                    else
                        last_evtime = dev->time_ctx.last_evtime;

                    if (last_evtime < minevtime)
                        minevtime = last_evtime;
                    break;
                }
            }
            if (!event)
                perf_mmap__read_done(map);
        }
    }

    // ULLONG_MAX and 0 are special values, not tsc, and cannot be converted to ns.
    if (minevtime == ULLONG_MAX || minevtime == 0)
        return minevtime;
    else
        return perf_time_to_ns(dev, minevtime);
}

u64 prof_dev_list_minevtime(void)
{
    u64 minevtime = ULLONG_MAX;
    u64 time;
    struct prof_dev *dev, *next;

    list_for_each_entry_safe(dev, next, &prof_dev_list, dev_link) {
        if (dev->type != PROF_DEV_TYPE_NORMAL)
            continue;
        time = prof_dev_minevtime(dev);
        if (time < minevtime)
            minevtime = time;
    }
    return minevtime;
}

static void prof_dev_list_close(void)
{
    struct prof_dev *dev;

restart:
    list_for_each_entry(dev, &prof_dev_list, dev_link) {
        prof_dev_close(dev);
        // May also close other prof_dev.
        goto restart;
    }
}

static void print_marker_and_interval(int fd, unsigned int revents, void *ptr)
{
    char buf[512];

    if (revents & EPOLLIN) {
        char *line = fgets(buf, sizeof(buf), stdin);
        if (line) {
            struct prof_dev *dev, *next;
            list_for_each_entry_safe(dev, next, &prof_dev_list, dev_link)
                if (prof_dev_is_final(dev))
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
    bool usage_self_start = false;
    profiler *main_prof = NULL;
    struct env *main_env = NULL;

    sigusr2_handler(0);

    libperf_init(libperf_print);

    main_epoll = event_poll__alloc(64);
    if (!main_epoll) {
        return -1;
    }

    main_prof = parse_main_options(argc, argv);
    if (!main_prof) return err;
    main_env = zalloc(sizeof(*main_env));
    if (!main_env) return err;
    *main_env = env;

    if (epoll_wait_signal(SIGCHLD, SIGINT, SIGTERM, SIGUSR1, SIGUSR2, SIGWINCH, 0) < 0)
        return -1;
    if (!isatty(STDIN_FILENO))
        main_epoll_add(STDIN_FILENO, EPOLLIN, NULL, print_marker_and_interval);
    if (env.usage_self) {
        timer_init(&usage_self, usage_self_handle);
        timer_start(&usage_self, env.usage_self * 1000000UL, false);
        usage_self_start = true;
    }

    if (!prof_dev_open(main_prof, main_env))
        return -1;

    while (running) {
        int fds = event_poll__poll(main_epoll, -1);

        // -ENOENT means there are no file descriptors in event_poll.
        if (fds == -ENOENT)
            running = 0;
    }
    err = 0;

    prof_dev_list_close();

    if (usage_self_start)
        timer_destroy(&usage_self);
    if (!isatty(STDIN_FILENO))
        main_epoll_del(STDIN_FILENO);

    return err;
}

