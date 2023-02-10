#include <stdlib.h>
#include <pthread.h>
#include <linux/hw_breakpoint.h>
#include <monitor.h>
#include <stack_helpers.h>
#include <trace_helpers.h>


#define HBP_NUM 4

static profiler breakpoint;

struct hw_breakpoint {
    unsigned long address;
    u8 len;
    u8 type;
};

static struct breakpoint_ctx {
    struct hw_breakpoint hwbp[HBP_NUM];
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    struct env *env;
} ctx;

static int monitor_ctx_init(struct env *env)
{
    if (env->callchain) {
        if (!env->flame_graph)
            ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL | CALLCHAIN_USER, stdout);
        else
            ctx.flame = flame_graph_open(CALLCHAIN_KERNEL | CALLCHAIN_USER, env->flame_graph);
        breakpoint.pages *= 2;
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    if (ctx.env->callchain) {
        if (!ctx.env->flame_graph)
            callchain_ctx_free(ctx.cc);
        else {
            flame_graph_output(ctx.flame);
            flame_graph_close(ctx.flame);
        }
    }
}

static int breakpoint_argc_init(int argc, char *argv[])
{
    int i;

    if (argc < 1) {
        fprintf(stderr, " <addr> needs to be specified.\n");
        help();
    }
    if (argc > HBP_NUM) {
        fprintf(stderr, " Up to %d breakpoints are supported.\n", HBP_NUM);
        help();
    }

    for (i = 0; i < argc; i++) {
        char *p, *s = strdup(argv[i]);
        int tk = *s;
        unsigned long value = tk - '0';
        u8 len = 1;
        u8 type = HW_BREAKPOINT_W;

        p = s + 1;
        if (value) {
            while (*p >= '0' && *p <= '9') value = value * 10 + *p++ - '0';
        } else if (*p == 'x' || *p == 'X') {
            while ((tk = *++p) && ((tk >= '0' && tk <= '9') || (tk >= 'a' && tk <= 'f') || (tk >= 'A' && tk <= 'F')))
                value = value * 16 + (tk & 15) + (tk >= 'A' ? 9 : 0);
        } else {
            fprintf(stderr, " <addr> is not decimal or hexadecimal.");
            help();
        }

        if (*p == '/') {
            ++p;
            if (*p >= '0' && *p <= '9')
                len = *p++ - '0';
        }
        if (*p == ':') {
            ++p;
            if (*p) type = 0;
            while (*p) {
                if (*p == 'r') type |=  HW_BREAKPOINT_R;
                else if (*p == 'w') type |= HW_BREAKPOINT_W;
                else if (*p == 'x') type |= HW_BREAKPOINT_X;
                else break;
                p++;
            }
        }
        if (*p) {
            fprintf(stderr, " <addr> parsing error.");
            help();
        }

        if (type & HW_BREAKPOINT_R)
            type |= HW_BREAKPOINT_W;

        if (type & HW_BREAKPOINT_X) {
            len = sizeof(long);
            type = HW_BREAKPOINT_X;
        }

        ctx.hwbp[i].address = value;
        ctx.hwbp[i].len = len;
        ctx.hwbp[i].type = type;

        free(s);
    }

    return 0;
}

static int breakpoint_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type        = PERF_TYPE_BREAKPOINT,
        .config      = 0,
        .size        = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU |
                       (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format = 0,
        .pinned        = 1,
        .disabled      = 1,
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int i;

    if (monitor_ctx_init(env) < 0)
        return -1;

    reduce_wakeup_times(&breakpoint, &attr);

    for (i = 0; i < HBP_NUM; i++) {
        if (ctx.hwbp[i].address) {
            if (env->verbose)
                printf("%p len %d type %d\n", (void *)ctx.hwbp[i].address, ctx.hwbp[i].len, ctx.hwbp[i].type);

            attr.bp_addr = ctx.hwbp[i].address;
            attr.bp_type = ctx.hwbp[i].type;
            attr.bp_len = ctx.hwbp[i].len;

            evsel = perf_evsel__new(&attr);
            if (!evsel)
                return -1;

            perf_evlist__add(evlist, evsel);
        } else
            break;
    }
    return 0;
}

static void breakpoint_deinit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void breakpoint_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU | PERF_SAMPLE_CALLCHAIN
    struct sample_type_data {
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        __u64   time;
        __u64   addr;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        struct callchain callchain;
    } *data = (void *)event->sample.array;

    print_time(stdout);
    printf(" pid %6d [%03d] %llu.%06llu: addr 0x%llx\n", data->tid_entry.pid, data->cpu_entry.cpu,
            data->time/NSEC_PER_SEC, (data->time%NSEC_PER_SEC)/1000, data->addr);
    if (ctx.env->callchain) {
        if (!ctx.env->flame_graph)
            print_callchain_common(ctx.cc, &data->callchain, data->tid_entry.pid);
        else
            flame_graph_add_callchain(ctx.flame, &data->callchain, data->tid_entry.pid, NULL);
    }
}

static const char *breakpoint_desc[] = PROFILER_DESC("breakpoint",
    "[OPTION...] [-g [--flame-graph file]] <addr>[/1/2/4/8][:rwx] ...",
    "Kernel/user-space hardware breakpoint facility.",
    "",
    "SYNOPSIS",
    "    HW_breakpoint: a unified kernel/user-space hardware breakpoint facility",
    "    using the CPU's debug registers.",
    "",
    "    Each process has a maximum of 4 breakpoints.",
    "",
    "EXAMPLES",
    "    "PROGRAME" breakpoint 0x7ffd8c7dae28 -g",
    "    "PROGRAME" breakpoint 0x7ffd8c7dae28/8:w");
static const char *breakpoint_argv[] = PROFILER_ARGV("breakpoint",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "call-graph", "flame-graph");
static profiler breakpoint = {
    .name = "breakpoint",
    .desc = breakpoint_desc,
    .argv = breakpoint_argv,
    .pages = 1,
    .argc_init = breakpoint_argc_init,
    .init = breakpoint_init,
    .deinit = breakpoint_deinit,
    .sample = breakpoint_sample,
};
PROFILER_REGISTER(breakpoint)

