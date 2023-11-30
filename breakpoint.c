#include <stdlib.h>
#include <pthread.h>
#include <linux/bitops.h>
#include <asm/perf_regs.h>
#include <linux/hw_breakpoint.h>
#include <monitor.h>
#include <stack_helpers.h>
#include <trace_helpers.h>

#if defined(__i386__) || defined(__x86_64__)
#define REG_NOSUPPORT_N 4
#define REG_NOSUPPORT ((1ULL << PERF_REG_X86_DS) | \
		       (1ULL << PERF_REG_X86_ES) | \
		       (1ULL << PERF_REG_X86_FS) | \
		       (1ULL << PERF_REG_X86_GS))
#if defined(__i386__)
#define PERF_REGS_MASK (((1ULL << PERF_REG_X86_32_MAX) - 1) & ~REG_NOSUPPORT)
#else
#define PERF_REGS_MASK (((1ULL << PERF_REG_X86_64_MAX) - 1) & ~REG_NOSUPPORT)
#endif
#elif defined(__aarch64__)
#define PERF_REGS_MASK ((1ULL << PERF_REG_ARM64_MAX) - 1)
#endif


#define HBP_NUM 4

static profiler breakpoint;

struct hw_breakpoint {
    unsigned long address;
    u8 len;
    u8 type;
    char typestr[4];
};

static struct hw_breakpoint hwbp[HBP_NUM];
struct breakpoint_ctx {
    struct hw_breakpoint hwbp[HBP_NUM];
    struct callchain_ctx *cc;
    struct flame_graph *flame;
};

static int monitor_ctx_init(struct prof_dev *dev)
{
    int i;
    struct env *env = dev->env;
    struct breakpoint_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    for (i = 0; i < HBP_NUM; i++)
        ctx->hwbp[i] = hwbp[i];

    if (env->callchain) {
        if (!env->flame_graph)
            ctx->cc = callchain_ctx_new(callchain_flags(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER), stdout);
        else
            ctx->flame = flame_graph_open(callchain_flags(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER), env->flame_graph);
        dev->pages *= 2;
    }

    return 0;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct breakpoint_ctx *ctx = dev->private;
    if (dev->env->callchain) {
        if (!dev->env->flame_graph)
            callchain_ctx_free(ctx->cc);
        else {
            flame_graph_output(ctx->flame);
            flame_graph_close(ctx->flame);
        }
    }
    free(ctx);
}

static int breakpoint_argc_init(int argc, char *argv[])
{
    int i, j;

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

        hwbp[i].address = value;
        hwbp[i].len = len;
        hwbp[i].type = type;
        j = 0;
        if (type & HW_BREAKPOINT_R) hwbp[i].typestr[j++] = 'R';
        if (type & HW_BREAKPOINT_W) hwbp[i].typestr[j++] = 'W';
        if (type & HW_BREAKPOINT_X) hwbp[i].typestr[j++] = 'X';
        hwbp[i].typestr[j] = '\0';

        free(s);
    }

    return 0;
}

static int breakpoint_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
    struct breakpoint_ctx *ctx;
    struct perf_event_attr attr = {
        .type        = PERF_TYPE_BREAKPOINT,
        .config      = 0,
        .size        = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU |
                       (env->callchain ? PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_INTR : 0),
        .read_format = 0,
        .sample_regs_intr = PERF_REGS_MASK,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = exclude_callchain_user(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .exclude_callchain_kernel = exclude_callchain_kernel(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int i;

    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;

    reduce_wakeup_times(dev, &attr);

    for (i = 0; i < HBP_NUM; i++) {
        if (ctx->hwbp[i].address) {
            if (env->verbose)
                printf("%p len %d type %d\n", (void *)ctx->hwbp[i].address, ctx->hwbp[i].len, ctx->hwbp[i].type);

            attr.bp_addr = ctx->hwbp[i].address;
            attr.bp_type = ctx->hwbp[i].type;
            attr.bp_len = ctx->hwbp[i].len;

            evsel = perf_evsel__new(&attr);
            if (!evsel)
                goto failed;

            perf_evlist__add(evlist, evsel);
        } else
            break;
    }
    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static void breakpoint_deinit(struct prof_dev *dev)
{
    monitor_ctx_exit(dev);
}

struct sample_regs_intr {
    u64     abi;
    u64     regs[hweight64(PERF_REGS_MASK)];
};

static void print_regs_intr(struct sample_regs_intr *regs_intr, u64 unused)
{
#if defined(__i386__) || defined(__x86_64__)
#define REG(r) regs_intr->regs[PERF_REG_X86_##r - (PERF_REG_X86_##r > PERF_REG_X86_DS ? REG_NOSUPPORT_N : 0)]
    printf("      RIP: %016lx RSP: %016lx RFLAGS:%08lx\n", REG(IP), REG(SP), REG(FLAGS));
    printf("      RAX: %016lx RBX: %016lx RCX: %016lx\n", REG(AX), REG(BX), REG(CX));
    printf("      RDX: %016lx RSI: %016lx RDI: %016lx\n", REG(DX), REG(SI), REG(DI));

#if defined(__i386__)
    printf("      RBP: %016lx CS: %04lx SS: %04lx\n", REG(BP), REG(CS), REG(SS));
#else
    printf("      RBP: %016lx R08: %016lx R09: %016lx\n", REG(BP), REG(R8), REG(R9));
    printf("      R10: %016lx R11: %016lx R12: %016lx\n", REG(R10), REG(R11), REG(R12));
    printf("      R13: %016lx R14: %016lx R15: %016lx\n", REG(R13), REG(R14), REG(R15));
    printf("      CS: %04lx SS: %04lx\n", REG(CS), REG(SS));
#endif

#elif defined(__aarch64__)
#define REG(r) regs_intr->regs[PERF_REG_ARM64_##r]
    printf("      X00: %016lx X01: %016lx X02: %016lx X03: %016lx\n", REG(X0), REG(X1), REG(X2), REG(X3));
    printf("      X04: %016lx X05: %016lx X06: %016lx X07: %016lx\n", REG(X4), REG(X5), REG(X6), REG(X7));
    printf("      X08: %016lx X09: %016lx X10: %016lx X11: %016lx\n", REG(X8), REG(X9), REG(X10), REG(X11));
    printf("      X12: %016lx X13: %016lx X14: %016lx X15: %016lx\n", REG(X12), REG(X13), REG(X14), REG(X15));
    printf("      X16: %016lx X17: %016lx X18: %016lx X19: %016lx\n", REG(X16), REG(X17), REG(X18), REG(X19));
    printf("      X20: %016lx X21: %016lx X22: %016lx X23: %016lx\n", REG(X20), REG(X21), REG(X22), REG(X23));
    printf("      X24: %016lx X25: %016lx X26: %016lx X27: %016lx\n", REG(X24), REG(X25), REG(X26), REG(X27));
    printf("      X28: %016lx X29: %016lx LR: %016lx\n", REG(X28), REG(X29), REG(LR));
    printf("      SP: %016lx PC: %016lx\n", REG(SP), REG(PC));
#endif
}

static void breakpoint_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct breakpoint_ctx *ctx = dev->private;
    // in linux/perf_event.h
    // PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU | PERF_SAMPLE_CALLCHAIN |
    // PERF_SAMPLE_REGS_INTR
    struct sample_type_data {
        __u64   ip;
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
    struct sample_regs_intr *regs_intr;
    int i;

    for (i = 0; i < HBP_NUM; i++) {
        if (ctx->hwbp[i].address == data->addr)
            break;
    }

    if (dev->print_title) print_time(stdout);
    printf("    pid %6d tid %6d [%03d] %llu.%06llu: breakpoint: 0x%llx/%d:%s ip 0x%llx\n", data->tid_entry.pid, data->tid_entry.tid,
            data->cpu_entry.cpu, data->time/NSEC_PER_SEC, (data->time%NSEC_PER_SEC)/1000,
            data->addr, ctx->hwbp[i].len, ctx->hwbp[i].typestr, data->ip);

    if (dev->env->callchain) {
        regs_intr = (struct sample_regs_intr *)&data->callchain.ips[data->callchain.nr];
        if (!dev->env->flame_graph)
            print_callchain_common_cbs(ctx->cc, &data->callchain, data->tid_entry.pid, (callchain_cbs)print_regs_intr, NULL, regs_intr);
        else
            flame_graph_add_callchain(ctx->flame, &data->callchain, data->tid_entry.pid, NULL);
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
    PROFILER_ARGV_CALLCHAIN_FILTER,
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

