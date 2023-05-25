#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/perf_regs.h>
#include <linux/bitops.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>

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


static profiler page_faults;
static struct monitor_ctx {
    struct perf_evlist *evlist;
    struct callchain_ctx *cc;
    struct env *env;
} ctx;

static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    if (env->callchain) {
        ctx.cc = callchain_ctx_new(callchain_flags(CALLCHAIN_KERNEL | CALLCHAIN_USER), stdout);
        page_faults.pages *= 2;
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    if (ctx.env->callchain) {
        callchain_ctx_free(ctx.cc);
    }
    tep__unref();
}

static int page_faults_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_PAGE_FAULTS,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER : 0),
        .read_format   = 0,
        .sample_regs_user = PERF_REGS_MASK,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = exclude_callchain_user(CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .exclude_callchain_kernel = exclude_callchain_kernel(CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;

    if (monitor_ctx_init(env) < 0)
        return -1;

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        errno = ENOMEM;
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    ctx.evlist = evlist;
    return 0;
}

static void page_faults_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}



// in linux/perf_event.h
// PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU |
// PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER
struct sample_type_header {
    u64			ip;
    struct {
        u32    pid;
        u32    tid;
    }    tid_entry;
    u64   time;
    u64   addr;
    struct {
        u32    cpu;
        u32    reserved;
    }    cpu_entry;
    struct callchain callchain;
};

struct sample_regs_user {
    u64     abi;
    u64     regs[hweight64(PERF_REGS_MASK)];
};

static void print_regs_user(struct sample_regs_user *regs_user, u64 unused)
{
#if defined(__i386__) || defined(__x86_64__)
#define REG(r) regs_user->regs[PERF_REG_X86_##r - (PERF_REG_X86_##r > PERF_REG_X86_DS ? REG_NOSUPPORT_N : 0)]
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
#define REG(r) regs_user->regs[PERF_REG_ARM64_##r]
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

static void page_faults_sample(union perf_event *event, int instance)
{
    struct sample_type_header *data = (void *)event->sample.array;
    struct sample_regs_user *regs_user;
    bool callchain = ctx.env->callchain;

    print_time(stdout);
    tep__update_comm(NULL, data->tid_entry.tid);
    printf("%16s %6u [%03d] %llu.%06llu: page-fault addr %016lx\n", tep__pid_to_comm(data->tid_entry.tid), data->tid_entry.tid,
                    data->cpu_entry.cpu, data->time / NSEC_PER_SEC, (data->time % NSEC_PER_SEC)/1000, data->addr);

    if (callchain) {
        regs_user = (struct sample_regs_user *)&data->callchain.ips[data->callchain.nr];
        print_callchain_common_cbs(ctx.cc, &data->callchain, data->tid_entry.pid, NULL, (callchain_cbs)print_regs_user, regs_user);
    }
}

static const char *page_faults_desc[] = PROFILER_DESC("page-faults",
    "[OPTION...] [-g]",
    "Print the user mode regs and stack when a page fault occurs.", "",
    "EXAMPLES", "",
    "    "PROGRAME" page-faults -p 2347 -g",
    "    "PROGRAME" page-faults -C 0 -g");
static const char *page_faults_argv[] = PROFILER_ARGV("page-faults",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_CALLCHAIN_FILTER,
    PROFILER_ARGV_PROFILER, "call-graph");
static profiler page_faults = {
    .name = "page-faults",
    .desc = page_faults_desc,
    .argv = page_faults_argv,
    .pages = 2,
    .init = page_faults_init,
    .deinit = page_faults_exit,
    .sample = page_faults_sample,
};
PROFILER_REGISTER(page_faults)


