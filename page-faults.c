#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/perf_regs.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>

#define REG_NOSUPPORT_N 4
#define REG_NOSUPPORT ((1ULL << PERF_REG_X86_DS) | \
		       (1ULL << PERF_REG_X86_ES) | \
		       (1ULL << PERF_REG_X86_FS) | \
		       (1ULL << PERF_REG_X86_GS))
#define PERF_REGS_MASK (((1ULL << PERF_REG_X86_64_MAX) - 1) & ~REG_NOSUPPORT)

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
        ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL | CALLCHAIN_USER, stdout);
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
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;

    if (monitor_ctx_init(env) < 0)
        return -1;

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
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
    u64     regs[PERF_REG_X86_64_MAX];
};

static void print_regs_user(struct sample_regs_user *regs_user, u64 unused)
{
#define REG(r) regs_user->regs[PERF_REG_X86_##r - (PERF_REG_X86_##r > PERF_REG_X86_DS ? REG_NOSUPPORT_N : 0)]
    printf("      RIP: %016lx RSP: %016lx RFLAGS:%08lx\n", REG(IP), REG(SP), REG(FLAGS));
    printf("      RAX: %016lx RBX: %016lx RCX: %016lx\n", REG(AX), REG(BX), REG(CX));
    printf("      RDX: %016lx RSI: %016lx RDI: %016lx\n", REG(DX), REG(SI), REG(DI));
    printf("      RBP: %016lx R08: %016lx R09: %016lx\n", REG(BP), REG(R8), REG(R9));
    printf("      R10: %016lx R11: %016lx R12: %016lx\n", REG(R10), REG(R11), REG(R12));
    printf("      R13: %016lx R14: %016lx R15: %016lx\n", REG(R13), REG(R14), REG(R15));
    printf("      CS: %04lx SS: %04lx\n", REG(CS), REG(SS));
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

static profiler page_faults = {
    .name = "page-faults",
    .pages = 2,
    .init = page_faults_init,
    .deinit = page_faults_exit,
    .sample = page_faults_sample,
};
PROFILER_REGISTER(page_faults)


