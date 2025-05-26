#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <monitor.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
#include <latency_helpers.h>
#include <bpf-skel/kvm_exit.h>
#include <bpf-skel/kvm_exit.skel.h>
#include <internal/xyarray.h>
#include <internal/evsel.h>


struct kvmexit_ctx {
    struct kvm_exit_bpf *obj;
    struct perf_evsel *evsel;
    struct comm_notify notify;
    struct latency_dist *lat_dist;
    struct perf_thread_map *thread_map;
    bool print_header;
    bool oncpu;
};

static int comm_notify(struct comm_notify *notify, int pid, int state, u64 free_time)
{
    if (state == NOTIFY_COMM_DELETE) {
        struct kvmexit_ctx *ctx = container_of(notify, struct kvmexit_ctx, notify);
        bpf_map__delete_elem(ctx->obj->maps.kvm_vcpu, &pid, sizeof(pid), 0);
    }
    return 0;
}

static int monitor_ctx_init(struct prof_dev *dev)
{
    struct env *env = dev->env;
    struct kvmexit_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    if (prof_dev_ins_oncpu(dev))
        ctx->oncpu = 1;

    ctx->obj = kvm_exit_bpf__open();
    if (!ctx->obj)
        goto free_ctx;

    if (global_comm_ref() < 0)
        goto destroy;

    ctx->lat_dist = latency_dist_new_quantile(env->perins, true, 0);
    if (!ctx->lat_dist)
        goto unref;

    ctx->notify.notify = comm_notify;
    global_comm_register_notify(&ctx->notify);
    return 0;

unref:
    global_comm_unref();
destroy:
    kvm_exit_bpf__destroy(ctx->obj);
free_ctx:
    free(ctx);
    return -1;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct kvmexit_ctx *ctx = dev->private;
    perf_thread_map__put(ctx->thread_map);
    global_comm_unregister_notify(&ctx->notify);
    latency_dist_free(ctx->lat_dist);
    global_comm_unref();
    kvm_exit_bpf__destroy(ctx->obj);
    free(ctx);
}

static int get_tgid(int tid)
{
    char path[256], line[256];
    FILE *fp;
    int pid = 0;

    // Read /proc/pid/status, get Tgid.
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "Tgid: %d", &pid) == 1)
            break;
        pid = 0;
    }
    fclose(fp);

    return pid;
}

static int bpf_kvm_exit_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct kvmexit_ctx *ctx;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_BPF_OUTPUT,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TIME | PERF_SAMPLE_RAW,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
        .wakeup_watermark = (dev->pages << 12) / 3,
    };
    int cpu, ins, i, tid;

    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;

    prof_dev_env2attr(dev, &attr);

    ctx->evsel = perf_evsel__new(&attr);
    if (!ctx->evsel)
        goto failed;
    perf_evlist__add(evlist, ctx->evsel);

    if (ctx->oncpu) {
        perf_cpu_map__for_each_cpu(cpu, ins, dev->cpus)
            ctx->obj->bss->work_cpus[cpu] = 1;
        for (i = 0; i < ARRAY_SIZE(ctx->obj->bss->percpu_event); i++)
            ctx->obj->bss->percpu_event[i].latency = INT64_MAX;

        bpf_program__set_autoload(ctx->obj->progs.kvm_exit_pid, 0);
        bpf_program__set_autoload(ctx->obj->progs.kvm_entry_pid, 0);
    } else {
        // can only be bound to cpu
        ctx->thread_map = dev->threads;
        perf_cpu_map__put(dev->cpus);
        dev->cpus = perf_cpu_map__new(NULL);
        dev->threads = perf_thread_map__new_dummy();

        tid = perf_thread_map__pid(ctx->thread_map, 0);
        ctx->obj->rodata->filter_pid = get_tgid(tid);

        bpf_program__set_autoload(ctx->obj->progs.kvm_exit, 0);
        bpf_program__set_autoload(ctx->obj->progs.kvm_entry, 0);
        bpf_program__set_autoload(ctx->obj->progs.sched_switch, 0);
    }

    ctx->obj->rodata->filter_latency = dev->env->threshold ? : 1000000 /* 1ms */;
    if (kvm_exit_bpf__load(ctx->obj))
        goto failed;

    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

#define FD(e, x, y) ((int *) xyarray__entry(e->fd, x, y))
static int bpf_kvm_exit_filter(struct prof_dev *dev)
{
    struct kvmexit_ctx *ctx = dev->private;
    struct bpf_map *perf_events = ctx->obj->maps.perf_events;
    int cpu, ins, perf_event_fd;
    int err;

    perf_cpu_map__for_each_cpu(cpu, ins, dev->cpus) {
        perf_event_fd = *FD(ctx->evsel, ins, 0);
        err = bpf_map__update_elem(perf_events, &cpu, sizeof(cpu), &perf_event_fd, sizeof(perf_event_fd), 0);
        if (err)
            return -1;
    }
    return kvm_exit_bpf__attach(ctx->obj);
}

static void print_latency_node(void *opaque, struct latency_node *node)
{
    struct prof_dev *dev = opaque;
    struct env *env = dev->env;
    struct kvmexit_ctx *ctx = dev->private;
    unsigned int exit_reason = node->key & 0xffffffff;
    u32 isa = node->key >> 32;
    double p99 = tdigest_quantile(node->td, 0.99);

    if (ctx->print_header) {
        ctx->print_header = false;
        print_time(stdout);
        printf("kvm-exit latency\n");

        if (env->perins)
            printf("[THREAD] ");
        printf("%-*s %8s %16s %12s %12s %12s %12s\n", isa == KVM_ISA_VMX ? 20 : 32, "exit_reason", "calls",
                 env->tsc ? "total(kcyc)" : "total(us)",
                 env->tsc ? "min(kcyc)" : "min(us)",
                 env->tsc ? "avg(kcyc)" : "avg(us)",
                 env->tsc ? "p99(kcyc)" : "p99(us)",
                 env->tsc ? "max(kcyc)" : "max(us)");

        if (env->perins)
            printf("-------- ");
        printf("%s %8s %16s %12s %12s %12s %12s\n", isa == KVM_ISA_VMX ? "--------------------" : "--------------------------------",
                "--------", "----------------", "------------", "------------", "------------", "------------");
    }
    if (env->perins)
        printf("[%6d] ", (int)node->instance);
    printf("%-*s %8lu %16.3f %12.3f %12.3f %12.3f %12.3f\n", isa == KVM_ISA_VMX ? 20 : 32,
            find_exit_reason(isa, exit_reason),
            node->n, node->sum/1000.0,
            node->min/1000.0, node->sum/node->n/1000.0, p99/1000.0, node->max/1000.0);
}

static void bpf_kvm_exit_interval(struct prof_dev *dev)
{
    struct kvmexit_ctx *ctx = dev->private;

    ctx->print_header = true;
    latency_dist_print_sorted(ctx->lat_dist, print_latency_node, dev);
    if (!ctx->print_header)
        printf("\n");
}

static void bpf_kvm_exit_deinit(struct prof_dev *dev)
{
    bpf_kvm_exit_interval(dev);
    monitor_ctx_exit(dev);
}

static void bpf_kvm_exit_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct kvmexit_ctx *ctx = dev->private;
    // in linux/perf_event.h
    // PERF_SAMPLE_TIME | PERF_SAMPLE_RAW
    struct kvm_vcpu_event *raw = (void *)event->sample.array + sizeof(u64) + sizeof(u32)/* u32 size; */;
    u64 *time = (void *)event->sample.array;
    u64 key = ((u64)raw->isa<<32) | raw->exit_reason;
    s64 delta = raw->latency;
    u32 hlt;

    if (unlikely(dev->env->verbose >= VERBOSE_EVENT))
        goto print_event;

    if (dev->env->greater_than && delta > dev->env->greater_than) {
        switch (raw->isa) {
            case KVM_ISA_VMX: hlt = EXIT_REASON_HLT; break;
            case KVM_ISA_SVM: hlt = SVM_EXIT_HLT; break;
            default: hlt = ARM_EXIT_HLT; break;
        }
        if (raw->exit_reason != hlt) {
        print_event:
            if (dev->print_title) prof_dev_print_time(dev, *time, stdout);
            printf("%16s %6u [%03d] %lu.%06lu: bpf:kvm-exit: %s lat %lu sched %lu\n", global_comm_get(raw->pid),
                raw->pid, prof_dev_ins_cpu(dev, instance), *time / NSEC_PER_SEC, (*time % NSEC_PER_SEC)/1000,
                find_exit_reason(raw->isa, raw->exit_reason), delta, ctx->oncpu ? raw->sched_latency : 0);
        }
    }
    latency_dist_input(ctx->lat_dist, dev->env->perins?raw->pid:0, key, delta>0?delta:0, 0);
}

static void bpf_kvm_exit_print_dev(struct prof_dev *dev, int indent)
{
    struct kvmexit_ctx *ctx = dev->private;
    int pid = 0;
    int n = 0;

    dev_printf("kvm_vcpu:\n");
    while (bpf_map__get_next_key(ctx->obj->maps.kvm_vcpu,
                pid == 0 ? NULL : &pid, &pid, sizeof(pid)) == 0) {
        dev_printf("%6u %s\n", pid, global_comm_get(pid));
        n++;
    }
}

static const char *bpf_kvm_exit_desc[] = PROFILER_DESC("bpf:kvm-exit",
    "[OPTION...] [--perins] [--than ns]",
    "Generate bpf:kvm-exit event.", "",
    "BPF-EVENT",
    "    u32 exit_reason   # exit reason",
    "    u64 latency       # kvm:kvm_exit => kvm:kvm_entry",
    "    u64 sched_latency # switch_out => switch_in", "",
    "EXAMPLES",
    "    "PROGRAME" bpf:kvm-exit -p 2347 -i 1000 --than 50ms",
    "    "PROGRAME" bpf:kvm-exit -C 1-4 -i 1000 --perins");
static const char *bpf_kvm_exit_argv[] = PROFILER_ARGV("bpf:kvm-exit",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "perins", "than", "threshold\nVmexit latency threshold, Dflt: 1ms");
struct monitor bpf_kvm_exit = {
    .name = "bpf:kvm-exit",
    .desc = bpf_kvm_exit_desc,
    .argv = bpf_kvm_exit_argv,
    .pages = 4,
    .init = bpf_kvm_exit_init,
    .filter = bpf_kvm_exit_filter,
    .deinit = bpf_kvm_exit_deinit,
    .interval = bpf_kvm_exit_interval,
    .sample = bpf_kvm_exit_sample,
    .print_dev = bpf_kvm_exit_print_dev,
};
MONITOR_REGISTER(bpf_kvm_exit)

