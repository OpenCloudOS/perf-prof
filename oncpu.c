#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/rblist.h>
#include <api/fs/fs.h>
#include <monitor.h>
#include <tep.h>

#define min(x, y) ({                \
    typeof(x) _min1 = (x);          \
    typeof(y) _min2 = (y);          \
    (void) (&_min1 == &_min2);      \
    _min1 < _min2 ? _min1 : _min2; })


static profiler oncpu;

struct runtime {
    struct rb_node rbn;
    int instance;
    union {
        int another;
        int cpu;
        int tid;
    };
    u64 runtime;
    char comm[16];
};

static struct oncpu_ctx {
    bool instance_oncpu;
    bool sched_stat_runtime_has_cpu;
    int nr_ins;
    int nr_cpus;
    struct rblist runtimes;
    int *percpu_thread_siblings;
    int *perins_vmf_sib;
    struct env *env;
} ctx;

struct sched_stat_runtime {
    unsigned short common_type; //       offset:0;       size:2; signed:0;
    unsigned char common_flags; //       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count; //       offset:3;       size:1; signed:0;
    int common_pid; //   offset:4;       size:4; signed:1;

    char comm[16];  //   offset:8;       size:16;        signed:1;
    pid_t pid;      //   offset:24;      size:4; signed:1;
    int cpu;        //   offset:28;      size:4; signed:1;
    u64 runtime;    //   offset:32;      size:8; signed:0;
    u64 vruntime;   //   offset:40;      size:8; signed:0;
};

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
struct sample_type_data {
    struct {
        u32    pid;
        u32    tid;
    }    tid_entry;
    struct {
        u32    cpu;
        u32    reserved;
    }    cpu_entry;
    u64       period;
    //PERF_SAMPLE_RAW
    struct {
        u32   size;
        union {
            __u8    data[0];
            struct sched_stat_runtime runtime;
        } __packed;
    } raw;
};

struct runtime_entry {
    int instance;
    union {
        int another;
        int cpu;
        int tid;
    };
};

static int runtime_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct runtime *run = rb_entry(rbn, struct runtime, rbn);
    const struct runtime_entry *e = entry;

    if (run->instance > e->instance)
        return 1;
    else if (run->instance < e->instance)
        return -1;

    if (run->another > e->another)
        return 1;
    else if (run->another < e->another)
        return -1;

    return 0;
}

static int runtime_instance_cmp(const void *entry, const struct rb_node *rbn)
{
    const struct runtime_entry *e = entry;
    struct runtime *run = rb_entry(rbn, struct runtime, rbn);

    return e->instance - run->instance;
}

static struct rb_node *runtime_node_new(struct rblist *rlist, const void *new_entry)
{
    const struct runtime_entry *e = new_entry;
    struct runtime *run = malloc(sizeof(*run));
    if (run) {
        RB_CLEAR_NODE(&run->rbn);
        run->instance = e->instance;
        run->another = e->another;
        run->runtime = 0;
        memset(run->comm, 0, 16);
        return &run->rbn;
    }
    return NULL;
}

static void runtime_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct runtime *run = rb_entry(rb_node, struct runtime, rbn);
    free(run);
}

static int read_cpu_thread_sibling(int cpu)
{
    struct perf_cpu_map *cpumap;
    char buff[PATH_MAX];
    char *cpu_list;
    size_t len = 0;
    int err, c, idx;
    int thread_sibling = -1;

    if (cpu >= ctx.nr_cpus)
        return -1;

    snprintf(buff, sizeof(buff), "devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
    if ((err = sysfs__read_str(buff, &cpu_list, &len)) < 0 ||
        len == 0) {
        fprintf(stderr, "failed to read %s, %d Not Supported.\n", buff, err);
        return -1;
    }
    cpu_list[len] = '\0';
    cpumap = perf_cpu_map__new(cpu_list);

    perf_cpu_map__for_each_cpu(c, idx, cpumap) {
        if (c < 0) {
            fprintf(stderr, "cpu < 0 %s, Not Supported.\n", cpu_list);
            free(cpu_list);
            return -1;
        }
        if (c == cpu)
            continue;
        thread_sibling = c;
        break;
    }
    perf_cpu_map__put(cpumap);
    free(cpu_list);
    return thread_sibling;
}

static int read_sched_vmf_sib(int ins)
{
    char path[64];
    char buf[32];
    int fd, len, vmf_sib;

    snprintf(path, sizeof(path), "/proc/%d/sched_vmf_sib", monitor_instance_thread(ins));
    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    len = (int)read(fd, buf, sizeof(buf));
    close(fd);
    if (len <= 0) return -1;
    len--;
    if (buf[len] == '\n' || len == sizeof(buf)-1)
        buf[len] = '\0';

    vmf_sib = atoi(buf);

    return perf_thread_map__idx(current_monitor()->threads, vmf_sib);
}


static int oncpu_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
        .wakeup_watermark = (oncpu.pages << 12) / 2,
    };
    struct perf_evsel *evsel;
    int i, id;

    if (!env->interval)
        env->interval = 1000;

    tep__ref();
    ctx.env = env;
    ctx.instance_oncpu = monitor_instance_oncpu();
    ctx.nr_ins = monitor_nr_instance();
    ctx.nr_cpus = get_present_cpus();
    rblist__init(&ctx.runtimes);
    ctx.runtimes.node_cmp = runtime_node_cmp;
    ctx.runtimes.node_new = runtime_node_new;
    ctx.runtimes.node_delete = runtime_node_delete;

    if (env->detail) {
        ctx.percpu_thread_siblings = calloc(ctx.nr_cpus, sizeof(int));
        if (!ctx.percpu_thread_siblings)
            return -1;
        for (i = 0; i < ctx.nr_cpus; i++) {
            ctx.percpu_thread_siblings[i] = read_cpu_thread_sibling(i);
            if (ctx.percpu_thread_siblings[i] == -1) {
                free(ctx.percpu_thread_siblings);
                ctx.percpu_thread_siblings = NULL;
                break;
            }
        }

        // on thread
        if (!ctx.instance_oncpu) {
            ctx.perins_vmf_sib = calloc(ctx.nr_ins, sizeof(int));
            if (!ctx.perins_vmf_sib)
                return -1;
            for (i = 0; i < ctx.nr_ins; i++) {
                ctx.perins_vmf_sib[i] = read_sched_vmf_sib(i);
            }
        }
    }

    attr.config = id = tep__event_id("sched", "sched_stat_runtime");
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    ctx.sched_stat_runtime_has_cpu = tep__event_has_field(id, "cpu");
    return 0;
}

static int oncpu_filter(struct perf_evlist *evlist, struct env *env)
{
    struct perf_evsel *evsel;
    int err;
    if (env->filter && env->filter[0]) {
        perf_evlist__for_each_evsel(evlist, evsel) {
            err = perf_evsel__apply_filter(evsel, env->filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void oncpu_exit(struct perf_evlist *evlist)
{
    rblist__exit(&ctx.runtimes);
    if (ctx.percpu_thread_siblings)
        free(ctx.percpu_thread_siblings);
    if (ctx.perins_vmf_sib)
        free(ctx.perins_vmf_sib);
    tep__unref();
}

static struct runtime *find_first_sib(int instance)
{
    struct rb_node *rbn;
    struct runtime_entry entry = {.instance = instance,};

    rbn = rb_find_first(&entry, &ctx.runtimes.entries.rb_root, runtime_instance_cmp);
    return rb_entry_safe(rbn, struct runtime, rbn);
}

#define for_each_runtime(first, run, member, cmp_member) \
    for(run = first; \
        run && run->cmp_member == first->cmp_member; \
        run = rb_entry_safe((rb_next(&run->member)), typeof(*run), member))

static void print_cpumap(struct runtime *first)
{
    struct runtime *run, *save = first;
    u64 sum = 0;

    if (first->cpu == -1) {
        sum = first->runtime;
        first = rb_entry_safe(rb_next(&first->rbn), struct runtime, rbn);
    }

    for_each_runtime(first, run, rbn, instance)
        sum += run->runtime;

    printf("%-6d %-16s %-7lu ", monitor_instance_thread(first->instance), first->comm, sum/1000000);

    if (ctx.percpu_thread_siblings) {
        u64 co = 0;
        if (ctx.perins_vmf_sib[first->instance] >= 0) {
            for_each_runtime(first, run, rbn, instance) {
                struct runtime *first_sib = find_first_sib(ctx.perins_vmf_sib[run->instance]);
                struct runtime *sib;
                for_each_runtime(first_sib, sib, rbn, instance) {
                    if (ctx.percpu_thread_siblings[sib->cpu] == run->cpu) {
                        co += min(run->runtime, sib->runtime);
                        break;
                    }
                }
            }
        }
        printf("%-6lu %-5lu  ", co/1000000, co*100/sum);
    }

    for_each_runtime(save, run, rbn, instance)
        printf("%d(%lums) ", run->cpu, run->runtime/1000000);

    if (ctx.percpu_thread_siblings) {
        printf(", ");
        for_each_runtime(first, run, rbn, instance)
            printf("%d ", ctx.percpu_thread_siblings[run->cpu]);
    }
    printf("\n");
}

static void print_tidmap(struct runtime *first)
{
    struct runtime *run;
    u64 sum = 0;

    for_each_runtime(first, run, rbn, instance)
        sum += run->runtime;

    printf("%03d %-7lu ", monitor_instance_cpu(first->instance), sum/1000000);

    for_each_runtime(first, run, rbn, instance)
        printf("%s:%d(%lums) ", run->comm, run->tid, run->runtime/1000000);

    printf("\n");
}

static void oncpu_interval(void)
{
    struct rb_node *next = rb_first_cached(&ctx.runtimes.entries);
    struct runtime *first, *run;

    if (rblist__empty(&ctx.runtimes))
        return ;

    print_time(stdout);
    printf("\n");
    if (!ctx.instance_oncpu)
        printf("THREAD %-16s %-7s %sCPUS(ms) %s\n", "COMM", "SUM(ms)",
            ctx.env->detail ? "CO(ms) CO(%)  " : "",
            ctx.env->detail ? ", SIBLINGS" : "");
    else
        printf("CPU %-7s COMM:TID(ms)\n", "SUM(ms)");

    first = rb_entry_safe(next, struct runtime, rbn);
    while (first) {
        ((!ctx.instance_oncpu) ? print_cpumap : print_tidmap)(first);
        for_each_runtime(first, run, rbn, instance);
        first = run;
    }
    rblist__exit(&ctx.runtimes);
}

static void oncpu_sample(union perf_event *event, int instance)
{
    struct sample_type_data *data = (void *)event->sample.array;
    struct runtime_entry entry;
    struct rb_node *rbn;
    struct runtime *run;
    int tid, cpu;

	/*
	 * CPU 24/KVM  89720 d... [179] 4925560.039977: sched:sched_stat_runtime: comm=CPU 90/KVM pid=89786 runtime=951502 [ns] vruntime=52818652842246 [ns]
	 *	ffffffff810d6157 update_curr+0x167 ([kernel.kallsyms])
	 *	ffffffff810d804d enqueue_entity+0x3d ([kernel.kallsyms])
	 *	ffffffff810d8bc9 enqueue_task_fair+0x59 ([kernel.kallsyms])
	 *	ffffffff810c67b6 enqueue_task+0x56 ([kernel.kallsyms])
	 *	ffffffff810c9543 activate_task+0x23 ([kernel.kallsyms])
	 *	ffffffff810c9893 ttwu_do_activate.constprop.119+0x33 ([kernel.kallsyms])
	 *	ffffffff810ccb3d try_to_wake_up+0x18d ([kernel.kallsyms])
	 *	ffffffff810cce22 default_wake_function+0x12 ([kernel.kallsyms])
	 *	ffffffff810b7938 autoremove_wake_function+0x18 ([kernel.kallsyms])
	 *	ffffffff810c04bb __wake_up_common+0x5b ([kernel.kallsyms])
	 *	ffffffff810c55c9 __wake_up+0x39 ([kernel.kallsyms])
	 *
	 * When a process is woken up to the specified cpu x, update_curr will be called on
	 * the current cpu, and sched:sched_stat_runtime will be recorded on the current cpu
	 * instead of cpu x. Will cause data->tid_entry.tid != data->raw.runtime.pid.
	 * As in the above example, 89720 != 89786.
	**/
    if (!ctx.sched_stat_runtime_has_cpu &&
        data->tid_entry.tid != data->raw.runtime.pid) { //TODO
    __print_return:
        if (ctx.instance_oncpu) {
            if (ctx.env->verbose && data->raw.runtime.runtime >= ctx.env->greater_than)
                tep__print_event(0, data->cpu_entry.cpu, data->raw.data, data->raw.size);
        }
        // A similar problem exists with attaching to a process.
        return;
    }

    tid = data->raw.runtime.pid;
    cpu = data->tid_entry.tid != data->raw.runtime.pid ? -1 : data->cpu_entry.cpu;
    if (ctx.sched_stat_runtime_has_cpu) {
        cpu = data->raw.runtime.cpu;
        if (ctx.instance_oncpu && cpu != data->cpu_entry.cpu) {
            instance = perf_cpu_map__idx(oncpu.cpus, cpu); // maybe -1;
            if (instance == -1)
                goto __print_return;
        }
    }

    entry.instance = instance;
    entry.another = ctx.instance_oncpu ? tid : cpu;
    rbn = rblist__findnew(&ctx.runtimes, &entry);
    if (rbn) {
        run = rb_entry(rbn, struct runtime, rbn);
        run->runtime += data->raw.runtime.runtime;
        if (run->comm[0] == 0 && data->tid_entry.tid == data->raw.runtime.pid) {
            memcpy(run->comm, data->raw.runtime.comm, 16);
        }
    }
}

static profiler oncpu = {
    .name = "oncpu",
    .pages = 4,
    .init = oncpu_init,
    .filter = oncpu_filter,
    .deinit = oncpu_exit,
    .interval = oncpu_interval,
    .sample = oncpu_sample,
};
PROFILER_REGISTER(oncpu)


