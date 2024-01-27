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


struct runtime {
    struct rb_node rbn;
    int instance;
    union {
        int another;
        int cpu;
        int tid;
    };
    u64 runtime;
    u64 nr_run;
    u64 max;
    char comm[16];
};

struct oncpu_ctx {
    bool tid_to_cpumap;
    int nr_ins;
    int nr_cpus;
    u64 *last_time;
    struct rblist runtimes;
    int *percpu_thread_siblings;
    int *perins_vmf_sib;
};

struct sched_stat_runtime {
    unsigned short common_type; //       offset:0;       size:2; signed:0;
    unsigned char common_flags; //       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count; //       offset:3;       size:1; signed:0;
    int common_pid; //   offset:4;       size:4; signed:1;

    char comm[16];  //   offset:8;       size:16;        signed:1;
    pid_t pid;      //   offset:24;      size:4; signed:1;
    u64 runtime;    //   offset:32;      size:8; signed:0;
    u64 vruntime;   //   offset:40;      size:8; signed:0;
};

struct sched_switch {
    unsigned short common_type; //       offset:0;       size:2; signed:0;
    unsigned char common_flags; //       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count; //       offset:3;       size:1; signed:0;
    int common_pid; //   offset:4;       size:4; signed:1;

    char prev_comm[16]; //       offset:8;       size:16;        signed:1;
    pid_t prev_pid; //   offset:24;      size:4; signed:1;
    int prev_prio; //    offset:28;      size:4; signed:1;
    long prev_state; //  offset:32;      size:8; signed:1;
    char next_comm[16]; //       offset:40;      size:16;        signed:1;
    pid_t next_pid; //   offset:56;      size:4; signed:1;
    int next_prio; //   offset:60;      size:4; signed:1;
};

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW
struct sample_type_data {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64  time;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
    __u64       period;
    //PERF_SAMPLE_RAW
    struct {
        __u32   size;
        union {
            __u8    data[0];
            struct sched_stat_runtime runtime;
            struct sched_switch sched_switch;
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
        run->nr_run = 0;
        run->max = 0;
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

static void empty(struct rblist *rblist, struct rb_node *rb_node)
{
}

static int runtime_sorted_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct runtime *run = rb_entry(rbn, struct runtime, rbn);
    struct runtime *e = rb_entry(entry, struct runtime, rbn);

    if (run->instance > e->instance)
        return 1;
    else if (run->instance < e->instance)
        return -1;

    if (run->runtime > e->runtime)
        return -1;
    else if (run->runtime < e->runtime)
        return 1;

    if (run->another > e->another)
        return 1;
    else if (run->another < e->another)
        return -1;

    return 0;
}

static struct rb_node *runtime_sorted_node_new(struct rblist *rlist, const void *new_entry)
{
    struct rb_node *n = (void *)new_entry;

    RB_CLEAR_NODE(n);
    return n;
}


static int read_cpu_thread_sibling(int cpu)
{
    struct perf_cpu_map *cpumap;
    char buff[PATH_MAX];
    char *cpu_list;
    size_t len = 0;
    int err, c, idx;
    int thread_sibling = -1;

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

static int read_sched_vmf_sib(int thread)
{
    char path[64];
    char buf[32];
    int fd, len, vmf_sib;

    snprintf(path, sizeof(path), "/proc/%d/sched_vmf_sib", thread);
    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    len = (int)read(fd, buf, sizeof(buf));
    close(fd);
    if (len <= 0) return -1;
    len--;
    if (buf[len] == '\n' || len == sizeof(buf)-1)
        buf[len] = '\0';

    vmf_sib = atoi(buf);

    return vmf_sib;
}

static void oncpu_exit(struct prof_dev *dev);
static int oncpu_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
    struct oncpu_ctx *ctx = zalloc(sizeof(*ctx));
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
        .wakeup_watermark = (dev->pages << 12) / 2,
    };
    struct perf_evsel *evsel;
    int i;

    if (!ctx)
        return -1;
    dev->private = ctx;

    if (!env->interval)
        env->interval = 1000;

    tep__ref();

    ctx->tid_to_cpumap = !prof_dev_ins_oncpu(dev);
    ctx->nr_ins = prof_dev_nr_ins(dev);
    ctx->nr_cpus = get_present_cpus();
    ctx->last_time = calloc(ctx->nr_ins, sizeof(u64));
    if (!ctx->last_time)
        goto failed;

    rblist__init(&ctx->runtimes);
    ctx->runtimes.node_cmp = runtime_node_cmp;
    ctx->runtimes.node_new = runtime_node_new;
    ctx->runtimes.node_delete = runtime_node_delete;

    if (ctx->tid_to_cpumap && env->detail) {
        ctx->percpu_thread_siblings = calloc(ctx->nr_cpus, sizeof(int));
        if (!ctx->percpu_thread_siblings)
            goto failed;
        for (i = 0; i < ctx->nr_cpus; i++) {
            ctx->percpu_thread_siblings[i] = read_cpu_thread_sibling(i);
            if (ctx->percpu_thread_siblings[i] == -1) {
                free(ctx->percpu_thread_siblings);
                ctx->percpu_thread_siblings = NULL;
                break;
            }
        }

        // on thread
        ctx->perins_vmf_sib = calloc(ctx->nr_ins, sizeof(int));
        if (!ctx->perins_vmf_sib)
            goto failed;
        for (i = 0; i < ctx->nr_ins; i++) {
            int vmf_sib = read_sched_vmf_sib(prof_dev_ins_thread(dev, i));
            ctx->perins_vmf_sib[i] = perf_thread_map__idx(dev->threads, vmf_sib);
        }
    }

    reduce_wakeup_times(dev, &attr);

    if (ctx->tid_to_cpumap)
        attr.config = tep__event_id("sched", "sched_stat_runtime");
    else
        attr.config = tep__event_id("sched", "sched_switch");
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        goto failed;
    }
    perf_evlist__add(evlist, evsel);

    return 0;

failed:
    oncpu_exit(dev);
    return -1;
}

static int oncpu_filter(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
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

static void oncpu_exit(struct prof_dev *dev)
{
    struct oncpu_ctx *ctx = dev->private;
    rblist__exit(&ctx->runtimes);
    if (ctx->last_time)
        free(ctx->last_time);
    if (ctx->percpu_thread_siblings)
        free(ctx->percpu_thread_siblings);
    if (ctx->perins_vmf_sib)
        free(ctx->perins_vmf_sib);
    tep__unref();
    free(ctx);
}

static void oncpu_lost(struct prof_dev *dev, union perf_event *event, int ins, u64 lost_start, u64 lost_end)
{
    struct oncpu_ctx *ctx = dev->private;

    print_lost_fn(dev, event, ins);

    if (using_order(dev)) {
        fprintf(stderr, "%s: the correctness when lost cannot be guaranteed.\n", dev->prof->name);
        return;
    }

    if (ctx->tid_to_cpumap) {
        // sched:sched_stat_runtime
    } else {
        // sched:sched_switch
        ctx->last_time[ins] = 0;
    }
}

static struct runtime *find_first_sib(struct oncpu_ctx *ctx, int instance)
{
    struct rb_node *rbn;
    struct runtime_entry entry = {.instance = instance,};

    rbn = rb_find_first(&entry, &ctx->runtimes.entries.rb_root, runtime_instance_cmp);
    return rb_entry_safe(rbn, struct runtime, rbn);
}

#define for_each_runtime(first, run, member, cmp_member) \
    for(run = first; \
        run && run->cmp_member == first->cmp_member; \
        run = rb_entry_safe((rb_next(&run->member)), typeof(*run), member))

static void print_cpumap(struct prof_dev *dev, struct runtime *first)
{
    struct oncpu_ctx *ctx = dev->private;
    struct runtime *run;
    u64 sum = 0;

    for_each_runtime(first, run, rbn, instance)
        sum += run->runtime;

    printf("%-6d %-16s %-7lu ", prof_dev_ins_thread(dev, first->instance), first->comm, sum/1000000);

    if (ctx->percpu_thread_siblings) {
        u64 co = 0;
        if (ctx->perins_vmf_sib[first->instance] >= 0) {
            for_each_runtime(first, run, rbn, instance) {
                struct runtime *first_sib = find_first_sib(ctx, ctx->perins_vmf_sib[run->instance]);
                struct runtime *sib;
                for_each_runtime(first_sib, sib, rbn, instance) {
                    if (ctx->percpu_thread_siblings[sib->cpu] == run->cpu) {
                        co += min(run->runtime, sib->runtime);
                        break;
                    }
                }
            }
        }
        printf("%-6lu %-5lu  ", co/1000000, co*100/sum);
    }

    for_each_runtime(first, run, rbn, instance)
        printf("%d(%lums) ", run->cpu, run->runtime/1000000);

    if (ctx->percpu_thread_siblings) {
        printf(", ");
        for_each_runtime(first, run, rbn, instance)
            printf("%d ", ctx->percpu_thread_siblings[run->cpu]);
    }
    printf("\n");
}

static void print_tidmap(struct prof_dev *dev, struct runtime *first)
{
    struct runtime *run;
    u64 sum = 0;

    for_each_runtime(first, run, rbn, instance)
        sum += run->runtime;

    printf("%03d %-7lu ", prof_dev_ins_cpu(dev, first->instance), sum/1000000);

    for_each_runtime(first, run, rbn, instance)
        if (dev->env->detail)
            printf("%s:%d(%.1fms/%lu/%.1fms) ", run->comm, run->tid, run->runtime/1000000.0, run->nr_run, run->max/1000000.0);
        else
            printf("%s:%d(%.1fms) ", run->comm, run->tid, run->runtime/1000000.0);

    printf("\n");
}

static void oncpu_interval(struct prof_dev *dev)
{
    struct env *env = dev->env;
    struct oncpu_ctx *ctx = dev->private;
    struct rb_node *next = rb_first_cached(&ctx->runtimes.entries);
    struct runtime *first, *run;
    struct rblist sorted;

    if (rblist__empty(&ctx->runtimes))
        return ;

    if (!ctx->tid_to_cpumap) {
        // sort by cpu(from small to big), runtime(from big to small), tid.

        rblist__init(&sorted);
        sorted.node_cmp = runtime_sorted_node_cmp;
        sorted.node_new = runtime_sorted_node_new;
        sorted.node_delete = runtime_node_delete;
        ctx->runtimes.node_delete = empty; //empty, not really delete

        /* sort, remove from `ctx->runtimes', add to `sorted'. */
        do {
            struct rb_node *rbn = rblist__entry(&ctx->runtimes, 0);
            rblist__remove_node(&ctx->runtimes, rbn);
            rblist__add_node(&sorted, rbn);
        } while (!rblist__empty(&ctx->runtimes));

        next = rblist__entry(&sorted, 0);
    }

    print_time(stdout);
    printf("\n");
    if (ctx->tid_to_cpumap)
        printf("THREAD %-16s %-7s %sCPUS(ms) %s\n", "COMM", "SUM(ms)",
            ctx->percpu_thread_siblings ? "CO(ms) CO(%)  " : "",
            ctx->percpu_thread_siblings ? ", SIBLINGS" : "");
    else
        printf("CPU %-7s COMM:TID(ms%s)\n", "SUM(ms)", env->detail ? "/switches/max_ms" : "");

    first = rb_entry_safe(next, struct runtime, rbn);
    while (first) {
        (ctx->tid_to_cpumap ? print_cpumap : print_tidmap)(dev, first);
        for_each_runtime(first, run, rbn, instance);
        first = run;
    }

    if (!ctx->tid_to_cpumap) {
        rblist__exit(&sorted);
        ctx->runtimes.node_delete = runtime_node_delete;
    } else
        rblist__exit(&ctx->runtimes);
}

static void oncpu_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct oncpu_ctx *ctx = dev->private;
    struct env *env = dev->env;
    struct sample_type_data *data = (void *)event->sample.array;
    struct runtime_entry entry;
    struct rb_node *rbn;
    struct runtime *run;
    int tid, cpu;
    u64 runtime;
    char *comm;

    if (env->verbose >= VERBOSE_EVENT)
        tep__print_event(data->time, data->cpu_entry.cpu, data->raw.data, data->raw.size);

    if (ctx->tid_to_cpumap) {
        // sched:sched_stat_runtime

        tid = data->tid_entry.tid;
        cpu = data->cpu_entry.cpu;
        runtime = data->raw.runtime.runtime;
        comm = data->raw.runtime.comm;
    } else {
        /*
         * sched:sched_switch
         *
         *        ps   1214 d... [000]  2359.771892: sched:sched_switch: ps:1214 [120] R ==> sap1001:112746 [120]
         *   sap1001 112746 d... [000]  2359.772143: sched:sched_switch: sap1001:112746 [120] S ==> ps:1214 [120]
         *
         * The runtime of sap1001:112746 is equal to 2359.772143 minus 2359.771892.
        **/
        if (ctx->last_time[instance] == 0) {
            ctx->last_time[instance] = data->time;
            return;
        }
        tid = data->raw.sched_switch.prev_pid;
        cpu = data->cpu_entry.cpu;
        runtime = data->time - ctx->last_time[instance];
        comm = data->raw.sched_switch.prev_comm;
        ctx->last_time[instance] = data->time;

        // exclude swapper
        if (strncmp(comm, "swapper/", 8) == 0)
            return;
    }

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
    if (ctx->tid_to_cpumap &&
        data->tid_entry.tid != data->raw.runtime.pid) {
        // print unhandled event
        if (env->verbose == VERBOSE_NOTICE && data->raw.runtime.runtime >= env->greater_than)
            tep__print_event(0, data->cpu_entry.cpu, data->raw.data, data->raw.size);

        // A similar problem exists with attaching to a process.
        return;
    }

    entry.instance = instance;
    entry.another = ctx->tid_to_cpumap ? cpu : tid;
    rbn = rblist__findnew(&ctx->runtimes, &entry);
    if (rbn) {
        run = rb_entry(rbn, struct runtime, rbn);
        run->runtime += runtime;
        run->nr_run += 1;
        if (runtime > run->max)
            run->max = runtime;
        if (run->comm[0] == 0) {
            memcpy(run->comm, comm, 16);
        }
    }
}

static const char *oncpu_desc[] = PROFILER_DESC("oncpu",
    "[OPTION...] [--detail] [--filter filter]",
    "Determine which processes are running on which CPUs.", "",
    "TRACEPOINT",
    "    sched:sched_switch, sched:sched_stat_runtime", "",
    "EXAMPLES",
    "    "PROGRAME" oncpu -p 2347",
    "    "PROGRAME" oncpu -C 0-3");
static const char *oncpu_argv[] = PROFILER_ARGV("oncpu",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "detail", "filter");
static profiler oncpu = {
    .name = "oncpu",
    .desc = oncpu_desc,
    .argv = oncpu_argv,
    .pages = 4,
    .init = oncpu_init,
    .filter = oncpu_filter,
    .deinit = oncpu_exit,
    .interval = oncpu_interval,
    .lost = oncpu_lost,
    .sample = oncpu_sample,
};
PROFILER_REGISTER(oncpu)


