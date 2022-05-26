#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <api/fs/fs.h>
#include <monitor.h>
#include <tep.h>


static profiler oncpu;

struct perins_cpumap {
    u64 nr;
    u64 map[0];
};

struct perins_info {
    char comm[16];
};

static struct oncpu_ctx {
    int nr_ins;
    int nr_cpus;
    int size_perins_cpumap;
    struct perins_cpumap *maps;
    struct perins_cpumap *all_ins;
    struct perins_info *infos;
    int *percpu_thread_siblings;
    struct env *env;
} ctx;

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


static int oncpu_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
        .wakeup_watermark = (oncpu.pages << 12) / 2,
    };
    struct perf_evsel *evsel;
    int i;

    if (monitor_instance_oncpu()) {
        fprintf(stderr, "Need to specify -p PID parameter\n");
        return -1;
    }
    if (!env->interval)
        env->interval = 1000;

    ctx.env = env;
    ctx.nr_ins = monitor_nr_instance();
    ctx.nr_cpus = get_present_cpus();
    ctx.size_perins_cpumap = sizeof(struct perins_cpumap) + ctx.nr_cpus * sizeof(u64);
    ctx.maps = malloc((ctx.nr_ins + 1) * ctx.size_perins_cpumap);
    if (!ctx.maps)
        return -1;
    ctx.all_ins = (void *)ctx.maps + ctx.nr_ins * ctx.size_perins_cpumap;
    memset(ctx.maps, 0, (ctx.nr_ins + 1) * ctx.size_perins_cpumap);

    ctx.infos = calloc(ctx.nr_ins, sizeof(struct perins_info));
    if (!ctx.infos)
        return -1;
    for (i = 0; i < ctx.nr_ins; i++) {
        char path[64];
        int fd, len;

        snprintf(path, sizeof(path), "/proc/%d/comm", monitor_instance_thread(i));
        fd = open(path, O_RDONLY);
        if (fd < 0) return -1;
        len = (int)read(fd, ctx.infos[i].comm, 16);
        close(fd);
        if (len <= 0) return -1;
        len--;
        if (ctx.infos[i].comm[len] == '\n' || len == 15)
            ctx.infos[i].comm[len] = '\0';
    }

    if (env->detail) {
        ctx.percpu_thread_siblings = calloc(ctx.nr_cpus, sizeof(int));
        if (!ctx.infos)
            return -1;
        for (i = 0; i < ctx.nr_cpus; i++) {
            ctx.percpu_thread_siblings[i] = read_cpu_thread_sibling(i);
            if (ctx.percpu_thread_siblings[i] == -1) {
                free(ctx.percpu_thread_siblings);
                ctx.percpu_thread_siblings = NULL;
                break;
            }
        }
    }

    attr.config = tep__event_id("sched", "sched_stat_runtime");
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static void oncpu_exit(struct perf_evlist *evlist)
{
    free(ctx.maps);
    free(ctx.infos);
    if (ctx.percpu_thread_siblings)
        free(ctx.percpu_thread_siblings);
}

static void print_cpumap(int ins, struct perins_cpumap *map)
{
    int i, p = 0;

    if (!map->nr)
        return;

    if (ins >= 0) {
        printf("%-6d %-16s %-7lu ", monitor_instance_thread(ins), ctx.infos[ins].comm, map->nr/1000000);
    }
    for (i = 0; i < ctx.nr_cpus; i++) {
        if (map->map[i] > 0)
            p += printf("%d(%lums) ", i, map->map[i]/1000000);
    }
    if (ctx.percpu_thread_siblings) {
        printf(", ");
        for (i = 0; i < ctx.nr_cpus; i++) {
            if (map->map[i] > 0)
                printf("%d ", ctx.percpu_thread_siblings[i]);
        }
    }
    printf("\n");
}

static void oncpu_interval(void)
{
    int i;

    print_time(stdout);
    printf("\n");
    if (ctx.env->perins) {
        printf("THREAD %-16s %-7s CPUS(ms) %s\n", "COMM", "SUM(ms)", ctx.env->detail ? ", SIBLINGS" : "");
        for (i = 0; i < ctx.nr_ins; i++) {
            print_cpumap(i, (void *)ctx.maps + i * ctx.size_perins_cpumap);
        }
    } else {
        print_cpumap(-1, ctx.all_ins);
    }
    memset(ctx.maps, 0, (ctx.nr_ins + 1) * ctx.size_perins_cpumap);
}

static void oncpu_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_CPU
    struct sample_type_data {
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        __u64		period;
    } *data = (void *)event->sample.array;
    struct perins_cpumap *map = (void *)ctx.maps + instance * ctx.size_perins_cpumap;

    map->nr += data->period;
    map->map[data->cpu_entry.cpu] += data->period;
    ctx.all_ins->nr += data->period;
    ctx.all_ins->map[data->cpu_entry.cpu] += data->period;
}

static profiler oncpu = {
    .name = "oncpu",
    .pages = 4,
    .init = oncpu_init,
    .deinit = oncpu_exit,
    .interval = oncpu_interval,
    .sample = oncpu_sample,
};
PROFILER_REGISTER(oncpu)


