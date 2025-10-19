#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <linux/bitops.h>
#include <monitor.h>
#include <stack_helpers.h>

#define REC(a) (1<<(PERF_RECORD_ ## a))
#define TEST(a) (dev->private ? ((u64)dev->private >> (PERF_RECORD_ ## a)) & 1 : 1)

static int misc_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_DUMMY,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 0,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU,
        .pinned        = 0,
        .disabled      = 1,
        .sample_id_all = 1,
        .ksymbol       = TEST(KSYMBOL), // bpf symbol
        .bpf_event     = TEST(BPF_EVENT),
        .cgroup        = TEST(CGROUP),
        .text_poke     = TEST(TEXT_POKE),

        /* .watermark  = 0,
         * .wakeup_events = 1,
         * For the PERF_RECORD_SAMPLE event, wakeup_events = 1
         * can work correctly, but not PERF_RECORD_KSYMBOL...
         */
        .watermark     = 1,
        .wakeup_watermark = 1,
    };
    struct perf_evsel *evsel;

    if (!dev->private)
        dev->private = (void *)(u64)(REC(KSYMBOL) | REC(BPF_EVENT) |
                                     REC(CGROUP) | REC(TEXT_POKE));

    evsel = perf_evsel__new(&attr);
    if (!evsel) goto failed;
    perf_evlist__add(evlist, evsel);

    if ((u64)dev->private & (1<<PERF_RECORD_TEXT_POKE))
        function_resolver_ref();

    return 0;

failed:
    return -1;
}

static int misc_reinit(struct prof_dev *dev, int err)
{
    u64 private = (u64)dev->private;

    if (err == -EINVAL) {
        private &= ~(1<<(fls64(private) - 1));
        if (((u64)dev->private ^ private) & (1<<PERF_RECORD_TEXT_POKE))
             function_resolver_unref();
        dev->private = (void *)private;
        return private != 0;
    } else
        return 0;
}

static void misc_deinit(struct prof_dev *dev)
{
    if ((u64)dev->private & (1<<PERF_RECORD_TEXT_POKE))
        function_resolver_unref();
}

struct sample_id_type {
    u32 pid, tid; // PERF_SAMPLE_TID
    u64 time;     // PERF_SAMPLE_TIME
    u32 cpu, res; // PERF_SAMPLE_CPU
};

static void misc_header(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct sample_id_type *s = (void *)event + event->header.size - sizeof(*s);
    prof_dev_print_time(dev, s->time, stdout);
    printf("pid %6u tid %6u [%03d] %lu.%06lu: ", s->pid, s->tid, s->cpu,
           s->time/1000/USEC_PER_SEC, (s->time/1000)%USEC_PER_SEC);
}

static void misc_ksymbol(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct perf_record_ksymbol *ksymbol = (void *)event;
    const char *str = "";
    if (ksymbol->ksym_type == PERF_RECORD_KSYMBOL_TYPE_BPF)
        str = "bpf";
    if (ksymbol->ksym_type == PERF_RECORD_KSYMBOL_TYPE_OOL)
        str = "kprobe/ftrace";
    misc_header(dev, event, instance);
    printf("misc:ksymbol: %s %s %016llx/%d %s\n", str,
        ksymbol->flags & PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER ? "unreg" : "reg",
        ksymbol->addr, ksymbol->len, ksymbol->name);
}

static void misc_bpf_event(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct perf_record_bpf_event *bpf = (void *)event;
    const char *type = "unknown";
    int i;
    misc_header(dev, event, instance);
    if (bpf->type == PERF_BPF_EVENT_PROG_LOAD)
        type = "prog load";
    if (bpf->type == PERF_BPF_EVENT_PROG_UNLOAD)
        type = "prog unload";
    printf("misc:bpf_event: %s id %u tag ", type, bpf->id);
    for (i = 0; i < BPF_TAG_SIZE; i++)
        printf("%02x", bpf->tag[i]);
    printf("\n");
}

static void misc_cgroup(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct perf_record_cgroup *cgroup = (void *)event;
    misc_header(dev, event, instance);
    printf("misc:cgroup: id %llu %s\n", cgroup->id, cgroup->path);
}

static void misc_text_poke(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct perf_record_text_poke_event *text = (void *)event;
    __u64 addr = text->addr;
    __u64 func = addr;
    char *func_name = function_resolver(NULL, &func, NULL);
    int i;
    misc_header(dev, event, instance);
    printf("misc:text_poke: %016llx", addr);
    for (i = 0; i < text->old_len; i++)
        printf(" %02x", text->bytes[i]);
    printf(" =>");
    for (i = 0; i < text->new_len; i++)
        printf(" %02x", text->bytes[i+text->old_len]);
    printf("  %s+0x%llx\n", func_name, addr-func);
}

static const char *misc_desc[] = PROFILER_DESC("misc",
    "[OPTION...]",
    "Miscellaneous trace.", "",
    "SYNOPSIS",
    "    ksymbol: trace register and unregister kernel symbols.",
    "    bpf_event: trace load and unload bpf programs.",
    "    cgroup: trace perf_event cgroup online.",
    "    text_poke: trace self-modifying kernel text.", "",
    "EXAMPLES",
    "    "PROGRAME" misc");
static const char *misc_argv[] = PROFILER_ARGV("misc",
    "OPTION:", "cpus", "output", "mmap-pages",
    "usage-self", "version", "verbose", "quiet", "help");
static profiler misc = {
    .name = "misc",
    .desc = misc_desc,
    .argv = misc_argv,
    .pages = 2,
    .init = misc_init,
    .reinit = misc_reinit,
    .deinit = misc_deinit,
    .ksymbol = misc_ksymbol,
    .bpf_event = misc_bpf_event,
    .cgroup = misc_cgroup,
    .text_poke = misc_text_poke,
};
PROFILER_REGISTER(misc);

