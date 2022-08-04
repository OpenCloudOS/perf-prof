#include <stdio.h>
#include <stdlib.h>
#include <monitor.h>

#ifdef CONFIG_LIBBPF

#include "perf_event.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int perf_event_filter_open(struct perf_event_filter *filter)
{
    struct perf_event_bpf *obj = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);

    obj = perf_event_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open and/or load BPF object\n");
        return -1;
    }

    bpf_program__set_perf_event(obj->progs.perf_event_do_filter);

    #define ASSIGN(a) obj->rodata->a = filter->a
    ASSIGN(filter_irqs_disabled);
    ASSIGN(irqs_disabled);
    ASSIGN(filter_tif_need_resched);
    ASSIGN(tif_need_resched);
    ASSIGN(filter_nr_running);
    ASSIGN(nr_running_min);
    ASSIGN(nr_running_max);

    err = perf_event_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    filter->obj = obj;
    filter->perf_event_prog_fd = bpf_program__fd(obj->progs.perf_event_do_filter);

    return 0;

cleanup:
    perf_event_bpf__destroy(obj);
    filter->obj = NULL;
    filter->perf_event_prog_fd = -1;
    return err;
}

void perf_event_filter_close(struct perf_event_filter *filter)
{
    if (filter && filter->obj) {
        perf_event_bpf__destroy(filter->obj);
        filter->obj = NULL;
        filter->perf_event_prog_fd = -1;
    }
}

#else

int perf_event_filter_open(struct perf_event_filter *filter)
{
    filter->obj = NULL;
    filter->perf_event_prog_fd = -1;
    return 0;
}
void perf_event_filter_close(struct perf_event_filter *filter) {}

#endif

