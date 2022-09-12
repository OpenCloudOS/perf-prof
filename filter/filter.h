#ifndef __FILTER_H
#define __FILTER_H

struct bpf_filter {
    void *obj;
    int bpf_fd;
    // args
    bool filter_irqs_disabled;
    bool irqs_disabled;
    bool filter_tif_need_resched;
    bool tif_need_resched;
    bool filter_exclude_pid;
    u32 exclude_pid;
    bool filter_nr_running;
    u32 nr_running_min;
    u32 nr_running_max;
    bool filter_runtime_greater;
    u32 runtime_greater;
};
int bpf_filter_open(struct bpf_filter *filter);
void bpf_filter_close(struct bpf_filter *filter);
int bpf_filter_init(struct bpf_filter *filter, struct env *env);

#endif
