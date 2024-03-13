#ifndef __VCPU_INFO_H
#define __VCPU_INFO_H

#include <monitor.h>

struct vcpu_info {
    int nr_vcpu;
    struct perf_cpu_map **host_cpus; // vcpu -> host_cpu map
    struct {
        int host_cpu; // vcpu -> host_cpu
        int thread_id; // vcpu -> thread_id
    } vcpu[0];
};
struct vcpu_info *vcpu_info_new(const char *vm);
void vcpu_info_free(struct vcpu_info *vcpu);


#endif
