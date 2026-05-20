#ifndef __VCPU_INFO_H
#define __VCPU_INFO_H

#include <linux/list.h>
#include <linux/refcount.h>
#include <perf/cpumap.h>

#if defined(__i386__) || defined(__x86_64__)
#include <asm/pvclock.h>
#endif

struct vcpu_data {
    /* from libvirtd */
    int host_cpu; // vcpu -> host_cpu
    int thread_id; // vcpu -> thread_id

#if defined(__i386__) || defined(__x86_64__)
    bool pvclock_update;
    /* from kvm */
    u64 tsc_offset;
    u64 tsc_scaling_ratio;
    u64 tsc_scaling_ratio_frac_bits;
    struct pvclock_vcpu_time_info pvti;
#endif
};

struct vcpu_info {
    struct list_head vm_link;
    const char *uuid;
    refcount_t ref;
    pid_t tgid;
    int kvm_vm_fd;

    int nr_vcpu;
    struct perf_cpu_map **host_cpus; // vcpu -> host_cpu map
    struct vcpu_data vcpu[0];
};

struct vcpu_info *vcpu_info_get(const char *uuid);
void vcpu_info_put(struct vcpu_info *vcpu);

#endif
