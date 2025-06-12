#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "kvm_exit.h"
#include "perf_output.bpf.h"

#define MAX_CPUS 4096
#define MAX_VCPUS 8192
#define INT64_MAX 9223372036854775807UL

const volatile unsigned int filter_pid = 0;
const volatile int64_t filter_latency = 0;
unsigned char work_cpus[MAX_CPUS] = {0};
struct kvm_vcpu_event percpu_event[MAX_CPUS] = {0};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VCPUS);
    __type(key, int);
    __type(value, struct kvm_vcpu_event);
} kvm_vcpu SEC(".maps");


SEC("raw_tp/kvm_exit")
#ifdef __TARGET_ARCH_arm64
#define _exit_reason  EXIT_REASON((u32)ret, esr_ec)
#define _isa   KVM_ISA_ARM
void BPF_PROG(kvm_exit, int ret, unsigned int esr_ec, unsigned long vcpu_pc)
#else
void BPF_PROG(kvm_exit, u32 _exit_reason, void *vcpu, u32 _isa)
#endif
{
    struct kvm_vcpu_event *data;
    u64 cpu = bpf_get_smp_processor_id();

    if (cpu >= MAX_CPUS || !work_cpus[cpu])
        return;

    data = &percpu_event[cpu];
    data->exit_reason = _exit_reason;
    data->latency = bpf_ktime_get_ns();

    if (!data->pid) {
        u64 id = bpf_get_current_pid_tgid();
        data->tgid = (u32)(id >> 32);
        data->pid = (u32)id;
        data->isa = _isa;
    }
}

SEC("raw_tp/kvm_entry")
void BPF_PROG(kvm_entry) // int vcpu_id | unsigned long vcpu_pc
{
    struct kvm_vcpu_event *data;
    u64 cpu = bpf_get_smp_processor_id();

    if (cpu >= MAX_CPUS || !work_cpus[cpu])
        return;

    data = &percpu_event[cpu];
    data->latency = bpf_ktime_get_ns() - (u64)data->latency;
    if (data->latency > filter_latency) {
        if (data->switches) {
            struct task_struct *task = (void *)bpf_get_current_task();
            u64 run_delay = BPF_CORE_READ(task, sched_info.run_delay);
            data->run_delay = run_delay - data->run_delay;
        } else {
            data->run_delay = 0;
            data->sched_latency = 0;
        }
        perf_output(ctx, data, sizeof(*data));
    }
    data->switches = 0;
}

SEC("raw_tp/sched_switch")
void BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    struct kvm_vcpu_event *curr, *prev_event, *next_event;
    u64 cpu = bpf_get_smp_processor_id();
    u32 next_pid;
    u64 time, run_delay;

    if (cpu >= MAX_CPUS || !work_cpus[cpu])
        return;

    time = 0;
    curr = &percpu_event[cpu];
    if (curr->pid) {
        time = bpf_ktime_get_ns();
        run_delay = BPF_CORE_READ(prev, sched_info.run_delay);
        prev_event = bpf_map_lookup_elem(&kvm_vcpu, &curr->pid);
        if (!prev_event) {
            curr->switches = 0;
            curr->sched_latency = time;
            curr->run_delay = run_delay;
            bpf_map_update_elem(&kvm_vcpu, &curr->pid, curr, BPF_ANY);
        } else {
            prev_event->exit_reason = curr->exit_reason;
            prev_event->latency = curr->latency;
            /*
             * From kvm_exit to kvm_entry, the vcpu may have multiple sched_switches
             * and sched_migrations.
             *
             * run_delay: Save it here, use it in kvm_entry and clean it up.
             *            Depends on CONFIG_SCHED_INFO, CONFIG_SCHEDSTATS
             *
             * curr->switches: Keeps the number of switches since kvm_exit.
             * curr->sched_latency: Cumulative value, the delay between vcpu switching
             *     out and switching in, since kvm_exit.
             *
             * prev_event->sched_latency: Contains the current time and historical
             *     latency. In the kvm_vcpu hashmap.
             */
            if (curr->switches == 0) {
                prev_event->switches = 0;
                prev_event->sched_latency = time;
                prev_event->run_delay = run_delay;
            } else {
                prev_event->switches = curr->switches;
                prev_event->sched_latency = time - curr->sched_latency;
            }
        }
        /*
         *  CPU     0                1
         *      vcpu=>idle
         *  (1) idle=>awk        idle=>vcpu(load kvm_vcpu, update percpu_event[1])
         *  (2) awk =>idle       vcpu=>idle(update kvm_vcpu)
         *      idle=>vcpu
         *
         * Assigning pid = 0 can avoid (1) (2) setting the old exit_reason/latency
         * to the kvm_vcpu hashmap.
         */
        curr->pid = 0;
    }

    next_pid = BPF_CORE_READ(next, pid);
    if (next_pid) {
        next_event = bpf_map_lookup_elem(&kvm_vcpu, &next_pid);
        if (next_event) {
            curr->tgid = next_event->tgid;
            curr->pid = next_event->pid;
            curr->isa = next_event->isa;
            curr->exit_reason = next_event->exit_reason;
            curr->latency = next_event->latency;
            curr->switches = next_event->switches + 1;
            curr->run_delay = next_event->run_delay;
            curr->sched_latency = (time ?: bpf_ktime_get_ns()) - (u64)next_event->sched_latency;
        } else {
            /*
             * For a newly generated vCPU, setting a INT64_MAX latency can ensure
             * that it does not generate incorrect output in kvm_entry.
             * (data->latency > filter_latency) condition is not met.
             */
            curr->latency = INT64_MAX;
        }
    }
}

SEC("raw_tp/kvm_exit")
#ifdef __TARGET_ARCH_arm64
void BPF_PROG(kvm_exit_pid, int ret, unsigned int esr_ec, unsigned long vcpu_pc)
#else
void BPF_PROG(kvm_exit_pid, u32 _exit_reason, void *vcpu, u32 _isa)
#endif
{
    static struct kvm_vcpu_event zero;
    struct kvm_vcpu_event *data;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid;

    if (filter_pid && (u32)(id >> 32) != filter_pid)
        return;

    pid = (u32)id;
    data = bpf_map_lookup_elem(&kvm_vcpu, &pid);
    if (!data) {
        bpf_map_update_elem(&kvm_vcpu, &pid, &zero, BPF_NOEXIST);
        data = bpf_map_lookup_elem(&kvm_vcpu, &pid);
        if (data) {
            data->tgid = (u32)(id >> 32);
            data->pid = (u32)id;
            data->isa = _isa;
        } else
            return;
    }
    data->exit_reason = _exit_reason;
    data->latency = bpf_ktime_get_ns();
}

SEC("raw_tp/kvm_entry")
void BPF_PROG(kvm_entry_pid) // int vcpu_id | unsigned long vcpu_pc
{
    u64 id = bpf_get_current_pid_tgid();
    struct kvm_vcpu_event *data;
    u32 pid;

    if (filter_pid && (u32)(id >> 32) != filter_pid)
        return;

    pid = (u32)id;
    data = bpf_map_lookup_elem(&kvm_vcpu, &pid);
    if (data) {
        data->latency = bpf_ktime_get_ns() - data->latency;
        if (data->latency > filter_latency)
            perf_output(ctx, data, offsetof(struct kvm_vcpu_event, run_delay));
    }
}

char LICENSE[] SEC("license") = "GPL";

