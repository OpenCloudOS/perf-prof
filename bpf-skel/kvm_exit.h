#ifndef __KVM_EXIT_H
#define __KVM_EXIT_H

struct kvm_vcpu_event
{
    uint32_t tgid, pid;
    uint32_t isa;   //KVM_ISA_VMX  KVM_ISA_SVM
    uint32_t exit_reason;
    int64_t latency;
    int64_t sched_latency;
};

#define KVM_ISA_VMX   1
#define KVM_ISA_SVM   2
#define KVM_ISA_ARM   3

#define EXIT_REASON_HLT        12     // intel
#define SVM_EXIT_HLT           0x078  // amd
#define ARM_EXIT_HLT           0x01   // arm64

#if defined(__aarch64__) || defined(__TARGET_ARCH_arm64)

#define ARM_EXIT_WITH_SERROR_BIT  31
#define ARM_EXCEPTION_CODE(x)     ((x) & ~(1U << ARM_EXIT_WITH_SERROR_BIT))
#define ARM_EXCEPTION_IS_TRAP(x)  (ARM_EXCEPTION_CODE((x)) == ARM_EXCEPTION_TRAP)
#define ARM_SERROR_PENDING(x)     !!((x) & (1U << ARM_EXIT_WITH_SERROR_BIT))

#define ARM_EXCEPTION_IRQ         0
#define ARM_EXCEPTION_EL1_SERROR  1
#define ARM_EXCEPTION_TRAP        2
#define ARM_EXCEPTION_IL          3
/* The hyp-stub will return this for any kvm_call_hyp() call */
#define ARM_EXCEPTION_HYP_GONE    HVC_STUB_ERR

#define HVC_STUB_ERR      0xbadca11

#define ARM_EXCEPTION_REASON(exit_code) (0x80000000 | (exit_code))

#define EXIT_REASON(exit_code, esr_ec) \
    (ARM_EXCEPTION_IS_TRAP(exit_code) ? esr_ec : ARM_EXCEPTION_REASON(exit_code))

#endif

#endif
