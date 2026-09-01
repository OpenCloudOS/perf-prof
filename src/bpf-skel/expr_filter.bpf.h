#ifndef __EXPR_FILTER_BPF_H
#define __EXPR_FILTER_BPF_H

/*
 * Kernel-side expression filter for a BPF event source.
 *
 * Included from both sides: the BPF program uses DEFINE_EXPR_FILTER() to emit
 * the placeholder, userspace uses EXPR_FILTER_NAME to find it again.
 *
 * A BPF program that produces events is an event source like any other, so
 * it needs a filter layer. DEFINE_EXPR_FILTER() emits a placeholder whose
 * instructions are replaced at load time by code compiled from a user-supplied
 * C expression, in the window between bpf_object__open() and bpf_object__load()
 * -- i.e. before libbpf appends the subprog into its callers, so the
 * replacement may be a different length than the placeholder.
 *
 * Usage:
 *
 *     DEFINE_EXPR_FILTER(struct kvm_vcpu_event)
 *
 *     ... if (expr_filter(event)) perf_output(ctx, event, sizeof(*event));
 *
 * A BPF program defines exactly one event, so there is nothing to
 * disambiguate and the filter's name is fixed at EXPR_FILTER_FUNC rather than
 * being passed in. Userspace looks the placeholder up by that same name.
 *
 * The event type is named explicitly rather than taking a void *, because
 * userspace recovers it from BTF: it looks up FUNC EXPR_FILTER_FUNC, follows
 * FUNC_PROTO -> PTR -> STRUCT, and walks the members to learn each field's
 * name, offset and size. That is what lets an expression refer to fields by
 * name and compile down to BPF_LDX_MEM(size, dst, r1, offset). A void *
 * parameter would leave nothing to resolve.
 *
 * Requirements on the placeholder body, all of which cost real debugging to
 * rediscover:
 *
 *  - It must be __noinline so it stays a real subprog in .text. That alone
 *    is not enough: a plain `return 1` gets constant-folded and .text ends
 *    up empty, so the return value is laundered through asm volatile.
 *
 *  - It must not reference any global, which is why the constant is laundered
 *    rather than read from a `const volatile` variable. Such a variable lives
 *    in .rodata, and libbpf would re-apply the resulting map relocation on
 *    top of the replacement instructions, rewriting insn[0].imm to a map fd.
 *    The verifier then rejects it: "BPF_LDX uses reserved fields".
 *
 *  - It must consume `event`, otherwise clang treats the parameter as dead
 *    and stops materialising it in r1 at the call site. Generated code that
 *    dereferences r1 then faults the verifier with "R1 is not a pointer".
 *
 *  - Generated code must be at least as long as this placeholder (2 insns).
 *    libbpf relocates BTF line_info using the original instruction count but
 *    validates against the new program length, so a shorter replacement
 *    trips "Invalid line_info[N].insn_off". Any real expression needs at
 *    least a load and an exit, so this is satisfied in practice.
 *
 * The generated code receives the event pointer in r1 and returns its verdict
 * in r0: non-zero keeps the event, zero drops it. It may also store to the
 * event, so `event' must point to writable memory (see expr_to_bpf()).
 *
 * The default implementation accepts every event.
 */

/*
 * Fixed name of the filter placeholder. Defined here, and only here, because
 * both sides need to agree on it: the BPF program declares the function,
 * userspace looks it up by name in the object's BTF.
 */
#define EXPR_FILTER_FUNC  expr_filter
/* Two levels: the inner macro would otherwise stringize the parameter's own
 * name rather than what it expands to. */
#define EXPR_FILTER_STR__(x)  #x
#define EXPR_FILTER_STR_(x)   EXPR_FILTER_STR__(x)
#define EXPR_FILTER_NAME  EXPR_FILTER_STR_(EXPR_FILTER_FUNC)

/* Only the BPF side can define the placeholder; userspace just needs the name
 * above, and including bpf_helpers.h there would not even compile. */
#ifdef __BPF__
#include <bpf/bpf_helpers.h>

#define DEFINE_EXPR_FILTER(event_type)                          \
    static __noinline int EXPR_FILTER_FUNC(event_type *event)    \
    {                                                           \
        int ret = 1;                                            \
                                                                \
        asm volatile("" : "+r"(ret) : "r"(event));               \
        return ret;                                             \
    }
#endif

#endif