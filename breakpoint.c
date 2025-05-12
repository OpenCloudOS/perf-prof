#include <stdlib.h>
#include <pthread.h>
#include <linux/bitops.h>
#include <asm/perf_regs.h>
#include <linux/hw_breakpoint.h>
#include <monitor.h>
#include <stack_helpers.h>
#include <trace_helpers.h>

#if defined(__i386__) || defined(__x86_64__)
#define REG_NOSUPPORT_N 4
#define REG_NOSUPPORT ((1ULL << PERF_REG_X86_DS) | \
		       (1ULL << PERF_REG_X86_ES) | \
		       (1ULL << PERF_REG_X86_FS) | \
		       (1ULL << PERF_REG_X86_GS))
#if defined(__i386__)
#define PERF_REGS_MASK (((1ULL << PERF_REG_X86_32_MAX) - 1) & ~REG_NOSUPPORT)
#else
#define PERF_REGS_MASK (((1ULL << PERF_REG_X86_64_MAX) - 1) & ~REG_NOSUPPORT)
#endif

#include <asm/insn.h>

#elif defined(__aarch64__)
#define PERF_REGS_MASK ((1ULL << PERF_REG_ARM64_MAX) - 1)
#endif


#define HBP_NUM 4

static profiler breakpoint;

struct hw_breakpoint {
    unsigned long address;
    u8 len;
    u8 type;
    char typestr[4];
};

struct insn_decode_ctxt {
    struct hw_breakpoint *bp;
    u64 addr;
    u64 data;
    /*
     * Data is safe: all write instructions are decoded.
     * MOV: Safe.
     * ADD: Unsafe, unless a safe instruction occurs before ADD.
     */
    bool safety;
};

static struct hw_breakpoint hwbp[HBP_NUM];
struct breakpoint_ctx {
    struct hw_breakpoint hwbp[HBP_NUM];
    struct insn_decode_ctxt ctxt[HBP_NUM];
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    bool print_ip;
    bool ip_sym;
    bool kcore;
};

static int monitor_ctx_init(struct prof_dev *dev)
{
    int i;
    struct env *env = dev->env;
    struct breakpoint_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    for (i = 0; i < HBP_NUM; i++) {
        ctx->hwbp[i] = hwbp[i];
        if (ctx->hwbp[i].type == HW_BREAKPOINT_W) {
            ctx->kcore = 1;
            ctx->ctxt[i].bp = &ctx->hwbp[i];
            /*
             * We need to ensure the order of write instructions
             * so that we can safely obtain all written values.
             */
            env->order = 1;
        }
    }

    ctx->print_ip = 1;
    if (env->callchain) {
        if (!env->flame_graph) {
            ctx->cc = callchain_ctx_new(callchain_flags(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER), stdout);
            ctx->print_ip = 0;
        } else
            ctx->flame = flame_graph_open(callchain_flags(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER), env->flame_graph);
        dev->pages *= 2;
    }

    if (ctx->print_ip) {
        ctx->cc = callchain_ctx_new(CALLCHAIN_KERNEL | CALLCHAIN_USER, stdout);
        callchain_ctx_config(ctx->cc, 0, 1, 1, 0, 0, '\n', '\n');
    }

    if (ctx->kcore)
        kcore_ref();

    tep__ref();
    return 0;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct breakpoint_ctx *ctx = dev->private;
    tep__unref();
    if (ctx->kcore)
        kcore_unref();
    callchain_ctx_free(ctx->cc);
    flame_graph_output(ctx->flame);
    flame_graph_close(ctx->flame);
    free(ctx);
}

static int breakpoint_argc_init(int argc, char *argv[])
{
    int i, j;

    if (argc < 1) {
        fprintf(stderr, " <addr> needs to be specified.\n");
        help();
    }
    if (argc > HBP_NUM) {
        fprintf(stderr, " Up to %d breakpoints are supported.\n", HBP_NUM);
        help();
    }

    for (i = 0; i < argc; i++) {
        char *p, *s = strdup(argv[i]);
        int tk = *s;
        unsigned long value = tk - '0';
        u8 len = 1;
        u8 type = HW_BREAKPOINT_W;

        p = s + 1;
        if (value) {
            while (*p >= '0' && *p <= '9') value = value * 10 + *p++ - '0';
        } else if (*p == 'x' || *p == 'X') {
            while ((tk = *++p) && ((tk >= '0' && tk <= '9') || (tk >= 'a' && tk <= 'f') || (tk >= 'A' && tk <= 'F')))
                value = value * 16 + (tk & 15) + (tk >= 'A' ? 9 : 0);
        } else {
            fprintf(stderr, " <addr> is not decimal or hexadecimal.");
            help();
        }

        if (*p == '/') {
            ++p;
            if (*p >= '0' && *p <= '9')
                len = *p++ - '0';
        }
        if (*p == ':') {
            ++p;
            if (*p) type = 0;
            while (*p) {
                if (*p == 'r') type |=  HW_BREAKPOINT_R;
                else if (*p == 'w') type |= HW_BREAKPOINT_W;
                else if (*p == 'x') type |= HW_BREAKPOINT_X;
                else break;
                p++;
            }
        }
        if (*p) {
            fprintf(stderr, " <addr> parsing error.");
            help();
        }

        if (type & HW_BREAKPOINT_R)
            type |= HW_BREAKPOINT_W;

        if (type & HW_BREAKPOINT_X) {
            len = sizeof(long);
            type = HW_BREAKPOINT_X;
        }

        hwbp[i].address = value;
        hwbp[i].len = len;
        hwbp[i].type = type;
        j = 0;
        if (type & HW_BREAKPOINT_R) hwbp[i].typestr[j++] = 'R';
        if (type & HW_BREAKPOINT_W) hwbp[i].typestr[j++] = 'W';
        if (type & HW_BREAKPOINT_X) hwbp[i].typestr[j++] = 'X';
        hwbp[i].typestr[j] = '\0';

        free(s);
    }

    return 0;
}

static int breakpoint_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
    struct breakpoint_ctx *ctx;
    struct perf_event_attr attr = {
        .type        = PERF_TYPE_BREAKPOINT,
        .config      = 0,
        .size        = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU |
                       (env->callchain ? PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_INTR : 0),
        .read_format = 0,
        .sample_regs_intr = PERF_REGS_MASK,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_user  = env->exclude_user,
        .exclude_kernel = env->exclude_kernel,
        .exclude_callchain_user = exclude_callchain_user(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .exclude_callchain_kernel = exclude_callchain_kernel(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int i;

    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;

    prof_dev_env2attr(dev, &attr);

    if (!attr.watermark)
        ctx->ip_sym = 1;

    for (i = 0; i < HBP_NUM; i++) {
        if (ctx->hwbp[i].address) {
            if (env->verbose)
                printf("%p len %d type %d\n", (void *)ctx->hwbp[i].address, ctx->hwbp[i].len, ctx->hwbp[i].type);

            attr.bp_addr = ctx->hwbp[i].address;
            attr.bp_type = ctx->hwbp[i].type;
            attr.bp_len = ctx->hwbp[i].len;

            evsel = perf_evsel__new(&attr);
            if (!evsel)
                goto failed;

            perf_evlist__add(evlist, evsel);
        } else
            break;
    }
    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static void breakpoint_deinit(struct prof_dev *dev)
{
    monitor_ctx_exit(dev);
}

struct sample_regs_intr {
    u64     abi;
    u64     regs[hweight64(PERF_REGS_MASK)];
};

static void print_regs_intr(struct sample_regs_intr *regs_intr, u64 unused)
{
#if defined(__i386__) || defined(__x86_64__)
#define REG(r) regs_intr->regs[PERF_REG_X86_##r - (PERF_REG_X86_##r > PERF_REG_X86_DS ? REG_NOSUPPORT_N : 0)]
    printf("      RIP: %016lx RSP: %016lx RFLAGS:%08lx\n", REG(IP), REG(SP), REG(FLAGS));
    printf("      RAX: %016lx RBX: %016lx RCX: %016lx\n", REG(AX), REG(BX), REG(CX));
    printf("      RDX: %016lx RSI: %016lx RDI: %016lx\n", REG(DX), REG(SI), REG(DI));

#if defined(__i386__)
    printf("      RBP: %016lx CS: %04lx SS: %04lx\n", REG(BP), REG(CS), REG(SS));
#else
    printf("      RBP: %016lx R08: %016lx R09: %016lx\n", REG(BP), REG(R8), REG(R9));
    printf("      R10: %016lx R11: %016lx R12: %016lx\n", REG(R10), REG(R11), REG(R12));
    printf("      R13: %016lx R14: %016lx R15: %016lx\n", REG(R13), REG(R14), REG(R15));
    printf("      CS: %04lx SS: %04lx\n", REG(CS), REG(SS));
#endif

#elif defined(__aarch64__)
#define REG(r) regs_intr->regs[PERF_REG_ARM64_##r]
    printf("      X00: %016lx X01: %016lx X02: %016lx X03: %016lx\n", REG(X0), REG(X1), REG(X2), REG(X3));
    printf("      X04: %016lx X05: %016lx X06: %016lx X07: %016lx\n", REG(X4), REG(X5), REG(X6), REG(X7));
    printf("      X08: %016lx X09: %016lx X10: %016lx X11: %016lx\n", REG(X8), REG(X9), REG(X10), REG(X11));
    printf("      X12: %016lx X13: %016lx X14: %016lx X15: %016lx\n", REG(X12), REG(X13), REG(X14), REG(X15));
    printf("      X16: %016lx X17: %016lx X18: %016lx X19: %016lx\n", REG(X16), REG(X17), REG(X18), REG(X19));
    printf("      X20: %016lx X21: %016lx X22: %016lx X23: %016lx\n", REG(X20), REG(X21), REG(X22), REG(X23));
    printf("      X24: %016lx X25: %016lx X26: %016lx X27: %016lx\n", REG(X24), REG(X25), REG(X26), REG(X27));
    printf("      X28: %016lx X29: %016lx LR: %016lx\n", REG(X28), REG(X29), REG(LR));
    printf("      SP: %016lx PC: %016lx\n", REG(SP), REG(PC));
#endif
}

#if defined(__i386__) || defined(__x86_64__)

#define byte_mask(n) ((1UL << 8*(n))-1)

static u64 reg_read(struct sample_regs_intr *regs_intr, int reg)
{
    switch (reg)
    {
        case 0: return regs_intr->regs[PERF_REG_X86_AX];
        case 1: return regs_intr->regs[PERF_REG_X86_CX];
        case 2: return regs_intr->regs[PERF_REG_X86_DX];
        case 3: return regs_intr->regs[PERF_REG_X86_BX];
        case 4: return regs_intr->regs[PERF_REG_X86_SP];
        case 5: return regs_intr->regs[PERF_REG_X86_BP];
        case 6: return regs_intr->regs[PERF_REG_X86_SI];
        case 7: return regs_intr->regs[PERF_REG_X86_DI];
        case 8: return regs_intr->regs[PERF_REG_X86_R8-REG_NOSUPPORT_N];
        case 9: return regs_intr->regs[PERF_REG_X86_R9-REG_NOSUPPORT_N];
        case 10: return regs_intr->regs[PERF_REG_X86_R10-REG_NOSUPPORT_N];
        case 11: return regs_intr->regs[PERF_REG_X86_R11-REG_NOSUPPORT_N];
        case 12: return regs_intr->regs[PERF_REG_X86_R12-REG_NOSUPPORT_N];
        case 13: return regs_intr->regs[PERF_REG_X86_R13-REG_NOSUPPORT_N];
        case 14: return regs_intr->regs[PERF_REG_X86_R14-REG_NOSUPPORT_N];
        case 15: return regs_intr->regs[PERF_REG_X86_R15-REG_NOSUPPORT_N];
        default: return regs_intr->regs[PERF_REG_X86_IP];
    }
}

static s32 disp(struct insn *insn)
{
    return insn->displacement.got ? insn->displacement.value : 0;
}

static u64 decode_modrm(struct insn *insn, struct sample_regs_intr *regs_intr)
{
    u8 rex_prefix = insn->rex_prefix.got ? insn->rex_prefix.bytes[0] : 0;
    int modrm_reg, index_reg, base_reg, scale;
    int modrm_mod, modrm_rm;
    u64 addr = 0UL;

    modrm_reg = ((rex_prefix << 1) & 8); /* REX.R */
    index_reg = (rex_prefix << 2) & 8; /* REX.X */
    base_reg = (rex_prefix << 3) & 8; /* REX.B */

    modrm_mod = X86_MODRM_MOD(insn->modrm.bytes[0]);
    modrm_reg = modrm_reg | X86_MODRM_REG(insn->modrm.bytes[0]);
    modrm_rm = base_reg | X86_MODRM_RM(insn->modrm.bytes[0]);
    if (modrm_mod == 3)
        return 0UL;

    /* 32/64-bit ModR/M decode. */
    if ((modrm_rm & 7) == 4) {
        u8 sib = insn->sib.bytes[0];
        index_reg |= (sib >> 3) & 7;
        base_reg |= sib & 7;
        scale = sib >> 6;

        if ((base_reg & 7) == 5 && modrm_mod == 0)
            addr += disp(insn);
        else
            addr += reg_read(regs_intr, base_reg);

        if (index_reg != 4)
            addr += reg_read(regs_intr, index_reg) << scale;
    } else if ((modrm_rm & 7) == 5 && modrm_mod == 0) {
        addr += disp(insn);
        if (insn->x86_64) // RIP-Relative Addressing
            addr += reg_read(regs_intr, 16 /* rIP */);
    } else {
        base_reg = modrm_rm;
        addr += reg_read(regs_intr, base_reg);
    }

    if (modrm_mod == 1 || modrm_mod == 2)
        addr += disp(insn);

    return addr;
}

static u64 decode_mem_abs(struct insn *insn)
{
    u64 addr;

    addr = insn->moffset2.got ? insn->moffset2.value : 0UL;
    addr = (addr << 32) | (insn->moffset1.got ? insn->moffset1.value : 0UL);

    return addr;
}

static u64 decode_opsrc_reg(struct insn *insn, struct sample_regs_intr *regs_intr, bool byteop)
{
    int bytes = byteop ? 1 : insn->opnd_bytes;
    u8 rex_prefix = insn->rex_prefix.got ? insn->rex_prefix.bytes[0] : 0;
    int highbyte_regs = (rex_prefix == 0) && byteop;
    int modrm_reg;
    u64 data;

    modrm_reg = ((rex_prefix << 1) & 8); /* REX.R */
    modrm_reg = modrm_reg | X86_MODRM_REG(insn->modrm.bytes[0]);

    if (highbyte_regs && modrm_reg >= 4 && modrm_reg < 8)
        data = reg_read(regs_intr, modrm_reg & 3) >> 8;
    else
        data = reg_read(regs_intr, modrm_reg);

    return bytes == 8 ? data : (data & byte_mask(bytes));
}

static u64 decode_opsrc_Acc(struct insn *insn, struct sample_regs_intr *regs_intr, bool byteop)
{
    int bytes = byteop ? 1 : insn->opnd_bytes;
    u64 data = reg_read(regs_intr, 0); // AL/rAX
    return bytes == 8 ? data : (data & byte_mask(bytes));
}

static u64 decode_opsrc_Imm(struct insn *insn, bool byteop, bool sign_extension)
{
    int bytes = byteop ? 1 : insn->opnd_bytes;
    int size = bytes == 8 ? 4 : bytes;
    u64 data;

    data = insn->immediate2.got ? (s64)insn->immediate2.value : 0UL;
    data = (data << 32) | (insn->immediate1.got ? (s64)insn->immediate1.value : 0UL);

    if (!sign_extension)
        data = data & byte_mask(size);

    return data;
}

static u64 decode_addr(struct insn *insn, struct sample_regs_intr *regs_intr)
{
    switch (insn->opcode.bytes[0])
    {
        // MOV
        case 0x88: // MOV Eb,Gb
        case 0x89: // MOV Ev,Gv
        case 0xC6: // Grp11 Eb,Ib (1A)
        case 0xC7: // Grp11 Ev,Iz (1A)
            return decode_modrm(insn, regs_intr);
        case 0xA2: // MOV Ob,AL
        case 0xA3: // MOV Ov,rAX
            return decode_mem_abs(insn);

        // ADD
        case 0x00: // ADD Eb,Gb         Add r8 to r/m8
        case 0x01: // ADD Ev,Gv         Add r64 to r/m64
        case 0x80: // Grp1 Eb,Ib (1A)   Add/Sub/.. imm8 to r/m8.
        case 0x81: // Grp1 Ev,Iz (1A)   Add/Sub/.. imm32 to r/m32.
        case 0x83: // Grp1 Ev,Ib (1A)   Add/Sub/.. sign-extended imm8 to r/m64

        // SUB
        case 0x28: // SUB Eb,Gb
        case 0x29: // SUB Ev,Gv
            return decode_modrm(insn, regs_intr);

        default:
            return 0UL;
    }
}

static u64 decode_data(struct insn *insn, struct sample_regs_intr *regs_intr, u64 old)
{
    int op = insn->opcode.bytes[0];
    int opext = 0;
    u64 data;
    int bytes = insn->opnd_bytes;
    static const void * const grp1_tbl[8] = {
        [0 ... 7] = && default_label,
        [0] = &&ADD,
        [5] = &&SUB,
    };

    switch (op)
    {
        // MOV
        case 0x88: /* MOV Eb,Gb  */ return decode_opsrc_reg(insn, regs_intr, 1);
        case 0x89: /* MOV Ev,Gv  */ return decode_opsrc_reg(insn, regs_intr, 0);
        case 0xA2: /* MOV Ob,AL  */ return decode_opsrc_Acc(insn, regs_intr, 1);
        case 0xA3: /* MOV Ov,rAX */ return decode_opsrc_Acc(insn, regs_intr, 0);
        case 0xC6: /* Grp11 Eb,Ib (1A) */ return decode_opsrc_Imm(insn, 1, 1);
        case 0xC7: /* Grp11 Ev,Iz (1A) */ return decode_opsrc_Imm(insn, 0, 1);

        // ADD
        case 0x00: /* ADD Eb,Gb */ data = decode_opsrc_reg(insn, regs_intr, 1); bytes = 1; goto ADD;
        case 0x01: /* ADD Ev,Gv */ data = decode_opsrc_reg(insn, regs_intr, 0);            goto ADD;
        case 0x80: /* Grp1 Eb,Ib (1A) */
        case 0x81: /* Grp1 Ev,Iz (1A) */
        case 0x83: /* Grp1 Ev,Ib (1A) */
            if (op == 0x80 || op == 0x83)
                bytes = 1;
            data = decode_opsrc_Imm(insn, bytes == 1, 1);
            opext = X86_MODRM_REG(insn->modrm.bytes[0]);
            goto *grp1_tbl[opext];
        ADD:
            data = old + data;
            break;

        // SUB
        case 0x28: /* SUB Eb,Gb */ data = decode_opsrc_reg(insn, regs_intr, 1); bytes = 1; goto SUB;
        case 0x29: /* SUB Ev,Gv */ data = decode_opsrc_reg(insn, regs_intr, 0);            goto SUB;
        SUB:
            data = old - data;
            break;

        default_label:
        default: return 0UL;
    }
    return bytes == 8 ? data : (data & byte_mask(bytes));
}

static bool safety(struct insn *insn)
{
    switch (insn->opcode.bytes[0])
    {
        case 0x88: // MOV Eb,Gb
        case 0x89: // MOV Ev,Gv
        case 0xA2: // MOV Ob,AL
        case 0xA3: // MOV Ov,rAX
        case 0xC6: // Grp11 Eb,Ib (1A)
        case 0xC7: // Grp11 Ev,Iz (1A)
            return true;
        default:
            return false;
    }
}

static bool supported(struct insn_decode_ctxt *ctxt, struct insn *insn)
{
    struct hw_breakpoint *bp = ctxt->bp;
    int op, opext;

    if (bp->type != HW_BREAKPOINT_W)
        return false;
    if (bp->len != 1 && insn->opnd_bytes != bp->len)
        return false;
    if (!insn->opcode.got)
        return false;
    if (insn->opcode.nbytes != 1) // only one-byte opcode
        return false;
    if (!insn->modrm.got || !insn->modrm.nbytes)
        return false;

    op = insn->opcode.bytes[0];
    switch (op)
    {
        // MOV
        case 0x88: // MOV Eb,Gb.        Move r8 to r/m8.
        case 0xA2: // MOV Ob,AL.        Move AL to (seg:offset)
            if (bp->len != 1) return false;
        case 0x89: // MOV Ev,Gv.        Move r64 to r/m64.
        case 0xA3: // MOV Ov,rAX.       Move RAX to (offset)
            break;
        case 0xC6: // Grp11 Eb,Ib (1A). Move imm8 to r/m8
        case 0xC7: // Grp11 Ev,Iz (1A). Move imm32 to r/m32
            opext = X86_MODRM_REG(insn->modrm.bytes[0]);
            if (opext != 0) // ! MOV
                return false;
            if (op == 0xC6 && bp->len != 1) // Eb
                return false;
            break;

        // ADD
        case 0x00: // ADD Eb,Gb         Add r8 to r/m8
            if (bp->len != 1) return false;
        case 0x01: // ADD Ev,Gv         Add r64 to r/m64
            break;
        case 0x80: // Grp1 Eb,Ib (1A)   Add/Sub/.. imm8 to r/m8.
        case 0x81: // Grp1 Ev,Iz (1A)   Add/Sub/.. imm32 to r/m32.
        case 0x83: // Grp1 Ev,Ib (1A)   Add/Sub/.. sign-extended imm8 to r/m64
            opext = X86_MODRM_REG(insn->modrm.bytes[0]);
            // 0:ADD, 1:OR, 2:ADC, 3:SBB, 4:AND, 5:SUB, 6:XOR, 7:CMP;
            if (opext != 0 && opext != 5) // ! ADD SUB
                return false;
            if (op == 0x80 && bp->len != 1) // Eb
                return false;
            break;

        // SUB
        case 0x28: // SUB Eb,Gb
            if (bp->len != 1) return false;
        case 0x29: // SUB Ev,Gv
            break;

        default:
            return false;
    }
    if (!safety(insn) && !ctxt->safety)
        return false;

    return true;
}

static void x86_decode_insn(struct insn_decode_ctxt *ctxt, u64 ip, struct sample_regs_intr *regs_intr)
{
    unsigned char in[15];
    int in_len = sizeof(in);
    struct insn insn;
    enum insn_mode mode;
    int i;
    bool safety = 0;

    if (regs_intr->abi == PERF_SAMPLE_REGS_ABI_NONE)
        return;

    if (kcore_read(ip - in_len /* Trap */, in, in_len) != in_len)
        return;

    mode = regs_intr->abi == PERF_SAMPLE_REGS_ABI_64 ? INSN_MODE_64 : INSN_MODE_32;
    for (i = in_len - 1; i >= 0; i--) {
        if (insn_decode(&insn, in + i, in_len - i, mode) < 0)
            continue;
        if (insn.length != in_len - i)
            continue;

        // Only supports destination memory operand.
        if (!supported(ctxt, &insn))
            continue;

        // Decode the memory address of the destination operand.
        ctxt->addr = decode_addr(&insn, regs_intr);
        if (ctxt->addr != ctxt->bp->address)
            continue;

        // Decode the data of the source operand.
        ctxt->data = decode_data(&insn, regs_intr, ctxt->data);
        safety = 1;

        printf("      INSN: ");
        for (; i < in_len; i++)
            printf("%02x ", in[i]);
        printf(" ADDR: %lx  DATA: %lx\n", ctxt->addr, ctxt->data);
        break;
    }

    ctxt->safety = safety;
}

#endif

static void breakpoint_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct breakpoint_ctx *ctx = dev->private;
    // in linux/perf_event.h
    // PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU | PERF_SAMPLE_CALLCHAIN |
    // PERF_SAMPLE_REGS_INTR
    struct sample_type_data {
        __u64   ip;
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        __u64   time;
        __u64   addr;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        struct callchain callchain;
    } *data = (void *)event->sample.array;
    struct {
        __u64 nr;
        __u64 ips[2];
    } callchain;
    struct sample_regs_intr *regs_intr;
    int i;

    for (i = 0; i < HBP_NUM; i++) {
        if (ctx->hwbp[i].address == data->addr)
            break;
    }

    if (dev->print_title) prof_dev_print_time(dev, data->time, stdout);
    tep__update_comm(NULL, data->tid_entry.tid);
    printf("%16s %6u [%03d] %llu.%06llu: breakpoint: 0x%llx/%d:%s%s", tep__pid_to_comm(data->tid_entry.tid), data->tid_entry.tid,
            data->cpu_entry.cpu, data->time/NSEC_PER_SEC, (data->time%NSEC_PER_SEC)/1000,
            data->addr, ctx->hwbp[i].len, ctx->hwbp[i].typestr, ctx->print_ip?" ip ":"\n");

    if (ctx->print_ip) {
        if (ctx->ip_sym || data->ip >= START_OF_KERNEL) {
            callchain.nr = 2;
            callchain.ips[0] = data->ip >= START_OF_KERNEL ? PERF_CONTEXT_KERNEL : PERF_CONTEXT_USER;
            callchain.ips[1] = data->ip;
            print_callchain(ctx->cc, (struct callchain *)&callchain, data->tid_entry.pid);
        } else
            printf("%016llx\n", data->ip);
    }

    if (dev->env->callchain) {
        regs_intr = (struct sample_regs_intr *)&data->callchain.ips[data->callchain.nr];

        if (ctx->kcore && ctx->hwbp[i].type == HW_BREAKPOINT_W) {
            #if defined(__i386__) || defined(__x86_64__)
            /*
             * Decode the instruction and get the value written to data->addr.
             *
             * You cannot directly use kcore_read to read the value of data->addr
             * because it may change. Currently, kcore_read() reads instructions,
             * which generally do not change, and decode the source operands.
             */
            // Instruction breakpoint, Exception Class: Fault.
            // Data write breakpoint,  Exception Class: Trap.
            x86_decode_insn(&ctx->ctxt[i], data->ip, regs_intr);
            #endif
        }

        if (!dev->env->flame_graph)
            print_callchain_common_cbs(ctx->cc, &data->callchain, data->tid_entry.pid, (callchain_cbs)print_regs_intr, NULL, regs_intr);
        else
            flame_graph_add_callchain(ctx->flame, &data->callchain, data->tid_entry.pid, NULL);
    }
}

static const char *breakpoint_desc[] = PROFILER_DESC("breakpoint",
    "[OPTION...] [-g [--flame-graph file]] <addr>[/1/2/4/8][:rwx] ...",
    "Kernel/user-space hardware breakpoint facility.",
    "",
    "SYNOPSIS",
    "    HW_breakpoint: a unified kernel/user-space hardware breakpoint facility",
    "    using the CPU's debug registers.",
    "",
    "    Each process has a maximum of 4 breakpoints.",
    "",
    "EXAMPLES",
    "    "PROGRAME" breakpoint 0x7ffd8c7dae28 -g",
    "    "PROGRAME" breakpoint 0x7ffd8c7dae28/8:w");
static const char *breakpoint_argv[] = PROFILER_ARGV("breakpoint",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_CALLCHAIN_FILTER, "exclude-user", "exclude-kernel",
    PROFILER_ARGV_PROFILER, "call-graph", "flame-graph");
static profiler breakpoint = {
    .name = "breakpoint",
    .desc = breakpoint_desc,
    .argv = breakpoint_argv,
    .pages = 1,
    .argc_init = breakpoint_argc_init,
    .init = breakpoint_init,
    .deinit = breakpoint_deinit,
    .sample = breakpoint_sample,
};
PROFILER_REGISTER(breakpoint)

