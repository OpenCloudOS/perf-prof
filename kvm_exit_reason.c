#define VMX_EXIT_REASONS			\
	_ER(EXCEPTION_NMI,	 0)		\
	_ER(EXTERNAL_INTERRUPT,	 1)		\
	_ER(TRIPLE_FAULT,	 2)		\
	_ER(INIT_SIGNAL,	 3)		\
	_ER(PENDING_INTERRUPT,	 7)		\
	_ER(NMI_WINDOW,		 8)		\
	_ER(TASK_SWITCH,	 9)		\
	_ER(CPUID,		 10)		\
	_ER(HLT,		 12)		\
	_ER(INVD,		 13)		\
	_ER(INVLPG,		 14)		\
	_ER(RDPMC,		 15)		\
	_ER(RDTSC,		 16)		\
	_ER(VMCALL,		 18)		\
	_ER(VMCLEAR,		 19)		\
	_ER(VMLAUNCH,		 20)		\
	_ER(VMPTRLD,		 21)		\
	_ER(VMPTRST,		 22)		\
	_ER(VMREAD,		 23)		\
	_ER(VMRESUME,		 24)		\
	_ER(VMWRITE,		 25)		\
	_ER(VMOFF,		 26)		\
	_ER(VMON,		 27)		\
	_ER(CR_ACCESS,		 28)		\
	_ER(DR_ACCESS,		 29)		\
	_ER(IO_INSTRUCTION,	 30)		\
	_ER(MSR_READ,		 31)		\
	_ER(MSR_WRITE,		 32)		\
	_ER(INVALID_STATE,		 33)		\
	_ER(MSR_LOAD_FAIL,		 34)		\
	_ER(MWAIT_INSTRUCTION,	 36)		\
	_ER(MONITOR_TRAP_FLAG,	 37)		\
	_ER(MONITOR_INSTRUCTION, 39)		\
	_ER(PAUSE_INSTRUCTION,	 40)		\
	_ER(MCE_DURING_VMENTRY,	 41)		\
	_ER(TPR_BELOW_THRESHOLD, 43)		\
	_ER(APIC_ACCESS,	 44)		\
	_ER(EOI_INDUCED,	 45)		\
	_ER(GDTR_IDTR,	 46)		\
	_ER(LDTR_TR,	 47)		\
	_ER(EPT_VIOLATION,	 48)		\
	_ER(EPT_MISCONFIG,	 49)		\
	_ER(INVEPT,		 50)		\
	_ER(RDTSCP,		 51)		\
	_ER(PREEMPTION_TIMER,	 52)		\
	_ER(INVVPID,	 53)		\
	_ER(WBINVD,		 54)		\
	_ER(XSETBV,		 55)		\
	_ER(APIC_WRITE,		 56)		\
	_ER(RDRAND,		 57)		\
	_ER(INVPCID,		 58)		\
	_ER(VMFUNC,		 59)		\
	_ER(ENCLS,		 60)		\
	_ER(RDSEED,		 61)		\
	_ER(PML_FULL,		 62)		\
	_ER(XSAVES,		 63)		\
	_ER(XRSTORS,		 64)		\
	_ER(UMWAIT,		 67)		\
	_ER(TPAUSE,		 68)

#define SVM_EXIT_REASONS \
	_ER(EXIT_READ_CR0,	0x000)		\
	_ER(EXIT_READ_CR2,	0x002)		\
	_ER(EXIT_READ_CR3,	0x003)		\
	_ER(EXIT_READ_CR4,	0x004)		\
	_ER(EXIT_READ_CR8,	0x008)		\
	_ER(EXIT_WRITE_CR0,	0x010)		\
	_ER(EXIT_WRITE_CR2,	0x012)		\
	_ER(EXIT_WRITE_CR3,	0x013)		\
	_ER(EXIT_WRITE_CR4,	0x014)		\
	_ER(EXIT_WRITE_CR8,	0x018)		\
	_ER(EXIT_READ_DR0,	0x020)		\
	_ER(EXIT_READ_DR1,	0x021)		\
	_ER(EXIT_READ_DR2,	0x022)		\
	_ER(EXIT_READ_DR3,	0x023)		\
	_ER(EXIT_READ_DR4,	0x024)		\
	_ER(EXIT_READ_DR5,	0x025)		\
	_ER(EXIT_READ_DR6,	0x026)		\
	_ER(EXIT_READ_DR7,	0x027)		\
	_ER(EXIT_WRITE_DR0,	0x030)		\
	_ER(EXIT_WRITE_DR1,	0x031)		\
	_ER(EXIT_WRITE_DR2,	0x032)		\
	_ER(EXIT_WRITE_DR3,	0x033)		\
	_ER(EXIT_WRITE_DR4,	0x034)		\
	_ER(EXIT_WRITE_DR5,	0x035)		\
	_ER(EXIT_WRITE_DR6,	0x036)		\
	_ER(EXIT_WRITE_DR7,	0x037)		\
	_ER(EXIT_EXCP_DE,	0x040)		\
	_ER(EXIT_EXCP_DB,	0x041)		\
	_ER(EXIT_EXCP_BP,	0x043)		\
	_ER(EXIT_EXCP_OF,	0x044)		\
	_ER(EXIT_EXCP_BR,	0x045)		\
	_ER(EXIT_EXCP_UD,	0x046)		\
	_ER(EXIT_EXCP_NM,	0x047)		\
	_ER(EXIT_EXCP_DF,	0x048)		\
	_ER(EXIT_EXCP_TS,	0x04a)		\
	_ER(EXIT_EXCP_NP,	0x04b)		\
	_ER(EXIT_EXCP_SS,	0x04c)		\
	_ER(EXIT_EXCP_GP,	0x04d)		\
	_ER(EXIT_EXCP_PF,	0x04e)		\
	_ER(EXIT_EXCP_MF,	0x050)		\
	_ER(EXIT_EXCP_AC,	0x051)		\
	_ER(EXIT_EXCP_MC,	0x052)		\
	_ER(EXIT_EXCP_XF,	0x053)		\
	_ER(EXIT_INTR,		0x060)		\
	_ER(EXIT_NMI,		0x061)		\
	_ER(EXIT_SMI,		0x062)		\
	_ER(EXIT_INIT,		0x063)		\
	_ER(EXIT_VINTR,		0x064)		\
	_ER(EXIT_CR0_SEL_WRITE,	0x065)		\
	_ER(EXIT_IDTR_READ,	0x066)		\
	_ER(EXIT_GDTR_READ,	0x067)		\
	_ER(EXIT_LDTR_READ,	0x068)		\
	_ER(EXIT_TR_READ,	0x069)		\
	_ER(EXIT_IDTR_WRITE,	0x06a)		\
	_ER(EXIT_GDTR_WRITE,	0x06b)		\
	_ER(EXIT_LDTR_WRITE,	0x06c)		\
	_ER(EXIT_TR_WRITE,	0x06d)		\
	_ER(EXIT_RDTSC,		0x06e)		\
	_ER(EXIT_RDPMC,		0x06f)		\
	_ER(EXIT_PUSHF,		0x070)		\
	_ER(EXIT_POPF,		0x071)		\
	_ER(EXIT_CPUID,		0x072)		\
	_ER(EXIT_RSM,		0x073)		\
	_ER(EXIT_IRET,		0x074)		\
	_ER(EXIT_SWINT,		0x075)		\
	_ER(EXIT_INVD,		0x076)		\
	_ER(EXIT_PAUSE,		0x077)		\
	_ER(EXIT_HLT,		0x078)		\
	_ER(EXIT_INVLPG,	0x079)		\
	_ER(EXIT_INVLPGA,	0x07a)		\
	_ER(EXIT_IOIO,		0x07b)		\
	_ER(EXIT_MSR,		0x07c)		\
	_ER(EXIT_TASK_SWITCH,	0x07d)		\
	_ER(EXIT_FERR_FREEZE,	0x07e)		\
	_ER(EXIT_SHUTDOWN,	0x07f)		\
	_ER(EXIT_VMRUN,		0x080)		\
	_ER(EXIT_VMMCALL,	0x081)		\
	_ER(EXIT_VMLOAD,	0x082)		\
	_ER(EXIT_VMSAVE,	0x083)		\
	_ER(EXIT_STGI,		0x084)		\
	_ER(EXIT_CLGI,		0x085)		\
	_ER(EXIT_SKINIT,	0x086)		\
	_ER(EXIT_RDTSCP,	0x087)		\
	_ER(EXIT_ICEBP,		0x088)		\
	_ER(EXIT_WBINVD,	0x089)		\
	_ER(EXIT_MONITOR,	0x08a)		\
	_ER(EXIT_MWAIT,		0x08b)		\
	_ER(EXIT_MWAIT_COND,	0x08c)		\
	_ER(EXIT_XSETBV,	0x08d)		\
	_ER(EXIT_RDPRU,	0x08e)		\
	_ER(EXIT_INVPCID,	0x0a2)		\
	_ER(EXIT_NPF, 		0x400)		\
	_ER(EXIT_AVIC_INCOMPLETE_IPI,		0x401)	\
	_ER(EXIT_AVIC_UNACCELERATED_ACCESS,	0x402)	\
	_ER(EXIT_ERR,		-1)

#if defined(__aarch64__) || defined(__TARGET_ARCH_arm64)
#define ARM_EXIT_REASONS 				\
	_ER(ESR_ELx_EC_UNKNOWN,	0x00)		\
	_ER(ESR_ELx_EC_WFx,	0x01)			\
	_ER(ESR_ELx_EC_CP15_32,	0x03)		\
	_ER(ESR_ELx_EC_CP15_64,	0x04)		\
	_ER(ESR_ELx_EC_CP14_MR,	0x05)		\
	_ER(ESR_ELx_EC_CP14_LS,	0x06)		\
	_ER(ESR_ELx_EC_FP_ASIMD, 0x07)		\
	_ER(ESR_ELx_EC_CP10_ID, 0x08)		\
	_ER(ESR_ELx_EC_PAC, 0x09)			\
	_ER(ESR_ELx_EC_CP14_64, 0x0C)		\
	_ER(ESR_ELx_EC_ILL, 0x0E)			\
	_ER(ESR_ELx_EC_SVC32, 0x11)			\
	_ER(ESR_ELx_EC_HVC32, 0x12)			\
	_ER(ESR_ELx_EC_SMC32, 0x13)			\
	_ER(ESR_ELx_EC_SVC64, 0x15)			\
	_ER(ESR_ELx_EC_HVC64, 0x16)			\
	_ER(ESR_ELx_EC_SMC64, 0x17)			\
	_ER(ESR_ELx_EC_SYS64, 0x18)			\
	_ER(ESR_ELx_EC_SVE, 0x19)			\
	_ER(ESR_ELx_EC_ERET, 0x1a)			\
	_ER(ESR_ELx_EC_IMP_DEF, 0x1f)		\
	_ER(ESR_ELx_EC_IABT_LOW, 0x20)		\
	_ER(ESR_ELx_EC_IABT_CUR, 0x21)		\
	_ER(ESR_ELx_EC_PC_ALIGN, 0x22)		\
	_ER(ESR_ELx_EC_DABT_LOW, 0x24)		\
	_ER(ESR_ELx_EC_DABT_CUR, 0x25)		\
	_ER(ESR_ELx_EC_SP_ALIGN, 0x26)		\
	_ER(ESR_ELx_EC_FP_EXC32, 0x28)		\
	_ER(ESR_ELx_EC_FP_EXC64, 0x2C)		\
	_ER(ESR_ELx_EC_SERROR, 0x2F)		\
	_ER(ESR_ELx_EC_BREAKPT_LOW, 0x30)	\
	_ER(ESR_ELx_EC_BREAKPT_CUR, 0x31)	\
	_ER(ESR_ELx_EC_SOFTSTP_LOW, 0x32)	\
	_ER(ESR_ELx_EC_SOFTSTP_CUR, 0x33)	\
	_ER(ESR_ELx_EC_WATCHPT_LOW, 0x34)	\
	_ER(ESR_ELx_EC_WATCHPT_CUR, 0x35)	\
	_ER(ESR_ELx_EC_BKPT32, 0x38)		\
	_ER(ESR_ELx_EC_VECTOR32, 0x3A)		\
	_ER(ESR_ELx_EC_BRK64, 0x3C)			\
	_ER(ESR_ELx_EC_MAX, 0x3F)			\
	_ER(ARM_EXCEPTION_IRQ, ARM_EXCEPTION_REASON(ARM_EXCEPTION_IRQ))	\
	_ER(ARM_EXCEPTION_EL1_SERROR, ARM_EXCEPTION_REASON(ARM_EXCEPTION_EL1_SERROR))\
	_ER(ARM_EXCEPTION_IL, ARM_EXCEPTION_REASON(ARM_EXCEPTION_IL))	\
	_ER(ARM_EXCEPTION_HYP_GONE, ARM_EXCEPTION_REASON(ARM_EXCEPTION_HYP_GONE))
#else
#define ARM_EXIT_REASONS
#endif


#define _ER(reason, val)	{ #reason, val },
struct str_values {
	const char	*str;
	unsigned int val;
};

static struct str_values vmx_exit_reasons[] = {
	VMX_EXIT_REASONS
	{ NULL, -1}
};

static struct str_values svm_exit_reasons[] = {
	SVM_EXIT_REASONS
	{ NULL, -1}
};

static struct str_values arm_exit_reasons[] = {
	ARM_EXIT_REASONS
	{ NULL, -1}
};

static struct isa_exit_reasons {
	unsigned int isa;
	struct str_values *strings;
} isa_exit_reasons[] = {
	{ .isa = KVM_ISA_VMX, .strings = vmx_exit_reasons },
	{ .isa = KVM_ISA_SVM, .strings = svm_exit_reasons },
	{ .isa = KVM_ISA_ARM, .strings = arm_exit_reasons },
	{ }
};

const char *find_exit_reason(unsigned int isa, unsigned int val)
{
	struct str_values *strings = NULL;
	int i;

	for (i = 0; isa_exit_reasons[i].strings; ++i)
		if (isa_exit_reasons[i].isa == isa) {
			strings = isa_exit_reasons[i].strings;
			break;
		}
	if (!strings)
		return "UNKNOWN-ISA";
	for (i = 0; strings[i].str; i++)
		if (strings[i].val == val)
			break;

	return strings[i].str;
}

