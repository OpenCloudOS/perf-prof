/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MATH64_H
#define _LINUX_MATH64_H

#include <linux/types.h>

#ifdef __x86_64__
static inline u64 mul_u64_u64_div64(u64 a, u64 b, u64 c)
{
	u64 q;

	asm ("mulq %2; divq %3" : "=a" (q)
				: "a" (a), "rm" (b), "rm" (c)
				: "rdx");

	return q;
}
#define mul_u64_u64_div64 mul_u64_u64_div64
#endif

#ifdef __SIZEOF_INT128__
static inline u64 mul_u64_u32_shr(u64 a, u32 b, unsigned int shift)
{
	return (u64)(((unsigned __int128)a * b) >> shift);
}

static inline u64 mul_u64_u64_shr(u64 a, u64 mul, unsigned int shift)
{
	return (u64)(((unsigned __int128)a * mul) >> shift);
}

#else

#ifdef __i386__
static inline u64 mul_u32_u32(u32 a, u32 b)
{
	u32 high, low;

	asm ("mull %[b]" : "=a" (low), "=d" (high)
			 : [a] "a" (a), [b] "rm" (b) );

	return low | ((u64)high) << 32;
}
#else
static inline u64 mul_u32_u32(u32 a, u32 b)
{
	return (u64)a * b;
}
#endif

static inline u64 mul_u64_u32_shr(u64 a, u32 b, unsigned int shift)
{
	u32 ah, al;
	u64 ret;

	al = a;
	ah = a >> 32;

	ret = mul_u32_u32(al, b) >> shift;
	if (ah)
		ret += mul_u32_u32(ah, b) << (32 - shift);

	return ret;
}

static inline u64 mul_u64_u64_shr(u64 a, u64 b, unsigned int shift)
{
	union {
		u64 ll;
		struct {
#ifdef __BIG_ENDIAN
			u32 high, low;
#else
			u32 low, high;
#endif
		} l;
	} rl, rm, rn, rh, a0, b0;
	u64 c;

	a0.ll = a;
	b0.ll = b;

	rl.ll = mul_u32_u32(a0.l.low, b0.l.low);
	rm.ll = mul_u32_u32(a0.l.low, b0.l.high);
	rn.ll = mul_u32_u32(a0.l.high, b0.l.low);
	rh.ll = mul_u32_u32(a0.l.high, b0.l.high);

	/*
	 * Each of these lines computes a 64-bit intermediate result into "c",
	 * starting at bits 32-95.  The low 32-bits go into the result of the
	 * multiplication, the high 32-bits are carried into the next step.
	 */
	rl.l.high = c = (u64)rl.l.high + rm.l.low + rn.l.low;
	rh.l.low = c = (c >> 32) + rm.l.high + rn.l.high + rh.l.low;
	rh.l.high = (c >> 32) + rh.l.high;

	/*
	 * The 128-bit result of the multiplication is in rl.ll and rh.ll,
	 * shift it right and throw away the high part of the result.
	 */
	if (shift == 0)
		return rl.ll;
	if (shift < 64)
		return (rl.ll >> shift) | (rh.ll << (64 - shift));
	return rh.ll >> (shift & 63);
}

#endif	/* __SIZEOF_INT128__ */

#ifndef mul_u64_u64_div64
static inline u64 mul_u64_u64_div64(u64 a, u64 b, u64 c)
{
	u64 quot, rem;

	quot = a / c;
	rem = a % c;

	return quot * b + (rem * b) / c;
}
#endif

#endif /* _LINUX_MATH64_H */
