// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/tools/lib/string.c
 *
 *  Copied from linux/lib/string.c, where it is:
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  More specifically, the first copied function was strtobool, which
 *  was introduced by:
 *
 *  d0f1fed29e6e ("Add a strtobool function matching semantics of existing in kernel equivalents")
 *  Author: Jonathan Cameron <jic23@cam.ac.uk>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/compiler.h>

/**
 * memdup - duplicate region of memory
 *
 * @src: memory region to duplicate
 * @len: memory region length
 */
void *memdup(const void *src, size_t len)
{
	void *p = malloc(len);

	if (p)
		memcpy(p, src, len);

	return p;
}

/**
 * strtobool - convert common user inputs into boolean values
 * @s: input string
 * @res: result
 *
 * This routine returns 0 iff the first character is one of 'Yy1Nn0', or
 * [oO][NnFf] for "on" and "off". Otherwise it will return -EINVAL.  Value
 * pointed to by res is updated upon finding a match.
 */
int strtobool(const char *s, bool *res)
{
	if (!s)
		return -EINVAL;

	switch (s[0]) {
	case 'y':
	case 'Y':
	case '1':
		*res = true;
		return 0;
	case 'n':
	case 'N':
	case '0':
		*res = false;
		return 0;
	case 'o':
	case 'O':
		switch (s[1]) {
		case 'n':
		case 'N':
			*res = true;
			return 0;
		case 'f':
		case 'F':
			*res = false;
			return 0;
		default:
			break;
		}
	default:
		break;
	}

	return -EINVAL;
}

/**
 * strlcpy - Copy a C-string into a sized buffer
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @size: size of destination buffer
 *
 * Compatible with *BSD: the result is always a valid
 * NUL-terminated string that fits in the buffer (unless,
 * of course, the buffer size is zero). It does not pad
 * out the result like strncpy() does.
 *
 * If libc has strlcpy() then that version will override this
 * implementation:
 */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wignored-attributes"
#endif
size_t __weak strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}
#ifdef __clang__
#pragma clang diagnostic pop
#endif

/**
 * skip_spaces - Removes leading whitespace from @str.
 * @str: The string to be stripped.
 *
 * Returns a pointer to the first non-whitespace character in @str.
 */
char *skip_spaces(const char *str)
{
	while (isspace(*str))
		++str;
	return (char *)str;
}

/**
 * strim - Removes leading and trailing whitespace from @s.
 * @s: The string to be stripped.
 *
 * Note that the first trailing whitespace is replaced with a %NUL-terminator
 * in the given string @s. Returns a pointer to the first non-whitespace
 * character in @s.
 */
char *strim(char *s)
{
	size_t size;
	char *end;

	size = strlen(s);
	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	return skip_spaces(s);
}

/**
 * strreplace - Replace all occurrences of character in string.
 * @s: The string to operate on.
 * @old: The character being replaced.
 * @new: The character @old is replaced with.
 *
 * Returns pointer to the nul byte at the end of @s.
 */
char *strreplace(char *s, char old, char new)
{
	for (; *s; ++s)
		if (*s == old)
			*s = new;
	return s;
}

static void *check_bytes8(const u8 *start, u8 value, unsigned int bytes)
{
	while (bytes) {
		if (*start != value)
			return (void *)start;
		start++;
		bytes--;
	}
	return NULL;
}

/**
 * memchr_inv - Find an unmatching character in an area of memory.
 * @start: The memory area
 * @c: Find a character other than c
 * @bytes: The size of the area.
 *
 * returns the address of the first character other than @c, or %NULL
 * if the whole buffer contains just @c.
 */
void *memchr_inv(const void *start, int c, size_t bytes)
{
	u8 value = c;
	u64 value64;
	unsigned int words, prefix;

	if (bytes <= 16)
		return check_bytes8(start, value, bytes);

	value64 = value;
	value64 |= value64 << 8;
	value64 |= value64 << 16;
	value64 |= value64 << 32;

	prefix = (unsigned long)start % 8;
	if (prefix) {
		u8 *r;

		prefix = 8 - prefix;
		r = check_bytes8(start, value, prefix);
		if (r)
			return r;
		start += prefix;
		bytes -= prefix;
	}

	words = bytes / 8;

	while (words) {
		if (*(u64 *)start != value64)
			return check_bytes8(start, value, 8);
		start += 8;
		words--;
	}

	return check_bytes8(start, value, bytes % 8);
}

/**
 * strsize - Decimal string length.
 *
 * @u: 64-bit value to be converted to a decimal string.
 *
 * return the length of the string.
 */
int strsize(u64 u)
{
	static u64 table[] = {
		9UL,
		99UL,
		999UL,
		9999UL,
		99999UL,
		999999UL,
		9999999UL,
		99999999UL,
		999999999UL,
		9999999999UL,
		99999999999UL,
		999999999999UL,
		9999999999999UL,
		99999999999999UL,
		999999999999999UL,
		9999999999999999UL,
		99999999999999999UL,
		999999999999999999UL,
		9999999999999999999UL,
		UINT64_MAX
	};
	int i;
	for (i = 0 ; ; i ++) {
		if (u <= table[i])
			return i + 1;
	}
}

/**
 * stradd - a + b
 *
 * Return a new string, which needs to be freed.
 */
char *stradd(const char *a, const char *b)
{
	size_t sa = strlen(a);
	size_t sb = strlen(b);
	char *ptr = malloc(sa + sb + 1);

	if (ptr) {
		memcpy(ptr, a, sa);
		memcpy(ptr + sa, b, sb);
		ptr[sa + sb] = '\0';
	}
	return ptr;
}

/**
 * straddv - String addition.
 * @a: string a.
 * @freea: Always free string a.
 * @fmt: printf format string.
 * @ap: variable argument lists
 *
 * Returns the string a plus the formatted string.
 */
char *straddv(char *a, void (*freea)(void *), const char *fmt, va_list ap)
{
	va_list ap_saved;
	char tmp[256];
	int len;
	size_t sa;
	char *ptr = NULL;

	va_copy(ap_saved, ap);
	len = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	if (len < 0)
		goto end;

	sa = a ? strlen(a) : 0;
	ptr = malloc(sa + len + 1);
	if (!ptr)
		goto end;

	memcpy(ptr, a, sa);
	if (len >= sizeof(tmp)) {
		int len1 = vsnprintf(ptr + sa, len + 1, fmt, ap_saved);
		if (len1 < 0 || len1 != len) {
			free(ptr);
			ptr = NULL;
			goto end;
		}
	} else
		memcpy(ptr + sa, tmp, len);

	ptr[sa + len] = '\0';

end:
	if (freea)
		freea(a);
	va_end(ap_saved);
	return ptr;
}

/**
 * straddf - String addition.
 * @a: string a.
 * @freea: Always free string a.
 * @fmt: printf format string.
 * @...: variable argument lists
 *
 * Returns the string a plus the formatted string.
 */
char *straddf(char *a, void (*freea)(void *), const char *fmt, ...)
{
	va_list ap;
	char *ptr;

	va_start(ap, fmt);
	ptr = straddv(a, freea, fmt, ap);
	va_end(ap);
	return ptr;
}
