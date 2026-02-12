// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "event-utils.h"
#include "event-parse.h"
#include "kbuffer.h"

#define __weak __attribute__((weak))

static int log_level = TEP_LOG_CRITICAL;

/**
 * tep_set_loglevel - set log level of the library
 * @level: desired level of the library messages
 */
void tep_set_loglevel(enum tep_loglevel level)
{
	log_level = level;
}

/**
 * tep_vprint - print library log messages
 * @name: name of the library.
 * @level: severity of the log message. This parameter is not used in this implementation, but as
 *	   the function is weak and can be overridden, having the log level could be useful
 *	   for other implementations.
 * @print_err: whether to print the errno, if non zero.
 * @fmt: printf format string of the message.
 * @ap: list of printf parameters.
 *
 * This function is used to print all messages from traceevent, tracefs and trace-cmd libraries.
 * It is defined as weak, so the application that uses those libraries can override it in order
 * to implement its own logic for printing library logs.
 *
 * Return the value of errno at the function enter.
 */
int __weak tep_vprint(const char *name, enum tep_loglevel level,
		      bool print_err, const char *fmt, va_list ap)
{
	return __tep_vprint(name, level, print_err, fmt, ap);
}

/**
 * __tep_vprint - print library log messages
 * @name: name of the library.
 * @level: severity of the log message. This parameter is not used in this implementation, but as
 *	   the function is weak and can be overridden, having the log level could be useful
 *	   for other implementations.
 * @print_err: whether to print the errno, if non zero.
 * @fmt: printf format string of the message.
 * @ap: list of printf parameters.
 *
 * This function is used to print all messages from traceevent, tracefs and trace-cmd libraries.
 * It is defined as weak, so the application that uses those libraries can override it in order
 * to implement its own logic for printing library logs.
 *
 * Return the value of errno at the function enter.
 */
int __tep_vprint(const char *name, enum tep_loglevel level,
		      bool print_err, const char *fmt, va_list ap)
{
	int ret = errno;
	FILE *fp = stdout;

	if (level <= TEP_LOG_WARNING) {
		fp = stderr;
		if (errno && print_err) {
			perror(name);
			fprintf(stderr, "  ");
		}
	}
	vfprintf(fp, fmt, ap);
	fprintf(fp, "\n");

	return ret;
}

void tep_warning(const char *fmt, ...)
{
	va_list ap;

	if (log_level < TEP_LOG_WARNING)
		return;

	va_start(ap, fmt);
	tep_vprint("libtraceevent", TEP_LOG_WARNING, true, fmt, ap);
	va_end(ap);
}


void tep_info(const char *fmt, ...)
{
	va_list ap;

	if (log_level < TEP_LOG_INFO)
		return;

	va_start(ap, fmt);
	tep_vprint("libtraceevent", TEP_LOG_INFO, false, fmt, ap);
	va_end(ap);
}

/* The below is for backward compatibility */
int __weak tep_vwarning(const char *name, const char *fmt, va_list ap)
{
	return tep_vprint(name, TEP_LOG_WARNING, true, fmt, ap);
}

void pr_stat(const char *fmt, ...) __attribute__((weak, alias("tep_info")));
void __pr_stat(const char *fmt, ...) __attribute__((weak, alias("tep_info")));

void __weak __vpr_stat(const char *fmt, va_list ap)
{
	tep_vprint("libtraceevent", TEP_LOG_INFO, false, fmt, ap);
}

void vpr_stat(const char *fmt, va_list ap) __attribute__((weak, alias("__vpr_stat")));

/**
 * tep_kbuffer - return an allocated kbuffer that can be used for the tep handle
 * @tep: the handle that will work with the kbuffer descriptor
 *
 * Allocates and returns a new kbuffer.
 * The return must be freed by kbuffer_free();
 */
struct kbuffer *tep_kbuffer(struct tep_handle *tep)
{
	enum kbuffer_endian endian;
	int long_size;

	long_size = tep_get_long_size(tep);

	/* If the long_size is not set, then use the commit size */
	if (!long_size)
		long_size = tep_get_header_page_size(tep);

	if (long_size == 8)
		long_size = KBUFFER_LSIZE_8;
	else
		long_size = KBUFFER_LSIZE_4;

	if (tep_is_file_bigendian(tep))
		endian = KBUFFER_ENDIAN_BIG;
	else
		endian = KBUFFER_ENDIAN_LITTLE;

	return kbuffer_alloc(long_size, endian);
}
