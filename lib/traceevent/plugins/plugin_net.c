// SPDX-License-Identifier: LGPL-2.1
#include <stdint.h>

#include "event-parse.h"
#include "trace-seq.h"

static unsigned long long
process_builtin_constant_p(struct trace_seq *s, unsigned long long *args)
{
	return 0;
}

static unsigned long long
process_builtin_bswap16(struct trace_seq *s, unsigned long long *args)
{
	return __builtin_bswap16((uint16_t)args[0]);
}

static unsigned long long
process_builtin_bswap32(struct trace_seq *s, unsigned long long *args)
{
	return __builtin_bswap32((uint32_t)args[0]);
}

static unsigned long long
process_builtin_bswap64(struct trace_seq *s, unsigned long long *args)
{
	return __builtin_bswap64(args[0]);
}

int TEP_PLUGIN_LOADER(struct tep_handle *tep)
{
	tep_register_print_function(tep,
				    process_builtin_constant_p,
				    TEP_FUNC_ARG_INT,
				    "__builtin_constant_p",
				    TEP_FUNC_ARG_INT,
				    TEP_FUNC_ARG_VOID);
	tep_register_print_function(tep,
				    process_builtin_bswap16,
				    TEP_FUNC_ARG_INT,
				    "__fswab16",
				    TEP_FUNC_ARG_INT,
				    TEP_FUNC_ARG_VOID);
	tep_register_print_function(tep,
				    process_builtin_bswap16,
				    TEP_FUNC_ARG_INT,
				    "__builtin_bswap16",
				    TEP_FUNC_ARG_INT,
				    TEP_FUNC_ARG_VOID);
	tep_register_print_function(tep,
				    process_builtin_bswap32,
				    TEP_FUNC_ARG_INT,
				    "__fswab32",
				    TEP_FUNC_ARG_INT,
				    TEP_FUNC_ARG_VOID);
	tep_register_print_function(tep,
				    process_builtin_bswap32,
				    TEP_FUNC_ARG_INT,
				    "__builtin_bswap32",
				    TEP_FUNC_ARG_INT,
				    TEP_FUNC_ARG_VOID);
	tep_register_print_function(tep,
				    process_builtin_bswap64,
				    TEP_FUNC_ARG_LONG,
				    "__fswab64",
				    TEP_FUNC_ARG_LONG,
				    TEP_FUNC_ARG_VOID);
	tep_register_print_function(tep,
				    process_builtin_bswap64,
				    TEP_FUNC_ARG_LONG,
				    "__builtin_bswap64",
				    TEP_FUNC_ARG_LONG,
				    TEP_FUNC_ARG_VOID);
	return 0;
}

void TEP_PLUGIN_UNLOADER(struct tep_handle *tep)
{
	tep_unregister_print_function(tep, process_builtin_constant_p,
				      "__builtin_constant_p");
	tep_unregister_print_function(tep, process_builtin_bswap16,
				      "__fswab16");
	tep_unregister_print_function(tep, process_builtin_bswap16,
				      "__builtin_bswap16");
	tep_unregister_print_function(tep, process_builtin_bswap32,
				      "__fswab32");
	tep_unregister_print_function(tep, process_builtin_bswap32,
				      "__builtin_bswap32");
	tep_unregister_print_function(tep, process_builtin_bswap64,
				      "__fswab64");
	tep_unregister_print_function(tep, process_builtin_bswap64,
				      "__builtin_bswap64");
}
