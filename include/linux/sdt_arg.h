/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SDT_ARG_H
#define __SDT_ARG_H

#include <linux/types.h>
#include <linux/compiler.h>

enum {
	SDT_ARG_VALID = 0,
	SDT_ARG_SKIP,
};

int arch_sdt_arg_parse_op(char *old_op, char **new_op);

#endif /* __SDT_ARG_H */
