// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2025 Google, Steven Rostedt <rostedt@goodmis.org>
 *
 * Reference: https://docs.kernel.org/bpf/btf.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <linux/btf.h>

#include "event-parse.h"
#include "event-utils.h"
#include "event-parse-local.h"

struct btf_header;
struct btf_type;

struct tep_btf {
	struct btf_header	*hdr;
	const char		*strings;
	struct btf_type		**types;
	unsigned long		nr_types;
	struct btf_type		**funcs;
	unsigned long		nr_funcs;
	void			*data;
	size_t			raw_size;
	void			*raw_data;
};

#define REALLOC_SIZE (1 << 10)
#define REALLOC_MASK (REALLOC_SIZE - 1)

static const char *btf_name(struct tep_btf *btf, int off)
{
	if (off < btf->hdr->str_len)
		return btf->strings + off;
	return "";
}

/* List taken from the Linux kernel */
static const char * const btf_kind_str[NR_BTF_KINDS] = {
	[BTF_KIND_UNKN]		= "UNKNOWN",
	[BTF_KIND_INT]		= "INT",
	[BTF_KIND_PTR]		= "PTR",
	[BTF_KIND_ARRAY]	= "ARRAY",
	[BTF_KIND_STRUCT]	= "STRUCT",
	[BTF_KIND_UNION]	= "UNION",
	[BTF_KIND_ENUM]		= "ENUM",
	[BTF_KIND_FWD]		= "FWD",
	[BTF_KIND_TYPEDEF]	= "TYPEDEF",
	[BTF_KIND_VOLATILE]	= "VOLATILE",
	[BTF_KIND_CONST]	= "CONST",
	[BTF_KIND_RESTRICT]	= "RESTRICT",
	[BTF_KIND_FUNC]		= "FUNC",
	[BTF_KIND_FUNC_PROTO]	= "FUNC_PROTO",
	[BTF_KIND_VAR]		= "VAR",
	[BTF_KIND_DATASEC]	= "DATASEC",
	[BTF_KIND_FLOAT]	= "FLOAT",
	[BTF_KIND_DECL_TAG]	= "DECL_TAG",
	[BTF_KIND_TYPE_TAG]	= "TYPE_TAG",
	[BTF_KIND_ENUM64]	= "ENUM64",
};

static const char *btf_type_str(const struct btf_type *t)
{
	return btf_kind_str[BTF_INFO_KIND(t->info)];
}

static int insert_type(struct btf_type ***types, unsigned long *cnt, struct btf_type *type)
{
	unsigned long nr_types = *cnt;
        struct btf_type **array = *types;

        if (!(nr_types & REALLOC_MASK)) {
                int size = nr_types + REALLOC_SIZE;

                array = realloc(array, sizeof(struct btf_type *) * size);
                if (!array) {
			tep_warning("Failed to alloct memory for new type");
			return -1;
		}
                *types = array;
        }

        array[nr_types++] = type;
	*cnt = nr_types;
	return 0;
}

static int add_type(struct tep_btf *btf, struct btf_type *type)
{
	return insert_type(&btf->types, &btf->nr_types, type);
}

static int add_func(struct tep_btf *btf, struct btf_type *type)
{
	return insert_type(&btf->funcs, &btf->nr_funcs, type);
}

static int btf_type_size(struct btf_type *type)
{
	int kind = BTF_INFO_KIND(type->info);
	int size = sizeof(*type);

	switch (kind) {
	case BTF_KIND_INT:
		return size + sizeof(int);
	case BTF_KIND_VAR:
		return size + sizeof(struct btf_var);
	case BTF_KIND_ARRAY:
		return size + sizeof(struct btf_array);
	case BTF_KIND_DECL_TAG:
		return size + sizeof(struct btf_decl_tag);
	case BTF_KIND_ENUM:
		return size + sizeof(struct btf_enum) * BTF_INFO_VLEN(type->info);
	case BTF_KIND_ENUM64:
		return size + sizeof(struct btf_enum64) * BTF_INFO_VLEN(type->info);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return size + sizeof(struct btf_member) * BTF_INFO_VLEN(type->info);
	case BTF_KIND_FUNC_PROTO:
		return size + sizeof(struct btf_param) * BTF_INFO_VLEN(type->info);
	case BTF_KIND_DATASEC:
		return size + sizeof(struct btf_var_secinfo) * BTF_INFO_VLEN(type->info);
	case BTF_KIND_PTR:
	case BTF_KIND_FWD:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPE_TAG:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
		return size;
	}
	return -1;
}

static int cmp_funcs(const void *A, const void *B, void *data)
{
	struct tep_btf *btf = data;
	const struct btf_type *a = *(const struct btf_type **)A;
	const struct btf_type *b = *(const struct btf_type **)B;
	const char *name_a = btf_name(btf, a->name_off);
	const char *name_b = btf_name(btf, b->name_off);

	return strcmp(name_a, name_b);
}

struct tcmd_search {
	struct tep_btf		*btf;
	const char		*name;
};

static int cmp_key_func(const void *A, const void *B)
{
	const struct tcmd_search *key = A;
	const struct btf_type *b = *(const struct btf_type **)B;
	const char *name_b = btf_name(key->btf, b->name_off);

	return strcmp(key->name, name_b);
}

static struct btf_type *tep_btf_find_func(struct tep_btf *btf, const char *name)
{
	struct tcmd_search tsearch;
	struct btf_type **t;

	if (!btf || !name)
		return NULL;

	tsearch.btf = btf;
	tsearch.name = name;

	t = bsearch(&tsearch, btf->funcs, btf->nr_funcs, sizeof(btf->funcs[0]),
		    cmp_key_func);

	return t ? *t : NULL;
}

static int load_types(struct tep_btf *btf)
{
	struct btf_type *type;
	void *start, *end;
	int size;

	start = btf->data + btf->hdr->type_off;
	end = start + btf->hdr->type_len;

	if (end > btf->raw_data + btf->raw_size)
		return -1;

	for (type = start; (void *)type < end;) {
		if (add_type(btf, type))
			return -1;
		if (BTF_INFO_KIND(type->info) == BTF_KIND_FUNC) {
			if (add_func(btf, type))
				return -1;
		}
		size = btf_type_size(type);
		if (size < 0) {
			tep_warning("Invalid type %d\n", BTF_INFO_KIND(type->info));
			return -1;
		}
		type = (void *)type + size;
	}

	qsort_r(btf->funcs, btf->nr_funcs, sizeof(btf->funcs[0]), cmp_funcs, btf);
	return 0;
}

__hidden void btf_free(struct tep_btf *btf)
{
	if (!btf)
		return;

	free(btf->types);
	free(btf->funcs);
	free(btf->raw_data);
}

static struct tep_btf *btf_init(void *raw_data, size_t data_size)
{
	struct tep_btf *btf;

	btf = calloc(1, sizeof(*btf));
	if (!btf)
		return NULL;

	btf->raw_data = malloc(data_size);
	if (!btf->raw_data)
		goto fail;

	memcpy(btf->raw_data, raw_data, data_size);

	btf->raw_size = data_size;
	btf->hdr = btf->raw_data;

	/* Currently only same endianess is supported */
	if (btf->hdr->magic != 0xeb9f) {
		if (btf->hdr->magic != 0x9feb)
			tep_warning("BTF does not match endianess of this machine");
		else
			tep_warning("Invalid BTF header");
		goto fail;
	}

	if (btf->hdr->hdr_len < sizeof(*btf->hdr)) {
		tep_warning("Header (%d) smaller than expected header %zd",
			    btf->hdr->hdr_len, sizeof(*btf->hdr));
		goto fail;
	}

	if (btf->hdr->str_off > data_size) {
		tep_warning("String header (%d) greater than data size %zd",
			    btf->hdr->str_len, data_size);
		goto fail;
	}

	btf->data = btf->raw_data + btf->hdr->hdr_len;

	btf->strings = btf->data + btf->hdr->str_off;

	if (load_types(btf) < 0)
		goto fail;

	return btf;
 fail:
	btf_free(btf);
	return NULL;
}

/**
 * tep_load_btf - Load BTF information into a tep handle
 * @tep: The tep handle to load the BTF info into
 * @raw_data: The raw data containing the BTF file
 * @data_size: The amount of data in @raw_data
 *
 * Initializes BTF into the @tep handle. If it had already had BTF
 * loaded, it will free the previous BTF and recreate it from @raw_data.
 *
 * Returns: 0 on success and -1 on failure.
 */
int tep_load_btf(struct tep_handle *tep, void *raw_data, size_t data_size)
{
	/* If btf was already loaded, free it */
	btf_free(tep->btf);

	tep->btf = btf_init(raw_data, data_size);
	if (!tep->btf)
		return -1;
	return 0;
}

static struct btf_type *btf_get_type(struct tep_btf *btf, int id)
{
	if (!id || id > btf->nr_types)
		return NULL;

	return btf->types[id - 1];
}

static struct btf_type *btf_skip_modifiers(struct tep_btf *btf, int id)
{
	struct btf_type *t = btf_get_type(btf, id);

	for (;;) {
		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id = t->type;
			t = btf_get_type(btf, t->type);
			continue;
		}
		break;
	}

	return t;
}

static void add_name(struct tep_btf *btf, struct btf_type *t,
		     struct trace_seq *s, const char *alt)
{
	const char *name;

	name = btf_name(btf, t->name_off);
	if (name)
		trace_seq_printf(s, "%s ", name);
	else if (alt)
		trace_seq_printf(s, "%s ", alt);
	else
		trace_seq_puts(s, "?? ");
}

static void btf_add_type(struct tep_btf *btf, struct trace_seq *s, int id)
{
	struct btf_type *t = btf_get_type(btf, id);
	unsigned int encode;
	int bits;

	while (t) {
		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_TYPEDEF:
			add_name(btf, t, s, "typedef");
			return;

		case BTF_KIND_ENUM:
			trace_seq_puts(s, "enum ");
			add_name(btf, t, s, NULL);
			return;

		case BTF_KIND_STRUCT:
			trace_seq_puts(s, "struct ");
			add_name(btf, t, s, NULL);
			return;

		case BTF_KIND_UNION:
			trace_seq_puts(s, "union ");
			add_name(btf, t, s, NULL);
			return;

		case BTF_KIND_PTR:
			if (t->type)
				btf_add_type(btf, s, t->type);
			else
				trace_seq_puts(s, "void ");
			trace_seq_puts(s, "*");
			return;

		case BTF_KIND_VOLATILE:	trace_seq_puts(s, "volatile ");
			btf_add_type(btf, s, t->type);
			return;

		case BTF_KIND_CONST:	trace_seq_puts(s, "const ");
			btf_add_type(btf, s, t->type);
			return;

		case BTF_KIND_INT:
			encode = *(int *)((void *)t + sizeof(*t));
			if (!(BTF_INT_ENCODING(encode) & BTF_INT_SIGNED))
				trace_seq_puts(s, "unsigned ");

			bits = BTF_INT_BITS(encode);
			switch (bits) {
			case 8:		trace_seq_puts(s, "char "); break;
			case 16:	trace_seq_puts(s, "short "); break;
			case 32:	trace_seq_puts(s, "int "); break;
			case 64:	trace_seq_puts(s, "long long "); break;
			default:	trace_seq_printf(s, "int%d ", bits);
			}
			return;


		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id = t->type;
			t = btf_get_type(btf, t->type);
			continue;
		}
		break;
	}
}

static void assign_arg(unsigned long long *arg, void *args, int size, int a)
{
	*arg = size == 4 ?
		*(unsigned int *)(args + a * sizeof(int)) :
		*(unsigned long long *)(args + a * sizeof(long long));
}

static int init_btf_func(struct tep_btf *btf, struct trace_seq *s,
			 void *args, int nmem, int size,
			 const char *func, struct btf_type **p_type)
{
	struct btf_type *type = tep_btf_find_func(btf, func);
	unsigned long long arg;
	const char *fp;
	int i;

	if (args && (size != 4 && size != 8))
		return -1;

	if (!type && (fp = strchr(func, '.'))) {
		char *f;
		/* func name has extra characters */
		f = strdup(func);
		if (f) {
			f[fp - func] = '\0';
			type = tep_btf_find_func(btf, f);
			free(f);
		}
	}

	if (!type) {
		for (i = 0; args && i < nmem; i++) {
			assign_arg(&arg, args, size, i);
			trace_seq_printf(s, "%llx", arg);
			if (i + 1 < nmem)
				trace_seq_puts(s, ", ");
		}
		*p_type = NULL;
		return 0;
	}

	if (BTF_INFO_KIND(type->info) != BTF_KIND_FUNC) {
		tep_warning("Invalid func type %d %s for function %s\n",
			    BTF_INFO_KIND(type->info),
			    btf_type_str(type), func);
		return -1;
	}

	*p_type = type;

	return 0;
}

/**
 * tep_btf_list_args - List the arguments (type and name) for a function
 * @tep: The tep descriptor to use
 * @s: The trace_seq to write the arguments into
 * @func: The name of the function.
 *
 * Loads up @s with the type and name of @func's arguments (basically
 * its prototype).
 *
 * Returns: number of arguments found, or -1 on failure.
 */
int tep_btf_list_args(struct tep_handle *tep, struct trace_seq *s, const char *func)
{
	struct tep_btf *btf = tep->btf;
	struct btf_type *type = tep_btf_find_func(btf, func);
	struct btf_param *param;
	const char *param_name;
	int p, nr;

	if (init_btf_func(btf, s, NULL, 0, 0, func, &type) < 0)
		return -1;

	/* Type is NULL if function wasn't found */
	if (!type)
		return -1;

	/* Get the function proto */
	type = btf_get_type(btf, type->type);

	/* No proto means "()" ? */
	if (!type)
		return 0;

	if (BTF_INFO_KIND(type->info) != BTF_KIND_FUNC_PROTO) {
		tep_warning("Invalid func proto type %d %s for function %s\n",
			    BTF_INFO_KIND(type->info),
			    btf_type_str(type), func);
		return -1;
	}

	/* Get the number of parameters */
	nr = BTF_INFO_VLEN(type->info);

	/* The parameters are right after the FUNC_PROTO type */
	param = ((void *)type) + sizeof(*type);

	for (p = 0; p < nr; p++) {

		if (p)
			trace_seq_puts(s, ", ");

		param_name = btf_name(btf, param[p].name_off);
		if (!param_name)
			param_name = "??";

		btf_add_type(btf, s, param[p].type);


		if (param_name)
			trace_seq_printf(s, "%s", param_name);
	}
	return p;
}

/**
 * tep_btf_print_args - Print function arguments from BTF info
 * @tep: The tep descriptor to use
 * @s: The trace_seq to write the arguments into
 * @args: The array that holds the arguments
 * @nmem: The number of arguments
 * @size: The size of each item in args (4 or 8).
 * @func: The name of the function.
 *
 * Loads up the @s with a list of arguments for the function based on
 * the @args.
 *
 * If there's no BTF loaded or @func is not found, then it just writes
 * the @args as raw numbers. Otherwise it will pretty print the
 * arguments based on the function info in BTF.
 *
 * Returns: 0 on success and -1 on failure.
 */
int tep_btf_print_args(struct tep_handle *tep, struct trace_seq *s, void *args,
		       int nmem, int size, const char *func)
{
	struct tep_btf *btf = tep->btf;
	struct btf_type *type = tep_btf_find_func(btf, func);
	struct btf_param *param;
	unsigned long long arg;
	unsigned int encode;
	const char *param_name;
	int a, p, x, nr;

	if (!func)
		return -1;

	if (init_btf_func(btf, s, args, nmem, size, func, &type) < 0)
		return -1;

	/* Type is NULL if function wasn't found */
	if (!type)
		return 0;

	/* Get the function proto */
	type = btf_get_type(btf, type->type);

	/* No proto means "()" ? */
	if (!type)
		return 0;

	if (BTF_INFO_KIND(type->info) != BTF_KIND_FUNC_PROTO) {
		tep_warning("Invalid func proto type %d %s for function %s\n",
			    BTF_INFO_KIND(type->info),
			    btf_type_str(type), func);
		return -1;
	}

	/* Get the number of parameters */
	nr = BTF_INFO_VLEN(type->info);

	/* The parameters are right after the FUNC_PROTO type */
	param = ((void *)type) + sizeof(*type);

	for (a = 0, p = 0; p < nr; a++, p++) {
		struct btf_type *t;
		int offset;
		int bits;

		if (p)
			trace_seq_puts(s, ", ");

		if (a == nmem) {
			trace_seq_puts(s, "...");
			break;
		}

		assign_arg(&arg, args, size, a);

		param_name = btf_name(btf, param[p].name_off);
		if (param_name)
			trace_seq_printf(s, "%s=", param_name);

		if (!param[p].type)
			continue;

		t = btf_skip_modifiers(btf, param[p].type);

		switch (t ? BTF_INFO_KIND(t->info) : BTF_KIND_UNKN) {
		case BTF_KIND_UNKN:
			trace_seq_putc(s, '?');
			/* Still print unknown type values */
			/* fallthough */
		case BTF_KIND_PTR:
			trace_seq_printf(s, "0x%llx", arg);
			break;
		case BTF_KIND_INT:
			encode = *(int *)((void *)t + sizeof(*t));
			bits = BTF_INT_BITS(encode);
			offset = BTF_INT_OFFSET(encode);
			arg >>= offset;
			if (bits < 64)
				arg &= (1ULL << bits) - 1;
			/* Print unsigned ints as hex */
			if (BTF_INT_ENCODING(encode) & BTF_INT_SIGNED)
				trace_seq_printf(s, "%lld", arg);
			else
				trace_seq_printf(s, "0x%llx", arg);
			break;
		case BTF_KIND_ENUM:
			trace_seq_printf(s, "%lld", arg);
			break;
		default:
			/* This does not handle complex arguments */
			trace_seq_printf(s, "(%s)[0x%llx", btf_type_str(t), arg);
			for (x = sizeof(long); x < t->size; x += sizeof(long)) {
				trace_seq_putc(s, ':');
				if (++a == nmem) {
					trace_seq_puts(s, "...]");
					return 0;
				}
				assign_arg(&arg, args, size, a);
				trace_seq_printf(s, "0x%llx", arg);
			}
			trace_seq_putc(s, ']');
			break;
		}
	}
	return 0;
}
