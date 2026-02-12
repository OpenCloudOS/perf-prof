// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */

#ifndef _PARSE_EVENTS_INT_H
#define _PARSE_EVENTS_INT_H

struct tep_cmdline;
struct cmdline_list;
struct func_map;
struct func_list;
struct event_handler;
struct func_resolver;
struct tep_plugins_dir;
struct tep_btf;
struct tep_mod_addr;

#define __hidden __attribute__((visibility ("hidden")))

struct tep_handle {
	int ref_count;

	int header_page_ts_offset;
	int header_page_ts_size;
	int header_page_size_offset;
	int header_page_size_size;
	int header_page_data_offset;
	int header_page_data_size;
	int header_page_overwrite;

	enum tep_endian file_bigendian;
	enum tep_endian host_bigendian;

	int old_format;

	int cpus;
	int long_size;
	int page_size;

	struct tep_cmdline *cmdlines;
	struct cmdline_list *cmdlist;
	int cmdline_count;

	struct func_map *func_map;
	struct func_resolver *func_resolver;
	struct func_list *funclist;
	unsigned int func_count;
	unsigned long long func_offset;
	unsigned long long mod_addr;
	unsigned long long _text_addr;
	struct tep_mod_addr *mod_addrs;
	struct tep_mod_addr *proc_mods;
	int nr_mod_addrs;
	int nr_proc_mods;


	struct printk_map *printk_map;
	struct printk_list *printklist;
	unsigned int printk_count;

	struct tep_event **events;
	int nr_events;
	struct tep_event **sort_events;
	enum tep_event_sort_type last_type;

	int type_offset;
	int type_size;

	int pid_offset;
	int pid_size;

	int pc_offset;
	int pc_size;

	int flags_offset;
	int flags_size;

	int ld_offset;
	int ld_size;

	int test_filters;

	int flags;

	struct tep_format_field *bprint_ip_field;
	struct tep_format_field *bprint_fmt_field;
	struct tep_format_field *bprint_buf_field;

	struct event_handler *handlers;
	struct tep_function_handler *func_handlers;

	/* cache */
	struct tep_event *last_event;

	struct tep_plugins_dir *plugins_dir;

	const char *input_buf;
	unsigned long long input_buf_ptr;
	unsigned long long input_buf_siz;

	struct tep_btf *btf;
};

enum tep_print_parse_type {
	PRINT_FMT_STRING,
	PRINT_FMT_ARG_DIGIT,
	PRINT_FMT_ARG_POINTER,
	PRINT_FMT_ARG_STRING,
};

struct tep_print_parse {
	struct tep_print_parse	*next;

	char				*format;
	int				ls;
	enum tep_print_parse_type	type;
	struct tep_print_arg		*arg;
	struct tep_print_arg		*len_as_arg;
};

void free_tep_event(struct tep_event *event);
void free_tep_format_field(struct tep_format_field *field);
void free_tep_plugin_paths(struct tep_handle *tep);

unsigned short data2host2(struct tep_handle *tep, unsigned short data);
unsigned int data2host4(struct tep_handle *tep, unsigned int data);
unsigned long long data2host8(struct tep_handle *tep, unsigned long long data);

/* access to the internal parser */
int peek_char(struct tep_handle *tep);
void init_input_buf(struct tep_handle *tep, const char *buf, unsigned long long size);
unsigned long long get_input_buf_ptr(struct tep_handle *tep);
const char *get_input_buf(struct tep_handle *tep);
enum tep_event_type read_token(struct tep_handle *tep, char **tok);
void free_token(char *tok);

/* BTF routines */
void btf_free(struct tep_btf *btf);

#endif /* _PARSE_EVENTS_INT_H */
