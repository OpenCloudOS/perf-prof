// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event-parse.h"
#include "trace-seq.h"

/*
 * prev_state is of size long, which is 32 bits on 32 bit architectures.
 * As it needs to have the same bits for both 32 bit and 64 bit architectures
 * we can just assume that the flags we care about will all be within
 * the 32 bits.
 */
#define MAX_STATE_BITS	32

static const char *convert_sym(struct tep_print_flag_sym *sym)
{
	static char save_states[MAX_STATE_BITS + 1];

	memset(save_states, 0, sizeof(save_states));

	/* This is the flags for the prev_state_field, now make them into a string */
	for (; sym; sym = sym->next) {
		long bitmask = strtoul(sym->value, NULL, 0);
		int i;

		for (i = 0; !(bitmask & 1); i++)
			bitmask >>= 1;

		if (i >= MAX_STATE_BITS)
			continue;

		save_states[i] = sym->str[0];
	}

	return save_states;
}

static struct tep_print_arg_field *
find_arg_field(struct tep_format_field *prev_state_field, struct tep_print_arg *arg)
{
	struct tep_print_arg_field *field;

	if (!arg)
		return NULL;

	if (arg->type == TEP_PRINT_FIELD)
		return &arg->field;

	if (arg->type == TEP_PRINT_OP) {
		field = find_arg_field(prev_state_field, arg->op.left);
		if (field && field->field == prev_state_field)
			return field;
		field = find_arg_field(prev_state_field, arg->op.right);
		if (field && field->field == prev_state_field)
			return field;
	}
	return NULL;
}

static struct tep_print_flag_sym *
test_flags(struct tep_format_field *prev_state_field, struct tep_print_arg *arg)
{
	struct tep_print_arg_field *field;

	field = find_arg_field(prev_state_field, arg->flags.field);
	if (!field)
		return NULL;

	return arg->flags.flags;
}

static struct tep_print_flag_sym *
search_op(struct tep_format_field *prev_state_field, struct tep_print_arg *arg)
{
	struct tep_print_flag_sym *sym = NULL;

	if (!arg)
		return NULL;

	if (arg->type == TEP_PRINT_OP) {
		sym = search_op(prev_state_field, arg->op.left);
		if (sym)
			return sym;

		sym = search_op(prev_state_field, arg->op.right);
		if (sym)
			return sym;
	} else if (arg->type == TEP_PRINT_FLAGS) {
		sym = test_flags(prev_state_field, arg);
	}

	return sym;
}

static const char *get_states(struct tep_format_field *prev_state_field)
{
	struct tep_print_flag_sym *sym;
	struct tep_print_arg *arg;
	struct tep_event *event;

	event = prev_state_field->event;

	/*
	 * Look at the event format fields, and search for where
	 * the prev_state is parsed via the format flags.
	 */
	for (arg = event->print_fmt.args; arg; arg = arg->next) {
		/*
		 * Currently, the __print_flags() for the prev_state
		 * is embedded in operations, so they too must be
		 * searched.
		 */
		sym = search_op(prev_state_field, arg);
		if (sym)
			return convert_sym(sym);
	}
	return NULL;
}

static void write_state(struct trace_seq *s, struct tep_format_field *field,
			struct tep_record *record)
{
	static struct tep_format_field *prev_state_field;
	static const char *states;
	unsigned long long val;
	int found = 0;
	int len;
	int i;

	if (!field)
		return;

	if (!states || field != prev_state_field) {
		states = get_states(field);
		if (!states)
			states = "SDTtXZPI";
		prev_state_field = field;
	}

	tep_read_number_field(field, record->data, &val);

	len = strlen(states);
	for (i = 0; i < len; i++) {
		if (!(val & (1 << i)))
			continue;

		if (found)
			trace_seq_putc(s, '|');

		found = 1;
		trace_seq_putc(s, states[i]);
	}

	if (!found)
		trace_seq_puts(s, val ? "R+" : "R");
}

static void write_and_save_comm(struct tep_format_field *field,
				struct tep_record *record,
				struct trace_seq *s, int pid)
{
	const char *comm;
	//int len;

	comm = (char *)(record->data + field->offset);
	//len = s->len;
	trace_seq_printf(s, "%.*s",
			 field->size, comm);

	/* make sure the comm has a \0 at the end. */
	//trace_seq_terminate(s);
	//comm = &s->buffer[len];

	/*
	 * tep_register_comm() will add duplicate (pid, comm) to tep->cmdlist,
	 * causing memory usage to increase rapidly.
	 */

	/* Help out the comm to ids. This will handle dups */
	//tep_register_comm(field->event->tep, comm, pid);
}

static int sched_wakeup_handler(struct trace_seq *s,
				struct tep_record *record,
				struct tep_event *event, void *context)
{
	struct tep_format_field *field;
	unsigned long long val;

	if (tep_get_field_val(s, event, "pid", record, &val, 1))
		return trace_seq_putc(s, '!');

	field = tep_find_any_field(event, "comm");
	if (field) {
		write_and_save_comm(field, record, s, val);
		trace_seq_putc(s, ':');
	}
	trace_seq_printf(s, "%lld", val);

	if (tep_get_field_val(s, event, "prio", record, &val, 1) == 0)
		trace_seq_printf(s, " [%lld]", val);

	if (tep_get_field_val(s, event, "success", record, &val, 0) == 0)
		trace_seq_printf(s, " success=%lld", val);

	if (tep_get_field_val(s, event, "target_cpu", record, &val, 0) == 0)
		trace_seq_printf(s, " CPU:%03llu", val);

	return 0;
}

static int sched_switch_handler(struct trace_seq *s,
				struct tep_record *record,
				struct tep_event *event, void *context)
{
	struct tep_format_field *field;
	unsigned long long val;

	if (tep_get_field_val(s, event, "prev_pid", record, &val, 1))
		return trace_seq_putc(s, '!');

	field = tep_find_any_field(event, "prev_comm");
	if (field) {
		write_and_save_comm(field, record, s, val);
		trace_seq_putc(s, ':');
	}
	trace_seq_printf(s, "%lld ", val);

	if (tep_get_field_val(s, event, "prev_prio", record, &val, 1) == 0)
		trace_seq_printf(s, "[%d] ", (int) val);

	field = tep_find_any_field(event, "prev_state");
	write_state(s, field, record);

	trace_seq_puts(s, " ==> ");

	if (tep_get_field_val(s, event, "next_pid", record, &val, 1))
		return trace_seq_putc(s, '!');

	field = tep_find_any_field(event, "next_comm");
	if (field) {
		write_and_save_comm(field, record, s, val);
		trace_seq_putc(s, ':');
	}
	trace_seq_printf(s, "%lld", val);

	if (tep_get_field_val(s, event, "next_prio", record, &val, 1) == 0)
		trace_seq_printf(s, " [%d]", (int) val);

	return 0;
}

int TEP_PLUGIN_LOADER(struct tep_handle *tep)
{
	tep_register_event_handler(tep, -1, "sched", "sched_switch",
				   sched_switch_handler, NULL);

	tep_register_event_handler(tep, -1, "sched", "sched_wakeup",
				   sched_wakeup_handler, NULL);

	tep_register_event_handler(tep, -1, "sched", "sched_wakeup_new",
				   sched_wakeup_handler, NULL);
	return 0;
}

void TEP_PLUGIN_UNLOADER(struct tep_handle *tep)
{
	tep_unregister_event_handler(tep, -1, "sched", "sched_switch",
				     sched_switch_handler, NULL);

	tep_unregister_event_handler(tep, -1, "sched", "sched_wakeup",
				     sched_wakeup_handler, NULL);

	tep_unregister_event_handler(tep, -1, "sched", "sched_wakeup_new",
				     sched_wakeup_handler, NULL);
}
