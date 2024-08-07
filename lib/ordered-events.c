// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>
#include <asm/bug.h>
#include <linux/list.h>
#include <linux/compiler.h>
#include <linux/string.h>
#include <perf/event.h>
#include <linux/ordered-events.h>

#define pr_N(n, fmt, ...)

#define pr(fmt, ...) pr_N(1, pr_fmt(fmt), ##__VA_ARGS__)

static bool __always_inline less(struct rb_node *rb1, const struct rb_node *rb2)
{
	struct ordered_event *o1 = rb_entry(rb1, struct ordered_event, rbnode);
	struct ordered_event *o2 = rb_entry(rb2, struct ordered_event, rbnode);
	return o1->timestamp < o2->timestamp;
}

static void queue_event(struct ordered_events *oe, struct ordered_event *new)
{
	u64 timestamp = new->timestamp;

	++oe->nr_events;

	if (new->timestamp > oe->max_timestamp) {
		oe->last = new;
		oe->max_timestamp = timestamp;
	}

	rb_add_cached(&new->rbnode, &oe->events, less);
}

static inline void update_alloc_size(struct ordered_events *oe, struct ordered_event *event, bool free)
{
	if (!oe->copy_on_queue)
		return;

	if (!free) {
		event->size = event->event->header.size;
		oe->cur_alloc_size += event->size;
	} else
		oe->cur_alloc_size -= event->size;
}

static union perf_event *__dup_event(struct ordered_events *oe,
				     union perf_event *event)
{
	union perf_event *new_event = NULL;

	if (oe->cur_alloc_size + event->header.size < oe->max_alloc_size) {
		new_event = memdup(event, event->header.size);
	}

	return new_event;
}

static union perf_event *dup_event(struct ordered_events *oe,
				   union perf_event *event)
{
	return oe->copy_on_queue ? __dup_event(oe, event) : event;
}

static void __free_dup_event(struct ordered_events *oe, union perf_event *event)
{
	if (event) {
		free(event);
	}
}

static void free_dup_event(struct ordered_events *oe, union perf_event *event)
{
	if (oe->copy_on_queue)
		__free_dup_event(oe, event);
}

#define MAX_SAMPLE_BUFFER	((64*1024 - sizeof(struct ordered_events_buffer)) / sizeof(struct ordered_event))
static struct ordered_event *alloc_event(struct ordered_events *oe,
					 union perf_event *event)
{
	struct list_head *cache = &oe->cache;
	struct ordered_event *new = NULL;
	union perf_event *new_event;
	size_t size;

	new_event = dup_event(oe, event);
	if (!new_event)
		return NULL;

	/*
	 * We maintain the following scheme of buffers for ordered
	 * event allocation:
	 *
	 *   to_free list -> buffer1 (64K)
	 *                   buffer2 (64K)
	 *                   ...
	 *
	 * Each buffer keeps an array of ordered events objects:
	 *    buffer -> event[0]
	 *              event[1]
	 *              ...
	 *
	 * Each allocated ordered event is linked to one of
	 * following lists:
	 *   - time ordered list 'events'
	 *   - list of currently removed events 'cache'
	 *
	 * Allocation of the ordered event uses the following order
	 * to get the memory:
	 *   - use recently removed object from 'cache' list
	 *   - use available object in current allocation buffer
	 *   - allocate new buffer if the current buffer is full
	 *
	 * Removal of ordered event object moves it from events to
	 * the cache list.
	 */
	size = sizeof(*oe->buffer) + MAX_SAMPLE_BUFFER * sizeof(*new);

	if (!list_empty(cache)) {
		new = list_entry(cache->next, struct ordered_event, list);
		list_del_init(&new->list);
	} else if (oe->buffer) {
		new = &oe->buffer->event[oe->buffer_idx];
		if (++oe->buffer_idx == MAX_SAMPLE_BUFFER)
			oe->buffer = NULL;
	} else if ((oe->cur_alloc_size + size) < oe->max_alloc_size) {
		oe->buffer = malloc(size);
		if (!oe->buffer) {
			free_dup_event(oe, new_event);
			return NULL;
		}

		pr("alloc size %" PRIu64 "B (+%zu), max %" PRIu64 "B\n",
		   oe->cur_alloc_size, size, oe->max_alloc_size);

		oe->cur_alloc_size += size;
		list_add(&oe->buffer->list, &oe->to_free);

		oe->buffer_idx = 1;
		new = &oe->buffer->event[0];
	} else {
		pr("allocation limit reached %" PRIu64 "B\n", oe->max_alloc_size);
		free_dup_event(oe, new_event);
		return NULL;
	}

	new->event = new_event;
	RB_CLEAR_NODE(&new->rbnode);
	update_alloc_size(oe, new, false);
	return new;
}

static struct ordered_event *
ordered_events__new_event(struct ordered_events *oe, u64 timestamp,
		    union perf_event *event)
{
	struct ordered_event *new;

	new = alloc_event(oe, event);
	if (new) {
		new->timestamp = timestamp;
		queue_event(oe, new);
	}

	return new;
}

void ordered_events__delete(struct ordered_events *oe, struct ordered_event *event)
{
	rb_erase_cached(&event->rbnode, &oe->events);
	list_add(&event->list, &oe->cache);
	oe->nr_events--;
	update_alloc_size(oe, event, true);
	free_dup_event(oe, event->event);
	event->event = NULL;
}

int ordered_events__queue(struct ordered_events *oe, union perf_event *event,
			  u64 timestamp, int instance)
{
	struct ordered_event *oevent;

	if (!timestamp || timestamp == ~0ULL)
		return -ETIME;

	if (timestamp < oe->last_flush) {
		oe->nr_unordered_events++;
	}

	oevent = ordered_events__new_event(oe, timestamp, event);
	if (!oevent) {
		ordered_events__flush_n(oe, 32);
		oevent = ordered_events__new_event(oe, timestamp, event);
	}

	if (!oevent)
		return -ENOMEM;

	oevent->instance = instance;
	return 0;
}

static int do_flush(struct ordered_events *oe, u64 limit, u32 n)
{
	struct rb_node *pos, *next = rb_first_cached(&oe->events);
	struct ordered_event *iter;
	int ret;

	if (!limit)
		return 0;

	while (next) {
		pos = next;
		next = rb_next(pos);

		iter = rb_entry(pos, struct ordered_event, rbnode);
		if (iter->timestamp > limit)
			break;
		ret = oe->deliver(oe, iter);
		if (ret)
			return ret;

		ordered_events__delete(oe, iter);
		oe->last_flush = iter->timestamp;

		n --;
		if (!n) break;
	}

	if (RB_EMPTY_ROOT(&oe->events.rb_root))
		oe->last = NULL;

	return 0;
}

static int __ordered_events__flush(struct ordered_events *oe, enum oe_flush how,
				   u64 arg)
{
	int err;
	u64 next_flush = 0;
	u32 n = oe->nr_events;

	if (oe->nr_events == 0)
		return 0;

	switch (how) {
	case OE_FLUSH__FINAL:
	case OE_FLUSH__TOP:
		next_flush = ULLONG_MAX;
		break;

	case OE_FLUSH__HALF:
	{
		struct ordered_event *first, *last;
		struct rb_node *pos = rb_first_cached(&oe->events);

		first = rb_entry_safe(pos, struct ordered_event, rbnode);
		last = oe->last;

		/* Warn if we are called before any event got allocated. */
		if (WARN_ONCE(!last || !first, "empty queue"))
			return 0;

		next_flush  = first->timestamp;
		next_flush += (last->timestamp - first->timestamp) / 2;
		break;
	}

	case OE_FLUSH__N:
		next_flush = ULLONG_MAX;
		n = arg;
		break;

	case OE_FLUSH__TIME:
		next_flush = arg;
		break;

	case OE_FLUSH__ROUND:
        next_flush = oe->round_flush;
        break;

	case OE_FLUSH__NONE:
	default:
		break;
	}

	err = do_flush(oe, next_flush, n);

	if (!err) {
		if (how == OE_FLUSH__ROUND)
			oe->round_flush = oe->max_timestamp;

		oe->last_flush_type = how;
	}

	return err;
}

int ordered_events__flush(struct ordered_events *oe, enum oe_flush how)
{
	return __ordered_events__flush(oe, how, 0);
}

int ordered_events__flush_time(struct ordered_events *oe, u64 timestamp)
{
	return __ordered_events__flush(oe, OE_FLUSH__TIME, timestamp);
}

int ordered_events__flush_n(struct ordered_events *oe, u64 n)
{
	return __ordered_events__flush(oe, OE_FLUSH__N, n);
}

u64 ordered_events__first_time(struct ordered_events *oe)
{
	struct rb_node *pos = rb_first_cached(&oe->events);
	struct ordered_event *event = rb_entry_safe(pos, struct ordered_event, rbnode);

	return event ? event->timestamp : 0;
}

void ordered_events__init(struct ordered_events *oe, ordered_events__deliver_t deliver,
			  void *data)
{
	oe->round_flush = 0;
	oe->max_timestamp = 0;
	oe->events = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&oe->cache);
	INIT_LIST_HEAD(&oe->to_free);
	oe->max_alloc_size = (u64) -1;
	oe->cur_alloc_size = 0;
	oe->deliver	   = deliver;
	oe->data	   = data;
}

static void
ordered_events_buffer__free(struct ordered_events_buffer *buffer,
			    unsigned int max, struct ordered_events *oe)
{
	if (oe->copy_on_queue) {
		unsigned int i;

		for (i = 0; i < max; i++)
			__free_dup_event(oe, buffer->event[i].event);
	}

	free(buffer);
}

void ordered_events__free(struct ordered_events *oe)
{
	struct ordered_events_buffer *buffer, *tmp;

	if (list_empty(&oe->to_free))
		return;

	/*
	 * Current buffer might not have all the events allocated
	 * yet, we need to free only allocated ones ...
	 */
	if (oe->buffer) {
		list_del_init(&oe->buffer->list);
		ordered_events_buffer__free(oe->buffer, oe->buffer_idx, oe);
	}

	/* ... and continue with the rest */
	list_for_each_entry_safe(buffer, tmp, &oe->to_free, list) {
		list_del_init(&buffer->list);
		ordered_events_buffer__free(buffer, MAX_SAMPLE_BUFFER, oe);
	}
}

void ordered_events__reinit(struct ordered_events *oe)
{
	ordered_events__deliver_t old_deliver = oe->deliver;
	void *old_data = oe->data;

	ordered_events__free(oe);
	memset(oe, '\0', sizeof(*oe));
	ordered_events__init(oe, old_deliver, old_data);
}
