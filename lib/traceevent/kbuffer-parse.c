// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sys/utsname.h>

#include "kbuffer.h"

#define MISSING_EVENTS (1UL << 31)
#define MISSING_STORED (1UL << 30)

#define COMMIT_MASK ((1 << 27) - 1)

/* Absolute time stamps do not have the 5 MSB, take from the real time stamp */
#define TS_MSB		(0xf8ULL << 56)

enum {
	KBUFFER_FL_HOST_BIG_ENDIAN	= (1<<0),
	KBUFFER_FL_BIG_ENDIAN		= (1<<1),
	KBUFFER_FL_LONG_8		= (1<<2),
	KBUFFER_FL_OLD_FORMAT		= (1<<3),
};

#define ENDIAN_MASK (KBUFFER_FL_HOST_BIG_ENDIAN | KBUFFER_FL_BIG_ENDIAN)

/** kbuffer
 * @timestamp		- timestamp of current event
 * @lost_events		- # of lost events between this subbuffer and previous
 * @flags		- special flags of the kbuffer
 * @subbuffer		- pointer to the sub-buffer page
 * @data		- pointer to the start of data on the sub-buffer page
 * @index		- index from @data to the @curr event data
 * @curr		- offset from @data to the start of current event
 *			   (includes metadata)
 * @next		- offset from @data to the start of next event
 * @size		- The size of data on @data
 * @start		- The offset from @subbuffer where @data lives
 * @first		- The offset from @subbuffer where the first non time stamp event lives
 *
 * @read_4		- Function to read 4 raw bytes (may swap)
 * @read_8		- Function to read 8 raw bytes (may swap)
 * @read_long		- Function to read a long word (4 or 8 bytes with needed swap)
 */
struct kbuffer {
	unsigned long long 	timestamp;
	long long		lost_events;
	unsigned long		flags;
	void			*subbuffer;
	void			*data;
	unsigned int		index;
	unsigned int		curr;
	unsigned int		next;
	unsigned int		size;
	unsigned int		start;
	unsigned int		first;

	unsigned int (*read_4)(void *ptr);
	unsigned long long (*read_8)(void *ptr);
	unsigned long long (*read_long)(struct kbuffer *kbuf, void *ptr);
	int (*next_event)(struct kbuffer *kbuf);
};

static void *zmalloc(size_t size)
{
	return calloc(1, size);
}

static int host_is_bigendian(void)
{
	unsigned char str[] = { 0x1, 0x2, 0x3, 0x4 };
	unsigned int *ptr;

	ptr = (unsigned int *)str;
	return *ptr == 0x01020304;
}

static int do_swap(struct kbuffer *kbuf)
{
	return ((kbuf->flags & KBUFFER_FL_HOST_BIG_ENDIAN) + kbuf->flags) &
		ENDIAN_MASK;
}

static unsigned long long swap_8(unsigned long data)
{
	return ((data & 0xffULL) << 56) |
		((data & (0xffULL << 8)) << 40) |
		((data & (0xffULL << 16)) << 24) |
		((data & (0xffULL << 24)) << 8) |
		((data & (0xffULL << 32)) >> 8) |
		((data & (0xffULL << 40)) >> 24) |
		((data & (0xffULL << 48)) >> 40) |
		((data & (0xffULL << 56)) >> 56);
}

static unsigned int swap_4(unsigned int data)
{
	return ((data & 0xffULL) << 24) |
		((data & (0xffULL << 8)) << 8) |
		((data & (0xffULL << 16)) >> 8) |
		((data & (0xffULL << 24)) >> 24);
}

static void write_8(bool do_swap, void *ptr, unsigned long long data)
{
	if (do_swap)
		*(unsigned long long *)ptr = swap_8(data);
	else
		*(unsigned long long *)ptr = data;
}

static void write_4(bool do_swap, void *ptr, unsigned int data)
{
	if (do_swap)
		*(unsigned int *)ptr = swap_4(data);
	else
		*(unsigned int *)ptr = data;
}

static unsigned long long __read_8(void *ptr)
{
	unsigned long long data = *(unsigned long long *)ptr;

	return data;
}

static unsigned long long __read_8_sw(void *ptr)
{
	unsigned long long data = *(unsigned long long *)ptr;

	return swap_8(data);
}

static unsigned int __read_4(void *ptr)
{
	unsigned int data = *(unsigned int *)ptr;

	return data;
}

static unsigned int __read_4_sw(void *ptr)
{
	unsigned int data = *(unsigned int *)ptr;

	return swap_4(data);
}

static unsigned long long read_8(struct kbuffer *kbuf, void *ptr)
{
	return kbuf->read_8(ptr);
}

static unsigned int read_4(struct kbuffer *kbuf, void *ptr)
{
	return kbuf->read_4(ptr);
}

static unsigned long long __read_long_8(struct kbuffer *kbuf, void *ptr)
{
	return kbuf->read_8(ptr);
}

static unsigned long long __read_long_4(struct kbuffer *kbuf, void *ptr)
{
	return kbuf->read_4(ptr);
}

static unsigned long long read_long(struct kbuffer *kbuf, void *ptr)
{
	return kbuf->read_long(kbuf, ptr);
}

static int calc_index(struct kbuffer *kbuf, void *ptr)
{
	return (unsigned long)ptr - (unsigned long)kbuf->data;
}

static int next_event(struct kbuffer *kbuf);
static int __next_event(struct kbuffer *kbuf);

/*
 * Just because sizeof(long) is 4 bytes, doesn't mean the OS isn't
 * 64bits
 */
static bool host_is_32bit(void)
{
	struct utsname buf;
	int ret;

	ret = uname(&buf);
	if (ret < 0) {
		/* Oh well, just assume it is 32 bit */
		return true;
	}
	/* If the uname machine value contains 64, assume the kernel is 64 bit */
	return strstr(buf.machine, "64") == NULL;
}

/**
 * kbuffer_alloc - allocat a new kbuffer
 * @size;	enum to denote size of word
 * @endian:	enum to denote endianness
 *
 * Allocates and returns a new kbuffer.
 */
struct kbuffer *
kbuffer_alloc(enum kbuffer_long_size size, enum kbuffer_endian endian)
{
	struct kbuffer *kbuf;
	int flags = 0;

	switch (size) {
	case KBUFFER_LSIZE_4:
		break;
	case KBUFFER_LSIZE_SAME_AS_HOST:
		if (sizeof(long) != 8 && host_is_32bit())
			break;
		/* fallthrough */
	case KBUFFER_LSIZE_8:
		flags |= KBUFFER_FL_LONG_8;
		break;
	default:
		return NULL;
	}

	switch (endian) {
	case KBUFFER_ENDIAN_LITTLE:
	case KBUFFER_ENDIAN_SAME_AS_HOST:
		break;
	case KBUFFER_ENDIAN_BIG:
		flags |= KBUFFER_FL_BIG_ENDIAN;
		break;
	default:
		return NULL;
	}

	kbuf = zmalloc(sizeof(*kbuf));
	if (!kbuf)
		return NULL;

	kbuf->flags = flags;

	if (host_is_bigendian()) {
		if (endian == KBUFFER_ENDIAN_SAME_AS_HOST)
			kbuf->flags |= KBUFFER_FL_BIG_ENDIAN;
		kbuf->flags |= KBUFFER_FL_HOST_BIG_ENDIAN;
	}

	if (do_swap(kbuf)) {
		kbuf->read_8 = __read_8_sw;
		kbuf->read_4 = __read_4_sw;
	} else {
		kbuf->read_8 = __read_8;
		kbuf->read_4 = __read_4;
	}

	if (kbuf->flags & KBUFFER_FL_LONG_8)
		kbuf->read_long = __read_long_8;
	else
		kbuf->read_long = __read_long_4;

	/* May be changed by kbuffer_set_old_format() */
	kbuf->next_event = __next_event;

	return kbuf;
}

/**
 * kbuffer_dup - duplicate a given kbuffer
 * @kbuf_orig; The kbuffer to duplicate
 *
 * Allocates a new kbuffer based off of anothe kbuffer.
 * Returns the duplicate on success or NULL on error.
 */
struct kbuffer *kbuffer_dup(struct kbuffer *kbuf_orig)
{
	struct kbuffer *kbuf;

	kbuf = malloc(sizeof(*kbuf));
	if (!kbuf)
		return NULL;

	*kbuf = *kbuf_orig;

	return kbuf;
}

/** kbuffer_free - free an allocated kbuffer
 * @kbuf:	The kbuffer to free
 *
 * Can take NULL as a parameter.
 */
void kbuffer_free(struct kbuffer *kbuf)
{
	free(kbuf);
}

/**
 * kbuffer_refresh - update the meta data from the subbuffer
 * @kbuf; The kbuffer to update
 *
 * If the loaded subbuffer changed its meta data (the commit)
 * then update the pointers for it.
 */
int kbuffer_refresh(struct kbuffer *kbuf)
{
	unsigned long long flags;
	unsigned int old_size;

	if (!kbuf || !kbuf->subbuffer)
		return -1;

	old_size = kbuf->size;

	flags = read_long(kbuf, kbuf->subbuffer + 8);
	kbuf->size = (unsigned int)flags & COMMIT_MASK;

	/* Update next to be the next element */
	if (kbuf->size != old_size && kbuf->curr == kbuf->next)
		next_event(kbuf);

	return 0;
}

static unsigned int type4host(struct kbuffer *kbuf,
			      unsigned int type_len_ts)
{
	if (kbuf->flags & KBUFFER_FL_BIG_ENDIAN)
		return (type_len_ts >> 29) & 3;
	else
		return type_len_ts & 3;
}

static unsigned int len4host(struct kbuffer *kbuf,
			     unsigned int type_len_ts)
{
	if (kbuf->flags & KBUFFER_FL_BIG_ENDIAN)
		return (type_len_ts >> 27) & 7;
	else
		return (type_len_ts >> 2) & 7;
}

static unsigned int type_len4host(struct kbuffer *kbuf,
				  unsigned int type_len_ts)
{
	if (kbuf->flags & KBUFFER_FL_BIG_ENDIAN)
		return (type_len_ts >> 27) & ((1 << 5) - 1);
	else
		return type_len_ts & ((1 << 5) - 1);
}

static unsigned int ts4host(struct kbuffer *kbuf,
			    unsigned int type_len_ts)
{
	if (kbuf->flags & KBUFFER_FL_BIG_ENDIAN)
		return type_len_ts & ((1 << 27) - 1);
	else
		return type_len_ts >> 5;
}

static void set_curr_to_end(struct kbuffer *kbuf)
{
	kbuf->curr = kbuf->size;
	kbuf->next = kbuf->size;
	kbuf->index = kbuf->size;
}

/*
 * Linux 2.6.30 and earlier (not much ealier) had a different
 * ring buffer format. It should be obsolete, but we handle it anyway.
 */
enum old_ring_buffer_type {
	OLD_RINGBUF_TYPE_PADDING,
	OLD_RINGBUF_TYPE_TIME_EXTEND,
	OLD_RINGBUF_TYPE_TIME_STAMP,
	OLD_RINGBUF_TYPE_DATA,
};

static unsigned int old_update_pointers(struct kbuffer *kbuf)
{
	unsigned long long extend;
	unsigned int type_len_ts;
	unsigned int type;
	unsigned int len;
	unsigned int delta;
	unsigned int length;
	void *ptr = kbuf->data + kbuf->curr;

	type_len_ts = read_4(kbuf, ptr);
	ptr += 4;

	type = type4host(kbuf, type_len_ts);
	len = len4host(kbuf, type_len_ts);
	delta = ts4host(kbuf, type_len_ts);

	switch (type) {
	case OLD_RINGBUF_TYPE_PADDING:
		kbuf->next = kbuf->size;
		return 0;

	case OLD_RINGBUF_TYPE_TIME_EXTEND:
		extend = read_4(kbuf, ptr);
		extend <<= TS_SHIFT;
		extend += delta;
		delta = extend;
		ptr += 4;
		length = 0;
		break;

	case OLD_RINGBUF_TYPE_TIME_STAMP:
		/* should never happen! */
		set_curr_to_end(kbuf);
		return -1;
	default:
		if (len)
			length = len * 4;
		else {
			length = read_4(kbuf, ptr);
			length -= 4;
			ptr += 4;
		}
		break;
	}

	kbuf->timestamp += delta;
	kbuf->index = calc_index(kbuf, ptr);
	kbuf->next = kbuf->index + length;

	return type;
}

static int __old_next_event(struct kbuffer *kbuf)
{
	int type;

	do {
		kbuf->curr = kbuf->next;
		if (kbuf->next >= kbuf->size)
			return -1;
		type = old_update_pointers(kbuf);
	} while (type == OLD_RINGBUF_TYPE_TIME_EXTEND || type == OLD_RINGBUF_TYPE_PADDING);

	return 0;
}

static unsigned int
translate_data(struct kbuffer *kbuf, void *data, void **rptr,
	       unsigned long long *delta, int *length)
{
	unsigned long long extend, msb = 0;
	unsigned int type_len_ts;
	unsigned int type_len;

	type_len_ts = read_4(kbuf, data);
	data += 4;

	type_len = type_len4host(kbuf, type_len_ts);
	*delta = ts4host(kbuf, type_len_ts);

	switch (type_len) {
	case KBUFFER_TYPE_PADDING:
		*length = read_4(kbuf, data);
		break;

	case KBUFFER_TYPE_TIME_STAMP:
		msb = kbuf->timestamp & TS_MSB;
		/* fall through */
	case KBUFFER_TYPE_TIME_EXTEND:
		extend = read_4(kbuf, data);
		data += 4;
		extend <<= TS_SHIFT;
		extend += *delta;
		*delta = extend | msb;
		*length = 0;
		break;

	case 0:
		*length = read_4(kbuf, data) - 4;
		*length = (*length + 3) & ~3;
		data += 4;
		break;
	default:
		*length = type_len * 4;
		break;
	}

	*rptr = data;

	return type_len;
}

static unsigned int update_pointers(struct kbuffer *kbuf)
{
	unsigned long long delta;
	unsigned int type_len;
	int length;
	void *ptr = kbuf->data + kbuf->curr;

	type_len = translate_data(kbuf, ptr, &ptr, &delta, &length);

	if (type_len == KBUFFER_TYPE_TIME_STAMP)
		kbuf->timestamp = delta;
	else
		kbuf->timestamp += delta;

	kbuf->index = calc_index(kbuf, ptr);
	kbuf->next = kbuf->index + length;

	return type_len;
}

/**
 * kbuffer_translate_data - read raw data to get a record
 * @swap:	Set to 1 if bytes in words need to be swapped when read
 * @data:	The raw data to read
 * @size:	Address to store the size of the event data.
 *
 * Returns a pointer to the event data. To determine the entire
 * record size (record metadata + data) just add the difference between
 * @data and the returned value to @size.
 */
void *kbuffer_translate_data(int swap, void *data, unsigned int *size)
{
	unsigned long long delta;
	struct kbuffer kbuf;
	int type_len;
	int length;
	void *ptr;

	if (swap) {
		kbuf.read_8 = __read_8_sw;
		kbuf.read_4 = __read_4_sw;
		kbuf.flags = host_is_bigendian() ? 0 : KBUFFER_FL_BIG_ENDIAN;
	} else {
		kbuf.read_8 = __read_8;
		kbuf.read_4 = __read_4;
		kbuf.flags = host_is_bigendian() ? KBUFFER_FL_BIG_ENDIAN: 0;
	}

	type_len = translate_data(&kbuf, data, &ptr, &delta, &length);
	switch (type_len) {
	case KBUFFER_TYPE_PADDING:
	case KBUFFER_TYPE_TIME_EXTEND:
	case KBUFFER_TYPE_TIME_STAMP:
		return NULL;
	}

	*size = length;

	return ptr;
}

static int __next_event(struct kbuffer *kbuf)
{
	int type;

	do {
		kbuf->curr = kbuf->next;
		if (kbuf->next >= kbuf->size)
			return -1;
		type = update_pointers(kbuf);
	} while (type == KBUFFER_TYPE_TIME_EXTEND ||
		 type == KBUFFER_TYPE_TIME_STAMP ||
		 type == KBUFFER_TYPE_PADDING);

	return 0;
}

static int next_event(struct kbuffer *kbuf)
{
	return kbuf->next_event(kbuf);
}

/**
 * kbuffer_next_event - increment the current pointer
 * @kbuf:	The kbuffer to read
 * @ts:		Address to store the next record's timestamp (may be NULL to ignore)
 *
 * Increments the pointers into the subbuffer of the kbuffer to point to the
 * next event so that the next kbuffer_read_event() will return a
 * new event.
 *
 * Returns the data of the next event if a new event exists on the subbuffer,
 * NULL otherwise.
 */
void *kbuffer_next_event(struct kbuffer *kbuf, unsigned long long *ts)
{
	int ret;

	if (!kbuf || !kbuf->subbuffer)
		return NULL;

	ret = next_event(kbuf);
	if (ret < 0)
		return NULL;

	if (ts)
		*ts = kbuf->timestamp;

	return kbuf->data + kbuf->index;
}

/**
 * kbuffer_load_subbuffer - load a new subbuffer into the kbuffer
 * @kbuf:	The kbuffer to load
 * @subbuffer:	The subbuffer to load into @kbuf.
 *
 * Load a new subbuffer (page) into @kbuf. This will reset all
 * the pointers and update the @kbuf timestamp. The next read will
 * return the first event on @subbuffer.
 *
 * Returns 0 on succes, -1 otherwise.
 */
int kbuffer_load_subbuffer(struct kbuffer *kbuf, void *subbuffer)
{
	unsigned long long flags;
	void *ptr = subbuffer;

	if (!kbuf || !subbuffer)
		return -1;

	kbuf->subbuffer = subbuffer;

	kbuf->timestamp = read_8(kbuf, ptr);
	ptr += 8;

	kbuf->curr = 0;

	if (kbuf->flags & KBUFFER_FL_LONG_8)
		kbuf->start = 16;
	else
		kbuf->start = 12;

	kbuf->data = subbuffer + kbuf->start;

	flags = read_long(kbuf, ptr);
	kbuf->size = (unsigned int)flags & COMMIT_MASK;

	if (flags & MISSING_EVENTS) {
		if (flags & MISSING_STORED) {
			ptr = kbuf->data + kbuf->size;
			kbuf->lost_events = read_long(kbuf, ptr);
		} else
			kbuf->lost_events = -1;
	} else
		kbuf->lost_events = 0;

	kbuf->index = 0;
	kbuf->next = 0;

	next_event(kbuf);

	/* save the first record from the page */
	kbuf->first = kbuf->curr;

	return 0;
}

/**
 * kbuffer_subbuf_timestamp - read the timestamp from a sub buffer
 * @kbuf:      The kbuffer to load
 * @subbuf:    The subbuffer to read from.
 *
 * Return the timestamp from a subbuffer.
 */
unsigned long long kbuffer_subbuf_timestamp(struct kbuffer *kbuf, void *subbuf)
{
	return kbuf->read_8(subbuf);
}

/**
 * kbuffer_ptr_delta - read the delta field from a record
 * @kbuf:      The kbuffer to load
 * @ptr:       The record in the buffe.
 *
 * Return the timestamp delta from a record
 */
unsigned int kbuffer_ptr_delta(struct kbuffer *kbuf, void *ptr)
{
	unsigned int type_len_ts;

	type_len_ts = read_4(kbuf, ptr);
	return ts4host(kbuf, type_len_ts);
}


/**
 * kbuffer_read_event - read the next event in the kbuffer subbuffer
 * @kbuf:	The kbuffer to read from
 * @ts:		The address to store the timestamp of the event (may be NULL to ignore)
 *
 * Returns a pointer to the data part of the current event.
 * NULL if no event is left on the subbuffer.
 */
void *kbuffer_read_event(struct kbuffer *kbuf, unsigned long long *ts)
{
	if (!kbuf || !kbuf->subbuffer)
		return NULL;

	if (kbuf->curr >= kbuf->size)
		return NULL;

	if (ts)
		*ts = kbuf->timestamp;
	return kbuf->data + kbuf->index;
}

/**
 * kbuffer_timestamp - Return the timestamp of the current event
 * @kbuf:	The kbuffer to read from
 *
 * Returns the timestamp of the current (next) event.
 */
unsigned long long kbuffer_timestamp(struct kbuffer *kbuf)
{
	return kbuf->timestamp;
}

/**
 * kbuffer_read_at_offset - read the event that is at offset
 * @kbuf:	The kbuffer to read from
 * @offset:	The offset into the subbuffer
 * @ts:		The address to store the timestamp of the event (may be NULL to ignore)
 *
 * The @offset must be an index from the @kbuf subbuffer beginning.
 * If @offset is bigger than the stored subbuffer, NULL will be returned.
 *
 * Returns the data of the record that is at @offset. Note, @offset does
 * not need to be the start of the record, the offset just needs to be
 * in the record (or beginning of it).
 *
 * Note, the kbuf timestamp and pointers are updated to the
 * returned record. That is, kbuffer_read_event() will return the same
 * data and timestamp, and kbuffer_next_event() will increment from
 * this record.
 */
void *kbuffer_read_at_offset(struct kbuffer *kbuf, int offset,
			     unsigned long long *ts)
{
	void *data;

	if (offset < kbuf->start)
		offset = 0;
	else
		offset -= kbuf->start;

	/* Reset the buffer */
	kbuffer_load_subbuffer(kbuf, kbuf->subbuffer);
	data = kbuffer_read_event(kbuf, ts);

	while (kbuf->curr < offset) {
		data = kbuffer_next_event(kbuf, ts);
		if (!data)
			break;
	}

	return data;
}

/**
 * kbuffer_subbuffer_size - the size of the loaded subbuffer
 * @kbuf:	The kbuffer to read from
 *
 * Returns the size of the subbuffer. Note, this size is
 * where the last event resides. The stored subbuffer may actually be
 * bigger due to padding and such.
 */
int kbuffer_subbuffer_size(struct kbuffer *kbuf)
{
	return kbuf->size;
}

/**
 * kbuffer_subbuffer - the currently loaded subbuffer
 * @kbuf:	The kbuffer to read from
 *
 * Returns the currently loaded subbuffer.
 */
void *kbuffer_subbuffer(struct kbuffer *kbuf)
{
	return kbuf->subbuffer;
}

/**
 * kbuffer_curr_index - Return the index of the record
 * @kbuf:	The kbuffer to read from
 *
 * Returns the index from the start of the data part of
 * the subbuffer to the current location. Note this is not
 * from the start of the subbuffer. An index of zero will
 * point to the first record. Use kbuffer_curr_offset() for
 * the actually offset (that can be used by kbuffer_read_at_offset())
 */
int kbuffer_curr_index(struct kbuffer *kbuf)
{
	return kbuf->curr;
}

/**
 * kbuffer_curr_offset - Return the offset of the record
 * @kbuf:	The kbuffer to read from
 *
 * Returns the offset from the start of the subbuffer to the
 * current location.
 */
int kbuffer_curr_offset(struct kbuffer *kbuf)
{
	return kbuf->curr + kbuf->start;
}

/**
 * kbuffer_event_size - return the size of the event data
 * @kbuf:	The kbuffer to read
 *
 * Returns the size of the event data (the payload not counting
 * the meta data of the record) of the current event.
 */
int kbuffer_event_size(struct kbuffer *kbuf)
{
	return kbuf->next - kbuf->index;
}

/**
 * kbuffer_curr_size - return the size of the entire record
 * @kbuf:	The kbuffer to read
 *
 * Returns the size of the entire record (meta data and payload)
 * of the current event.
 */
int kbuffer_curr_size(struct kbuffer *kbuf)
{
	return kbuf->next - kbuf->curr;
}

/**
 * kbuffer_missed_events - return the # of missed events from last event.
 * @kbuf: 	The kbuffer to read from
 *
 * Returns the # of missed events (if recorded) before the current
 * event. Note, only events on the beginning of a subbuffer can
 * have missed events, all other events within the buffer will be
 * zero.
 */
int kbuffer_missed_events(struct kbuffer *kbuf)
{
	/* Only the first event can have missed events */
	if (kbuf->curr)
		return 0;

	return kbuf->lost_events;
}

/**
 * kbuffer_set_old_forma - set the kbuffer to use the old format parsing
 * @kbuf:	The kbuffer to set
 *
 * This is obsolete (or should be). The first kernels to use the
 * new ring buffer had a slightly different ring buffer format
 * (2.6.30 and earlier). It is still somewhat supported by kbuffer,
 * but should not be counted on in the future.
 */
void kbuffer_set_old_format(struct kbuffer *kbuf)
{
	kbuf->flags |= KBUFFER_FL_OLD_FORMAT;

	kbuf->next_event = __old_next_event;
}

/**
 * kbuffer_start_of_data - return offset of where data starts on subbuffer
 * @kbuf:	The kbuffer
 *
 * Returns the location on the subbuffer where the data starts.
 */
int kbuffer_start_of_data(struct kbuffer *kbuf)
{
	return kbuf->first + kbuf->start;
}

/**
 * kbuffer_raw_get - get raw buffer info
 * @kbuf:	The kbuffer
 * @subbuf:	Start of mapped subbuffer
 * @info:	Info descriptor to fill in
 *
 * For debugging. This can return internals of the ring buffer.
 * Expects to have info->next set to what it will read.
 * The type, length and timestamp delta will be filled in, and
 * @info->next will be updated to the next element.
 * The @subbuf is used to know if the info is passed the end of
 * data and NULL will be returned if it is.
 */
struct kbuffer_raw_info *
kbuffer_raw_get(struct kbuffer *kbuf, void *subbuf, struct kbuffer_raw_info *info)
{
	unsigned long long flags;
	unsigned long long delta;
	unsigned int type_len;
	unsigned int size;
	int start;
	int length;
	void *ptr = info->next;

	if (!kbuf || !subbuf)
		return NULL;

	if (kbuf->flags & KBUFFER_FL_LONG_8)
		start = 16;
	else
		start = 12;

	flags = read_long(kbuf, subbuf + 8);
	size = (unsigned int)flags & COMMIT_MASK;

	if (ptr < subbuf || ptr >= subbuf + start + size)
		return NULL;

	type_len = translate_data(kbuf, ptr, &ptr, &delta, &length);

	info->next = ptr + length;

	info->type = type_len;
	info->delta = delta;
	info->length = length;

	return info;
}

/**
 * kbuffer_read_buffer - read a buffer like the kernel would perform a read
 * @kbuf: the kbuffer handle
 * @buffer: where to write the data into
 * @len; The length of @buffer
 *
 * This will read the saved sub buffer within @kbuf like the systemcall
 * of read() to the trace_pipe_raw would do. That is, if either @len
 * can not fit the entire buffer, or if the current index in @kbuf
 * is non-zero, it will write to @buffer a new subbuffer that could be
 * loaded into kbuffer_load_subbuffer(). That is, it will write into
 * @buffer a  legitimate sub-buffer with a header and all that has the
 * proper timestamp and commit fields.
 *
 * Returns the index after the last element written.
 * 0 if nothing was copied.
 * -1 on error (which includes not having enough space in len to
 *   copy the subbuffer header or any of its content. In otherwords,
 *   do not try again!
 *
 * @kbuf current index will be set to the next element to read.
 */
int kbuffer_read_buffer(struct kbuffer *kbuf, void *buffer, int len)
{
	unsigned long long ts;
	unsigned int type_len_ts;
	bool do_swap = false;
	int buf_len = len;
	int last_next;
	int save_curr;

	/* Are we at the end of the buffer */
	if (kbuf->curr >= kbuf->size)
		return 0;

	/* If we can not copy anyting, return -1 */
	if (len < kbuf->start)
		return -1;

	/* Check if the first event can fit */
	if (len < (kbuf->next - kbuf->curr) + kbuf->start)
		return -1;

	if (kbuf->read_8 ==  __read_8_sw)
		do_swap = true;

	/* Have this subbuffer timestamp be the current timestamp */
	write_8(do_swap, buffer, kbuf->timestamp);

	len -= kbuf->start;

	save_curr = kbuf->curr;

	/* Due to timestamps, we must save the current next to use */
	last_next = kbuf->next;

	while (len >= kbuf->next - save_curr) {
		last_next = kbuf->next;
		if (!kbuffer_next_event(kbuf, &ts))
			break;
	}

	len = last_next - save_curr;
	/* No event was found? */
	if (!len)
		return 0;

	memcpy(buffer + kbuf->start, kbuf->data + save_curr, len);

	/* Zero out the delta, as the sub-buffer has the timestamp */
	type_len_ts = read_4(kbuf, buffer + kbuf->start);

	if (kbuf->flags & KBUFFER_FL_BIG_ENDIAN)
		type_len_ts &= ~(((1 << 27) - 1));
	else
		type_len_ts &= ((1 << 5) - 1);

	write_4(do_swap, buffer + kbuf->start, type_len_ts);

	/*
	 * If reading the first event and there are lost events, add it
	 * to the buffer.
	 */
	if (!save_curr && kbuf->lost_events) {
		unsigned long long cnt_8;
		unsigned int cnt_4;
		int word_size;

		if (kbuf->flags & KBUFFER_FL_LONG_8)
			word_size = sizeof(cnt_8);
		else
			word_size = sizeof(cnt_4);

		if (len + kbuf->start <= word_size + buf_len) {
			if (word_size == sizeof(cnt_8)) {
				cnt_8 = kbuf->lost_events;
				write_8(do_swap, buffer + len + kbuf->start, cnt_8);
			} else {
				cnt_4 = kbuf->lost_events;
				write_4(do_swap, buffer + len + kbuf->start, cnt_4);
			}
			len |= MISSING_STORED;
		}
		len |= MISSING_EVENTS;
	}

	/* Update the size */
	if (kbuf->read_long == __read_long_8)
		write_8(do_swap, buffer + 8, len);
	else
		write_4(do_swap, buffer + 8, len);

	return last_next;
}
