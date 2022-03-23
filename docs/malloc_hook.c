#include <stdio.h>
#include <gperftools/malloc_hook_c.h>

static void NewHook(const void* ptr, size_t size)
{
}
static void DeleteHook(const void* ptr)
{
}

static __attribute__((constructor))
void init(void)
{
	MallocHook_AddNewHook(&NewHook);
	MallocHook_AddDeleteHook(&DeleteHook);
}

static __attribute__((destructor))
void deinit(void)
{
	MallocHook_RemoveNewHook(&NewHook);
	MallocHook_RemoveDeleteHook(&DeleteHook);
}

