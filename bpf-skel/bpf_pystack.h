#include <asm/types.h>
#include <linux/version.h>

#define MAX_STACK_DEPTH 32
#define MAX_STR_LEN 128

struct perstack{
    u64 filefunc;
    u64 time;
    int lineno;
};
struct stack_t {
    u32 depth;
    struct perstack pystack[MAX_STACK_DEPTH];
};
