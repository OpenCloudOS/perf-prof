#include <asm/types.h>
#include <linux/version.h>

// 最大调用栈深度
#define MAX_STACK_DEPTH 32
// 最大字符串长度
#define MAX_STR_LEN 128

struct perstack{
    u64 filefunc;
    u64 time;
    int lineno;
};
// 线程调用栈结构体
struct stack_t {
    u32 depth;
    struct perstack pystack[MAX_STACK_DEPTH];
};