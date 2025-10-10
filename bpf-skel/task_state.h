#ifndef __TASK_STATE_H__
#define __TASK_STATE_H__

#include <asm/types.h>
#include <linux/version.h>

/* Task comm string length */
#define TASK_COMM_LEN 16

/* Task state flags (used in tsk->state) */
#define TASK_RUNNING            0x00000000
#define TASK_INTERRUPTIBLE      0x00000001
#define TASK_UNINTERRUPTIBLE    0x00000002
#define __TASK_STOPPED          0x00000004
#define __TASK_TRACED           0x00000008

/* Task exit state flags (used in tsk->exit_state) */
#define EXIT_DEAD               0x00000010
#define EXIT_ZOMBIE             0x00000020
#define EXIT_TRACE              (EXIT_ZOMBIE | EXIT_DEAD)

/* Additional task state flags */
#define TASK_PARKED             0x00000040
#define TASK_DEAD               0x00000080
#define TASK_WAKEKILL           0x00000100
#define TASK_WAKING             0x00000200
#define TASK_NOLOAD             0x00000400
#define TASK_NEW                0x00000800
#define TASK_RTLOCK_WAIT        0x00001000
#define TASK_FREEZABLE          0x00002000
#define __TASK_FREEZABLE_UNSAFE (0x00004000 * IS_ENABLED(CONFIG_LOCKDEP))
#define TASK_FROZEN             0x00008000
#define TASK_STATE_MAX          0x00010000
#define RUNDELAY                (TASK_STATE_MAX << 1)
#define TASK_ANY                (TASK_STATE_MAX - 1)

/* Composite state macros */
#define TASK_FREEZABLE_UNSAFE   (TASK_FREEZABLE | __TASK_FREEZABLE_UNSAFE)
#define TASK_KILLABLE           (TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED            (TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED             __TASK_TRACED
#define TASK_IDLE               (TASK_UNINTERRUPTIBLE | TASK_NOLOAD)
#define TASK_NORMAL             (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)
#define TASK_NO_INTERRUPTIBLE   -2

/* Stack and filter limits */
#define MAX_STACKS              32      // Maximum stack depth
#define MAX_COMM_FILTER         16      // Maximum number of comm filters

struct filters {
    bool pid;          // Filter by pid
    bool comm;         // Filter by comm
    int comm_num;      // Number of comm filters
    int state;         // Task state filter
    uint64_t latency;  // Latency threshold
    int stack;         // Stack trace enabled
    bool perins;       // Per-process statistics enabled
};

/* Key for state statistics map */
struct state_key {
    pid_t pid;         // -1 for system, pid for process
    int state;         // Task state
};

/* Value for state statistics map */
struct state_info {
    int calls;                 // Number of calls
    unsigned long total;       // Total time spent in this state (us)
    unsigned long min;         // Minimum time spent in this state (us)
    unsigned long max;         // Maximum time spent in this state (us)
    unsigned long p50;         // 50th percentile (us)
    unsigned long p95;         // 95th percentile (us)
    unsigned long p99;         // 99th percentile (us)
};

/* Last state info for a task */
struct task_last_state {
    int memused;               // Memory used
    uint64_t readchar;         // Bytes read
    uint64_t writechar;        // Bytes written
    uint64_t freepages_delay;  // Free pages delay
    uint64_t thrashing_delay;  // Thrashing delay
    uint64_t swapin_delay;     // Swap-in delay
};

/* State node for a task */
struct task_state_node {
    pid_t pid;                 // Process ID
    pid_t tgid;                // Thread Group ID
    char comm[TASK_COMM_LEN];  // Command name
    unsigned long long last_time; // Timestamp (ns)
    int last_state;            // Last state
    int last_user_stack_id;    // Last user stack ID
    int last_kern_stack_id;    // Last kernel stack ID
    bool has_state_info;       // State info available
    int priority;              // Task priority
    struct task_last_state curr_state_info; // Current state info
};

/* Stack trace event structure */
struct stacktrace_event {
    pid_t pid;                 // Process ID
    uint64_t latency;          // Latency (ns)
    uint64_t total_delay;      // Total delay (ns)
    int state;                 // Task state
    int last_user_stack_id;    // Last user stack ID
    int last_kern_stack_id;    // Last kernel stack ID
    int user_stack_id;         // User stack ID
    int kern_stack_id;         // Kernel stack ID
};

#endif /* __TASK_STATE_H__ */