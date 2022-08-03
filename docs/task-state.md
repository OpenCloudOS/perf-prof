# task-state

分析进程状态（睡眠状态，不可中断状态），在指定状态停留超过一定时间打印出内核栈和用户态栈。

共监控2个事件：

- **sched:sched_switch**，获取进程切换出去时的状态，及进程切换的时间。
- **sched:sched_wakeup**，获取进程唤醒时刻，用于计算在指定状态停留的时间。

还需要利用ftrace提供的filter功能，过滤特定的进程名，特定的进程状态。

```
用法:
    perf-prof task-state [-S] [-D] [--than ms] [--filter comm] [-C cpu] [-g [--flame-graph file]] [-m pages]
例子:
    perf-prof task-state -D --than 100 --filter nginx -g # 打印nginx进程D住超过100ms的栈。

  -S, --interruptible        TASK_INTERRUPTIBLE    S状态进程
  -D, --uninterruptible      TASK_UNINTERRUPTIBLE  D状态进程
      --than=ms              Greater than specified time, ms  在特定状态停留超过指定时间，ms单位。
      --filter=filter        event filter/comm filter  过滤进程名字
      --flame-graph=file     Specify the folded stack file  折叠栈文件
  -g, --call-graph           Enable call-graph recording  抓取栈
  -m, --mmap-pages=pages     number of mmap data pages and AUX area tracing mmap pages
  -C, --cpu=CPU              Monitor the specified CPU, Dflt: all cpu
```

