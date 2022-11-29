# top

```
 Usage: perf-prof top [OPTION...] -e EVENT[...] [-i INT] [-k key] [--only-comm]

    Display key-value counters in top mode.

    SYNOPSIS
        Get the key from the event 'key' ATTR. Default, key=pid. Get the value from
        the event's 'top-by' or 'top-add' ATTR. Key is the counter and value is the
        value of the counter. Therefore, from multiple events, multiple counters are
        constructed with different keys. The same key, the value is accumulated.
        Finally, display these counters in top mode.

        If the -e parameter specifies multiple events, the key ATTR of these events
        must have the same meaning.

        For each event, multiple top-by and top-add ATTR can be specified.

        For events whose key has the meaning of pid, you can specify the 'comm' ATTR
        to display the process name.

    EXAMPLES
        perf-prof top -e kvm:kvm_exit//key=exit_reason/ -i 1000
        perf-prof top -e irq:irq_handler_entry//key=irq/ -C 0
        perf-prof top -e sched:sched_stat_runtime//top-by=runtime/ -C 0 -i 1000
        perf-prof top -e sched:sched_stat_runtime//top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/ -C 0 -i 1000

    NOTE
        Default, key=pid, comm=comm.

            -e sched:sched_stat_runtime//top-by=runtime/
            -e sched:sched_stat_runtime//top-by=runtime/key=pid/comm=comm/

        Are the same.

OPTION:
  -C, --cpus <CPU[-CPU],...>    Monitor the specified CPU, Dflt: all cpu
  -p, --pids <PID,...>          Attach to processes
  -t, --tids <TID,...>          Attach to threads
      --cgroups <cgroup,...>    Attach to cgroups, support regular expression.
  -i, --interval <ms>           Interval, Unit: ms
  -o, --output <file>           Output file name
      --order                   Order events by timestamp.
      --order-mem <Bytes>       Maximum memory used by ordering events. Unit: GB/MB/KB/*B.
  -m, --mmap-pages <pages>      Number of mmap data pages and AUX area tracing mmap pages
  -V, --version                 Version info
  -v, --verbose                 be more verbose
  -q, --quiet                   be more quiet
  -h, --help                    Give this help list

PROFILER OPTION:
  -e, --event <EVENT,...>       Event selector. use 'perf list tracepoint' to list available tp events.
                                  EVENT,EVENT,...
                                  EVENT: sys:name[/filter/ATTR/ATTR/.../]
                                  filter: ftrace filter
                                  ATTR:
                                      stack: sample_type PERF_SAMPLE_CALLCHAIN
                                      max-stack=int : sample_max_stack
                                      alias=str: event alias
                                      top-by=field: add to top, sort by this field
                                      top-add=field: add to top
                                      comm=field: top, show COMM
                                      ptr=field: kmemleak, ptr field, Dflt: ptr=ptr
                                      size=field: kmemleak, size field, Dflt: size=bytes_alloc
                                      num=field: num-dist, num field
                                      key=field: key for multiple events: top, multi-trace
                                      untraced: multi-trace, auxiliary, no two-event analysis
                                      trigger: multi-trace, use events to trigger interval output
  -k, --key <str>               Key for series events
      --only-comm               top: only show comm but not key
```

top主要作用是把单个事件按照key的值拆分成多个计数器，并按照top方式排序并呈现这些计数器。



# 原理

## 1 选定待分析的事件

如 sched:sched_wakeup。并分析事件的各个字段含义。可以利用末尾的`help`来查看事件的字段。

```
# ./perf-prof top -e sched:sched_wakeup help

perf-prof top -e "sched:sched_wakeup/./[alias=./top-by=./top-add=./key=./comm=./]" [-k .] [-C .] [-p .] [-i .] [-m .] [-v] 

sched:sched_wakeup
name: sched_wakeup
ID: 340
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:char comm[16];    offset:8;       size:16;        signed:1;
        field:pid_t pid;        offset:24;      size:4; signed:1;
        field:int prio; offset:28;      size:4; signed:1;
        field:int success;      offset:32;      size:4; signed:1;
        field:int target_cpu;   offset:36;      size:4; signed:1;

print fmt: "comm=%s pid=%d prio=%d success=%d target_cpu=%03d", REC->comm, REC->pid, REC->prio, REC->success, REC->target_cpu
```

- comm：进程名
- pid：进程id
- prio：进程优先级

## 2 选定要拆分的参数key

如：按照pid参数做拆分。

先从sched:sched_wakeup事件读取pid参数，不同的pid值将作为独立的计数器。

```
<...> 203395 d... [024] 2189785.311468: sched:sched_wakeup: monitor:203273 [120] success=1 CPU:072
<...> 203395 dNh. [024] 2189785.311473: sched:sched_wakeup: pal_session:114279 [100] success=1 CPU:024
<idle>      0 dNh. [024] 2189785.311736: sched:sched_wakeup: iscsid:46713 [110] success=1 CPU:024
```

- pid=203273，是一个计数器，用于跟踪monitor进程相关的计数。
- pid=114279，是一个计数器，用于跟踪pal_session进程相关的计数。
- pid=46713，是一个计数器，用于跟踪iscsid进程相关的计数。

选中的拆分参数，作为`key`。通过`key`属性和`-k`参数来指定该参数。

按下列顺序选择拆分字段：

- 如果指定`key`属性，则优先选择key属性。
- 如果未指定key属性，但指定`-k`参数，则选择-k参数。
- 如果key属性和-k参数都未指定，则判断选定事件是否存在"pid"字段。如果存在，则设定事件的默认key属性：`key=pid`；并判断选定事件是否存在"comm"属性，如果存在，则设定事件默认的comm属性：`comm=comm`。
- 如果上面都未选中，则从perf_event采样事件获取tid作为key，并读取/proc/tid/comm作为comm。tid是事件发生时刻的当前进程id。

```
perf-prof top -e sched:sched_wakeup//key=pid/  # 优先选择key属性
perf-prof top -e sched:sched_wakeup -k pid  # 其次是-k参数
perf-prof top -e sched:sched_wakeup  # 判断默认key属性：key=pid, comm=comm，等价于 sched:sched_wakeup//key=pid/comm=comm/
perf-prof top -e sched:sched_switch  # 无pid字段，key=发生sched_switch时的tid
```

## 3 向key添加计数器

选定拆分key之后，还需要向key添加计数器，计数器作为`value`。单个事件可以指定多个字段作为计数器。向key添加多个计数器，value内就会包含多个计数器值。

按下列顺序选择计数器：

- 如果指定`top-by`和`top-add`属性，则top-by和top-add指定的字段就会作为一个计数器添加到value内。每发生一个事件，从指定的事件读取指定的字段值，并累加到对应的value内的计数器上。
- 如果未指定top-by和top-add属性，则事件自身作为一个计数器添加到value，每发生一个事件value内的计数器加1。

```
perf-prof top -e sched:sched_wakeup//key=pid/  # 按照sched_wakeup事件自身做计数。
perf-prof top -e sched:sched_stat_runtime//top-by=runtime/  # 默认key属性：key=pid。按runtime来计数，不断累加runtime字段的值。
```

## 4 按top方式呈现这些计数器

top方式呈现，就是把这些计数器排序后显示。排序按照*从大到小*顺序排列。

按下列顺序排序：

- 如果指定`top-by`属性，则该计数器优先排序。
- 如果未指定top-by属性，则按照剩余的计数器排序。

如果指定`comm`属性，则key属性的含义必须是进程id。否则top显示是无意义的。comm值显示在行的末尾。

### 4.1 例1

```
# perf-prof top -e sched:sched_wakeup
2022-11-30 00:49:25.185638 perf-prof - 00:49:25  sample 33320 events
     PID SCHED_WAKEUP COMM            
  114279        15083 pal_session
  114255          957 pal_main
   54767          951 tbsd_ccd
   46713          947 iscsid
   29841          756 grep
  133219          101 python
```

等价于`perf-prof top -e sched:sched_wakeup//key=pid/comm=comm/`

sched:sched_wakeup事件使用pid作为拆分参数key，向key添加sched_wakeup计数器。其含义就是：按照pid拆分成多个计数器。key对应的value内只包含一个计数器。

- 从sched:sched_wakeup事件，读取key=pid字段作为key，并根据key找到value，递增value内的sched_wakeup计数器。

- PID=114279，内包含1个计数器，SCHED_WAKEUP=15083。含义是，进程114279总共发生15083次唤醒。

### 4.2 例2

```
# perf-prof top -e sched:sched_stat_runtime//top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/
2022-11-30 01:00:29.015117 perf-prof - 01:00:29  sample 19321 events
     PID      RUNTIME SCHED_SWITCH COMM            
  178657     19726743           37 python
  178697     14427853           24 ps
  106819     10580040          121 sap1008
  178428      7917486          205 perf-prof
  133204      6820715          738 python
```

等价于`perf-prof top -e sched:sched_stat_runtime//key=pid/top-by=runtime/comm=comm/,sched:sched_switch//key=prev_pid/comm=prev_comm/`

sched:sched_stat_runtime事件使用pid作为拆分参数key，sched:sched_switch事件使用prev_pid作为拆分参数key。其含义一致，都代表进程id。

向key添加2个计数器：`runtime`从sched:sched_stat_runtime事件的runtime字段取值并累加；`sched_switch`来自sched:sched_switch事件自身，每个事件加1。key对应的value内包含2个计数器。

- 从sched:sched_stat_runtime事件，读取key=pid字段作为key，并根据key找到value，并读取runtime字段累加到value的runtime计数器上。
- 从sched:sched_switch事件，读取key=prev_pid字段作为key，并根据key找到value，递增value的sched_switch计数器。
- PID=178657，内包含2个计数器，RUNTIME=19726743，SCHED_SWITCH=37。含义是：进程178657，共运行19726743ns，共发生进程切换37次。
- `top-by=runtime`runtime计数器会优先排序。

## 5 only-comm

`--only-comm`参数，可以控制只显示comm，不显示key。这种场景会使用comm作为key，根据comm来查找value，增加value内的计数器。

只要comm一样，就会找到相同的value，计数值会累加到一起。最新效果就是，可以根据comm来计数。

```
# perf-prof top -e sched:sched_stat_runtime//top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/ --only-comm
2022-11-30 01:40:57.177778 perf-prof - 01:40:57  sample 113096 events
     RUNTIME SCHED_SWITCH COMM            
  1000001489            0 worker2_1.47
   382746756         3806 sh
    96019497         1216 python
    88542906          563 awk
    72958796        14993 pal_session
    52932874          217 perf-prof
```

- python 进程，内部包含2个计数器，RUNTIME=96019497，SCHED_SWITCH=1216。python进程，可能是不同的pid，但comm都是python，计数值会统计到一起。最终效果：所有python进程共同运行96019497ns，共发生1216次进程切换。