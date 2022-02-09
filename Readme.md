# 基于perf的监控框架

基于`libperf`和`libtraceevent`库实现简单的监控框架，提供比perf更灵活的特性。

- 数据不落盘。
- 数据过滤，基于tracepoint的过滤机制，减少数据量。
- 数据实时处理并输出。不需要存盘后再处理。
- 基于perf_event_open系统调用。

虽然比perf更灵活，但不能替代perf。perf灵活的符号处理，支持大量的event，支持很多硬件PMU特性。

## 1 框架介绍

```
# ./perf-monitor  --help
Usage: perf-monitor [OPTION...]
Monitor based on perf_event

USAGE:
    perf-monitor split-lock [-T trigger] [-C cpu] [-G] [-i INT] [--test]
    perf-monitor irq-off [-L lat] [-C cpu] [-g] [-m pages] [--precise]
    perf-monitor profile [-F freq] [-C cpu] [-g [--flame-graph file [-i INT]]] [-m pages] [--exclude-*] [-G] [--than PCT]
    perf-monitor cpu-util [-i INT] [-C cpu] [--exclude-*] [-G]
    perf-monitor trace -e event [--filter filter] [-C cpu] [-g [--flame-graph file [-i INT]]]
    perf-monitor signal [--filter comm] [-C cpu] [-g] [-m pages]
    perf-monitor task-state [-S] [-D] [--than ms] [--filter comm] [-C cpu] [-g [--flame-graph file]] [-m pages]
    perf-monitor watchdog [-F freq] [-g] [-m pages] [-C cpu] [-v]
    perf-monitor kmemleak --alloc tp --free tp [-m pages] [-g [--flame-graph file]] [-v]
    perf-monitor percpu-stat -i INT [-C cpu] [--syscalls]
    perf-monitor kvm-exit [-C cpu] [-p PID] [-i INT] [--perins] [--than us]
    perf-monitor mpdelay -e EVENT[...] [-C cpu] [-p PID] [-i INT] [--perins] [--than us]
    perf-monitor --symbols /path/to/bin

      --alloc=tp             Memory alloc tracepoint/kprobe
  -C, --cpu=CPU              Monitor the specified CPU, Dflt: all cpu
  -D, --uninterruptible      TASK_UNINTERRUPTIBLE
  -e, --event=EVENT,...      Event selector. use 'perf list tracepoint' to list available tp events.
                             EVENT,EVENT,...
                             EVENT: sys:name/filter/ATTR/ATTR/.../
                             ATTR:
                                 stack: sample_type PERF_SAMPLE_CALLCHAIN
      --exclude-guest        exclude guest
      --exclude-kernel       exclude kernel
      --exclude-user         exclude user
      --filter=filter        Event filter/comm filter
      --flame-graph=file     Specify the folded stack file.
      --free=tp              Memory free tracepoint/kprobe
  -F, --freq=n               Profile at this frequency, Dflt: 100, No profile: 0
  -g, --call-graph           Enable call-graph recording
  -G, --guest                Monitor GUEST, Dflt: false
  -i, --interval=INT         Interval, ms
  -L, --latency=LAT          Interrupt off latency, unit: us, Dflt: 20ms
  -m, --mmap-pages=pages     Number of mmap data pages and AUX area tracing mmap pages
  -p, --pids=PID,PID         Attach to processes
      --perins               Print per instance stat
      --precise              Generate precise interrupt
      --symbols=symbols      Maps addresses to symbol names.
                             Similar to pprof --symbols.
      --syscalls             Trace syscalls
  -S, --interruptible        TASK_INTERRUPTIBLE
      --test                 Split-lock test verification
      --than=ge              Greater than specified time, ms/us/percent
  -T, --trigger=T            Trigger Threshold, Dflt: 1000, No trigger: 0
  -v, --verbose              Verbose debug output
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional for any corresponding short options.
```

监控框架采用模块化设计，目前支持一些基础的监控模块：

- split-lock，监控硬件pmu，发生split-lock的次数，以及触发情况。
- irq-off，监控中断关闭的情况。
- profile，分析采样栈，可以分析内核态CPU利用率超过一定百分比抓取内核态栈。
- cpu-util，cpu利用率监控，可以监控到guest模式的CPU利用率。派生自profile。
- trace，读取某个tracepoint事件。
- signal，监控给特定进程发送的信号。
- task-state，监控进程处于D、S状态的时间，超过指定时间可以打印栈。
- watchdog，监控hard、soft lockup的情况，在将要发生时，预先打印出内核栈。
- kmemleak，监控alloc、free的情况，判断可能的内存泄露。
- kvm-exit，监控虚拟化指令的延迟。

每个监控模块都需要定义一个`struct monitor `结构，来指定如何初始化、过滤、释放监控事件，以及如何处理采样到的监控事件。

## 2 Example: signal

一个最简单demo例子。

```
struct monitor monitor_signal = {
    .name = "signal",
    .pages = 2,
    .init = signal_init,
    .filter = signal_filter,
    .deinit = signal_exit,
    .sample = signal_sample,
};
ONITOR_REGISTER(monitor_signal)
```

定义模块初始化、过滤、销毁、处理采样等接口。

## 3 monitor.init

```
static int signal_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = 1,
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;
    int id;

    if (monitor_ctx_init(env) < 0)
        return -1;

    id = tep__event_id("signal", "signal_generate");
    if (id < 0)
        return -1;

    attr.config = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}
```

定义perf_event_attr表示监控的事件。

tep__event_id("signal", "signal_generate")，获取signal:signal_generate tracepoint点的id。

perf_evsel__new(&attr)，根据perf事件，创建evsel。1个evsel表示一个特点的事件，拿着这个事件可以到对应的cpu、线程上创建出perf_event。

perf_evlist__add(evlist, evsel)，加到evlist。一个evlist表示一组evsel事件。

### 3.1 perf_event_attr

定义event的属性。可以指定perf命令定义的所有事件。

- 硬件pmu事件
  - breakpoint事件
  - cpu事件
  - uncore事件
- tracepoint点事件
- kprobe事件
- uprobe事件

可以通过`ls /sys/bus/event_source/devices`命令看到所有的事件类型。

- **perf_event_attr.type** 事件类型

  ```
  PERF_TYPE_*
  	通过`cat /sys/bus/event_source/devices/*/type`获取类型。
  ```

- **perf_event_attr.config** 事件配置

  ```
  根据不同的type, config值不一样。
  	PERF_TYPE_TRACEPOINT: config 指定tracepoint点的id.
  	PERF_TYPE_HARDWARE: config 指定特定的参数PERF_COUNT_HW_*
  ```

- **perf_event_attr.sample_period** 采样周期

  ```
  定义采样周期, 发生多少次事件之后, 发起1个event到ring buffer
  ```

- **perf_event_attr.sample_type** 采样类型

  ```
  PERF_SAMPLE_*
  	定义放到ring buffer的事件, 需要哪些字段
  ```

- **perf_event_attr.comm**

  ```
  PERF_RECORD_COMM
  	记录进程comm和pid/tid的对应关系, 可以用于libtraceevent模块中tep_register_comm,
  	之后tep_print_event(ctx.tep, &s, &record, "%s", TEP_PRINT_COMM)就能打印出进程名
  	这样只能收集新创建进程的名字, 已启动进程的pid使用/proc/pid/comm来获取.
  ```

- **perf_event_attr.task**

  ```
  PERF_RECORD_FORK/PERF_RECORD_EXIT
  	记录进程创建和退出事件
  ```

- **perf_event_attr.context_switch**

  ```
  PERF_RECORD_SWITCH/PERF_RECORD_SWITCH_CPU_WIDE
  	记录进程切换信息
  ```

## 4 monitor.sample

```
static void signal_sample(union perf_event *event)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_data {
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        __u64   time;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        struct {
            __u32   size;
	        __u8    data[0];
        } raw;
    } *data = (void *)event->sample.array;

    tep__update_comm(NULL, data->tid_entry.tid);
    print_time(stdout);
    tep__print_event(data->time/1000, data->cpu_entry.cpu, data->raw.data, data->raw.size);
}
```

根据`perf_event_attr.sample_type`来定义采样的事件的字段，可以还原出一个结构体。

tep__print_event，打印tracepoint事件。

## 5 其他功能

### 5.1 traceevent插件

```
TRACEEVENT_PLUGIN_DIR
	export TRACEEVENT_PLUGIN_DIR=$(pwd)/lib/traceevent/plugins
	可以加载libtraceevent的插件
```

### 5.2 trace_helper

- **ksyms**，内核符号表，用于解析内核栈。符号信息来自于`/proc/kallsyms`
- **syms**，用户态符号表，用于解析用户栈。符号信息来自可执行程序和动态库的符号表。
- **hist**，直方图，log2，linear。

初始代码来自于bcc项目。

### 5.3 用户态符号表

用户态符号表，使用`syms_cache`结构表示，通过pid找到特定于进程的`syms`符号集合。

syms符号集合由/proc/pid/maps内所有的文件映射组成，每一个文件映射由一个`dso`来表示，syms包含dso的集合。

每个dso由映射到进程地址空间内的[起始地址、结束地址、文件对象]表示。文件对象由`object`结构表示。

object结构表示一个动态库的符号集合，由多个`sym`组成。object是可以给多个进程共享的，通过引用计数管理object的引用和释放。

sym表示一个特定的符号。由符号名字，起始地址，大小组成。

```
syms_cache --> syms --> dso --> object --> sym
```

### 5.4 用户态内存泄露检测

```
LD_PRELOAD=/lib64/libtcmalloc.so HEAPCHECK=draconian PPROF_PATH=./perf-monitor /path/to/bin
```

利用tcmalloc的内存泄露检测功能。

- **LD_PRELOAD=**，预先加载tcmalloc库，替换glibc库的malloc和free函数。
- **HEAPCHECK=**，内存泄露检测。draconian检测所有的内存泄露。
- **PPROF_PATH=**，指定符号解析命令。`perf-monitor --symbols`具备跟`pprof --symbols`一样的符号解析能力。

### 5.5 栈的处理

栈的处理方式各种各样，如perf top风格的栈负载处理，火焰图风格的栈处理。

perf-monitor目前支持的栈处理。

- 栈及符号打印。用`callchain_ctx`表示，定义了栈的打印风格，可控制内核态、用户态、地址、符号、偏移量、dso、正向栈、反向栈。每个栈帧的分隔符、栈的分隔符。
- key-value栈。以栈做为key，可以过滤重复栈，并能唯一寻址value。用`key_value_paires`结构表示，一般相同的栈都有类似的作用，如内存分配栈，可以分析相同的栈分配的总内存量，未释放的总内存量。类似于gperftools提供的HEAPCHECKE功能，最后报告的内存泄露是以栈为基准的。
- 火焰图。把相同的栈以及栈的每一帧聚合到一起。用`flame_graph`结构表示，能够生成折叠栈格式：反向栈、每帧以";"分隔、末尾是栈的数量。例子：`swapper;start_kernel;rest_init;cpu_idle;default_idle;native_safe_halt 1`。使用[flamegraph.pl](https://github.com/brendangregg/FlameGraph/blob/master/flamegraph.pl)生成火焰图。

### 5.6 火焰图

perf-monitor仅输出折叠栈格式，并对输出栈比较多的模块做了支持。目前已支持：`profile, task-state, kmemleak, trace`

原先在stdout直接输出栈，目前切换成火焰图之后，不会再输出栈，而是会在命令结束时输出火焰图折叠栈文件。通过`[-g [--flame-graph file]]`参数启用火焰图，必须支持栈(-g)才能输出火焰图。折叠栈文件以`file.folded`命名。使用`flamegraph.pl`最终生成svg火焰图。

```
$ perf-monitor task-state -S --than 100 --filter cat -g --flame-graph cat
$ flamegraph.pl cat.folded > cat.svg
```

#### 5.6.1 按时间的火焰图

是以固定间隔输出折叠栈，折叠栈包含时间戳。最终生成的火焰图是按时间排序的。对于长时间的监控，可以根据时间戳查找问题。

```
$ grep "15:46:33" cat.folded | flamegraph.pl > cat.svg #生成15:46:33秒开始的火焰图
```

#### 5.6.2 网络丢包火焰图

```
$ perf-monitor trace -e skb:kfree_skb -g --flame-graph kfree_skb -m 128 #监控丢包
$ perf-monitor trace -e skb:kfree_skb -g --flame-graph kfree_skb -i 600000 -m 128 #每600秒间隔输出火焰图
$ flamegraph.pl --reverse  kfree_skb.folded > kfree_skb.svg #生成火焰图
```

#### 5.6.3 CPU性能火焰图

```
$ perf-monitor profile -F 1000 -C 0,1 --exclude-user -g --flame-graph profile #采样内核态CPU利用率的火焰图
$ perf-monitor profile -F 1000 -C 0,1 --exclude-user -g --flame-graph profile -i 600000 #每600秒间隔输出火焰图
$ grep "15:46:33" profile.folded | flamegraph.pl > profile.svg #生成15:46:33秒开始600秒的火焰图
```



## 6 已支持的模块

### 6.1 watchdog

监控hard、soft lockup的情况，在将要发生时，预先打印出内核栈。

总共监控5个事件。

- **timer:hrtimer_expire_entry**，加上过滤器，用于跟踪watchdog_timer_fn的执行。
- **timer:hrtimer_start**，加上过滤器，监控watchdog_timer的启动。
- **timer:hrtimer_cancel**，加上过滤器，监控watchdog_timer的取消。
- **sched:sched_switch**，加上过滤器，监控watchdog线程的运行。
- **pmu:bus-cycles**，用于定时发起NMI中断，采样内核栈。

在pmu:bus-cycles事件发生时，判断hard lockup，如果预测将要发生硬死锁，就输出抓取的内核栈。

在timer:hrtimer_expire_entry事件发生时，判断soft lockup，如果预测将要发生软死锁，就输出线程调度信息和pmu:bus-cycles事件采样的内核栈。

在发生hardlockup时，一般伴随着长时间关闭中断，可能会导致其他cpu执行也卡住，导致perf-monitor工具也无法执行。这样的场景，可以借助crash来分析内核perf_event的ring buffer来获取到一定的栈。虽然工具无法执行，但采样还是会持续采的。

```
用法:
	perf-monitor watchdog -F 1 -g

  -F, --freq=n               指定采样的频率，采样是使用内核的pmu事件，会发起nmi中断，-F指定发起nmi中断的频率。
  -g, --call-graph           抓取内核栈，发起pmu事件时，把内核态栈采样到。
  -C, --cpu=CPU              指定在哪些cpu上启用watchdog监控，不指定默认会读取/proc/sys/kernel/watchdog_cpumask来确定所有启用的CPU，默认开启nohzfull的cpu不启用watchdog。
```



### 6.2 profile

分析采样栈，可以分析内核态CPU利用率超过一定百分比抓取内核态栈。

统计cpu利用率，利用pmu可以过滤用户态和内核态的功能，统计1秒内内核态的cycle数，除以tsc频率，就能计算出%sys占比。

共监控1个事件。

- **pmu:ref-cycles**，参数时钟默认以固定频率运行，以tsc的频率运行。会先从内核获取tsc_khz的频率，然后固定间隔采样。

```
用法:
	perf-monitor profile [-F freq] [-C cpu] [-g [--flame-graph file [-i INT]]] [-m pages] [--exclude-*] [-G] [--than PCT]
例子:
	perf-monitor profile -F 100 -C 0 -g --exclude-user --than 30  #对cpu0采样，在内核态利用率超过30%打印内核栈。

  -F, --freq=n               以固定频率采样。
  -i, --interval=INT         以固定间隔输出火焰图。单位ms
  -C, --cpu=CPU              指定在哪些cpu上采样栈。
  -g, --call-graph           抓取采样点的栈。
      --exclude-user         过滤掉用户态的采样，只采样内核态，可以减少采样点。降低cpu压力。
      --exclude-kernel       过滤掉内核态采样，只采样用户态。
      --exclude-guest        过滤掉guest，保留host。
      --flame-graph=file     指定folded stack file.
  -G, --guest                过滤掉host，保留guest。
      --than=PCT             百分比，指定采样的用户态或者内核态超过一定百分比才输出信息，包括栈信息。可以抓取偶发内核态占比高的问题。
```

### 6.3 task-state

分析进程状态（睡眠状态，不可中断状态），在指定状态停留超过一定时间打印出内核栈和用户态栈。

共监控2个事件：

- **sched:sched_switch**，获取进程切换出去时的状态，及进程切换的时间。
- **sched:sched_wakeup**，获取进程唤醒时刻，用于计算在指定状态停留的时间。

还需要利用ftrace提供的filter功能，过滤特定的进程名，特定的进程状态。

```
用法:
    perf-monitor task-state [-S] [-D] [--than ms] [--filter comm] [-C cpu] [-g [--flame-graph file]] [-m pages]
例子:
    perf-monitor task-state -D --than 100 --filter nginx -g # 打印nginx进程D住超过100ms的栈。

  -S, --interruptible        TASK_INTERRUPTIBLE    S状态进程
  -D, --uninterruptible      TASK_UNINTERRUPTIBLE  D状态进程
      --than=ms              Greater than specified time, ms  在特定状态停留超过指定时间，ms单位。
      --filter=filter        event filter/comm filter  过滤进程名字
      --flame-graph=file     Specify the folded stack file  折叠栈文件
  -g, --call-graph           Enable call-graph recording  抓取栈
  -m, --mmap-pages=pages     number of mmap data pages and AUX area tracing mmap pages
  -C, --cpu=CPU              Monitor the specified CPU, Dflt: all cpu
```

### 6.4 kmemleak

分析内存泄露，一般内存分配都对应alloc和free两个点。内存泄露，alloc之后永远不会释放。

工具原理：

- 在alloc点抓到对应的内存分配信息，进程id、comm、内核栈、分配时间。并存到alloc链表里。
- 在free点，从alloc链表查找alloc信息。能找到，说明正确的分配和释放，删除alloc链表的记录。找不到说明在工具启动前分配的，直接丢弃。
- alloc和free之间通过`ptr`指针关联起来。动态增加的alloc/free tracepoint点需要ptr指针。
- 在工具结束时，打印所有alloc链表的信息。即为，*最可能的内存泄露点*。工具执行时间越久，越能得到最准确的信息。

可以解决内核[kmemleak](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/dev-tools/kmemleak.rst)工具不支持percpu内存泄露问题。

共监控2个事件：

- **alloc**，需要自己指定，可以是`kmem:kmalloc、pcpu_alloc`等分配内存点。alloc点需要获取内核栈。
- **free**，需要自己指定，与alloc相对应。可以是`kmem:kfree、free_percpu`等释放内存点。free点不需要栈信息。

```
用法:
    perf-monitor kmemleak --alloc tp --free tp [-m pages] [-g [--flame-graph file]] [-v]
例子:
    echo 'r:alloc_percpu pcpu_alloc ptr=$retval' >> /sys/kernel/debug/tracing/kprobe_events #ptr指向分配的内存地址
    echo 'p:free_percpu free_percpu ptr=%di' >> /sys/kernel/debug/tracing/kprobe_events
    perf-monitor kmemleak --alloc kprobes:alloc_percpu --free kprobes:free_percpu -m 8 -g

      --alloc=tp             memory alloc tracepoint/kprobe
      --free=tp              memory free tracepoint/kprobe
      --flame-graph=file     Specify the folded stack file.
  -g, --call-graph           Enable call-graph recording
  -m, --mmap-pages=pages     number of mmap data pages and AUX area tracing mmap pages
  -v, --verbose              Verbose debug output
```

### 6.5 kvm-exit

在虚拟化场景，大部分指令都不需要退出到kvm模块，但少量特权指令需要退出，由kvm模块拦截并模拟执行指令。该工具可以监控指令执行的耗时分布。

类似`perf trace -s`可以统计系统调用耗时分布一样，`perf-monitor kvm-exit`可以统计特权指令的耗时分布。

共监控2个tracepoint点：

- kvm:kvm_exit，特权指令退出到kvm模块。
- kvm:kvm_entry，特权指令执行完成，进入guest。

```
用法:
	perf-monitor kvm-exit [-C cpu] [-p PID] [-i INT] [--perins] [--than us] [-v]
例子:
	perf-monitor kvm-exit -C 5-20,53-68 -i 1000 --than 1000 #统计CPU上的特权指令耗时,每1000ms输出一次,并打印耗时超过1000us的日志


  -C, --cpu=CPU              Monitor the specified CPU, Dflt: all cpu
  -p, --pids=PID,PID         Attach to processes
  -i, --interval=INT         Interval, ms
      --perins               print per instance stat 打印每个实例的统计信息
      --than=ge              Greater than specified time, us 微妙单位
  -m, --mmap-pages=pages     number of mmap data pages and AUX area tracing mmap pages
  -v, --verbose              Verbose debug output
```

例子输出

```
$ ./perf-monitor kvm-exit -C 5-20,53-68 -i 1000 --than 1000
2021-12-12 16:11:10.214139            <...> 206966 .N.. [017] 15504452.408994: kvm:kvm_exit: reason EXTERNAL_INTERRUPT rip 0xffffffff81c01f58 info 0 800000fd
2021-12-12 16:11:10.214203            <...> 206966 d... [017] 15504452.412981: kvm:kvm_entry: vcpu 20
2021-12-12 16:11:10.287391            <...> 206966 .N.. [017] 15504452.473318: kvm:kvm_exit: reason EXTERNAL_INTERRUPT rip 0xffffffff81063be2 info 0 800000fd
2021-12-12 16:11:10.287441            <...> 206966 d... [017] 15504452.485435: kvm:kvm_entry: vcpu 20
2021-12-12 16:11:10.437325 
     kvm-exit latency(ns) : count    distribution
         0 -> 255        : 0        |                                        |
       256 -> 511        : 2728     |**                                      |
       512 -> 1023       : 53994    |****************************************|
      1024 -> 2047       : 12247    |*********                               |
      2048 -> 4095       : 718      |                                        |
      4096 -> 8191       : 82       |                                        |
      8192 -> 16383      : 10       |                                        |
     16384 -> 32767      : 1        |                                        |
     32768 -> 65535      : 1        |                                        |
     65536 -> 131071     : 0        |                                        |
    131072 -> 262143     : 0        |                                        |
    262144 -> 524287     : 0        |                                        |
    524288 -> 1048575    : 0        |                                        |
   1048576 -> 2097151    : 0        |                                        |
   2097152 -> 4194303    : 1        |                                        |
   4194304 -> 8388607    : 0        |                                        |
   8388608 -> 16777215   : 1        |                                        |
exit_reason             calls        total(us)   min(us)   avg(us)      max(us)
-------------------- -------- ---------------- --------- --------- ------------
HLT                     40619     24054882.841     0.690   592.207    15776.440
MSR_WRITE               65240        56540.696     0.450     0.866        9.316
EXTERNAL_INTERRUPT       2035        17504.350     0.465     8.601    12116.764
VMCALL                   2173         4309.715     0.865     1.983        8.601
PAUSE_INSTRUCTION         202          226.786     0.546     1.122        3.497
IO_INSTRUCTION             37          217.492     1.703     5.878       34.496
CPUID                      96           82.303     0.611     0.857        2.506
```

可以看的有2次EXTERNAL_INTERRUPT退出，处理超过1000us，并输出对应的tracepoint点信息。

### 6.6 mpdelay

多点延迟（Multipoint delay）是指进程或cpu执行流经过多个点，每两个相邻点之间的延迟。

实际的场景有很多，如系统调用从进入到退出，中间可能会经过很多点。虚拟机vmexit到vmentry，中间会经过很多点。收包中断，到包走完协议栈的路径。

多个点，可以是静态的tracepoint点，也可以是通过kprobe动态增加的tracepoint点。最少需要定义2个点。

多个点的定义：

```
Event syntax:
   EVENT,EVENT,...
EVENT:
   sys:name/filter/ATTR/ATTR/.../
ATTR:
   stack : sample_type PERF_SAMPLE_CALLCHAIN
   ...
```

- sys，tracepoint点对应的system。
- name，tracepoint点的name。
- filter，过滤器。有些点需要特定的过滤，只输出我们需要的。
- ATTR，属性。目前只定义了stack，获取tracepoint点的栈。

```
用法：
	perf-monitor mpdelay -e evt,evt[,evt] [-C cpu] [-p PID] [-i INT] [--perins] [--than us]
例子：
	./perf-monitor mpdelay -e 'syscalls:sys_enter_nanosleep,syscalls:sys_exit_nanosleep' -p 16023 -i 1000 --than 600 --perins
	# 监控进程16023的nanosleep系统调用，输出超过600us的情况。
	./perf-monitor mpdelay -e timer:hrtimer_start/function==0xffffffffc0537050/,timer:hrtimer_expire_entry/function==0xffffffffc0537050/,timer:hrtimer_expire_exit -C 1-21,25-45,49-69,73-93 -i 1000
	# 监控指定cpu上hrtimer的启动到执行完成的路径。

  -e, --event=evt[,evt]      event selector. use 'perf list tracepoint' to list available tp events
  -C, --cpu=CPU              Monitor the specified CPU, Dflt: all cpu
  -p, --pids=PID,PID         Attach to processes
  -i, --interval=INT         Interval, ms
      --perins               print per instance stat 打印每个实例的统计信息，cpu或者线程
      --than=ge              Greater than specified time, us 微妙单位
  -m, --mmap-pages=pages     number of mmap data pages and AUX area tracing mmap pages
  -v, --verbose              Verbose debug output
```

例子输出

```
$ ./perf-monitor mpdelay -e timer:hrtimer_start/function==0xffffffffc0537050/,timer:hrtimer_expire_entry/function==0xffffffffc0537050/,timer:hrtimer_expire_exit -C 1-21,25-45,49-69,73-93 -i 1000 --than 2000
2021-12-29 10:51:35.025780 
                     start => end                           calls        total(us)   min(us)   avg(us)      max(us)
--------------------------    -------------------------- -------- ---------------- --------- --------- ------------
       timer:hrtimer_start => timer:hrtimer_expire_entry    83485     83372310.556     2.440   998.650     1005.681
timer:hrtimer_expire_entry => timer:hrtimer_expire_exit     83620        41499.929     0.320     0.496        2.131
2021-12-29 10:51:36.028619 
                     start => end                           calls        total(us)   min(us)   avg(us)      max(us)
--------------------------    -------------------------- -------- ---------------- --------- --------- ------------
       timer:hrtimer_start => timer:hrtimer_expire_entry    83404     83248724.665     2.173   998.138     1003.088
timer:hrtimer_expire_entry => timer:hrtimer_expire_exit     83603        41795.723     0.310     0.499        2.085
```

