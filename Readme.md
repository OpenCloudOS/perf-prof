# 基于perf的监控框架

基于`libperf`和`libtraceevent`库实现简单的监控框架，提供比perf更灵活的特性。

- 数据不落盘。
- 数据过滤，基于tracepoint的过滤机制，减少数据量。
- 数据实时处理并输出。不需要存盘后再处理。
- 基于perf_event_open系统调用。

虽然比perf更灵活，但不能替代perf。perf灵活的符号处理，支持大量的event，支持很多硬件PMU特性。

![perf-prof框架](docs/images/perf-prof_framework.png)



# 1 框架介绍

内核态，采样事件经过`filter`过滤之后，存放到`ringbuffer`上，并递增`counter`计数器。只有经过filter过滤出来的事件才会放到ringbuffer。

- 过滤器filter包含ebpf过滤器、pmu过滤器、ftrace过滤器(tracepoint)，过滤可以减少事件量，筛选出感兴趣的事件。
- 每个perf_event都有独立的ringbuffer，多个perf_event可以共用ringbuffer。ringbuffer上存放采样事件，包含一些基础数据，cpu、time、callchain等。采样默认关闭，通过`perf_event_attr.sample_period`参数开启采样。
- 每个perf_event都有独立counter，不能共享。counter默认开启，不能关闭。计数和采样可以同时开启。

用户态，**perf-prof**框架不断读取`ringbuffer`的采样事件和`counter`，经过`order`排序事件，最后送到`profiler`处理事件。

- order，按时间顺序排序事件，单个perf_event的ringbuffer上的事件是有序的，多个perf_event的ringbuffer不能保证顺序，需要排序合并起来。简化profiler的处理。order是可选项。

profiler，处理事件。决定打开哪些事件，如何处理事件。

- **profiler.init** 初始化`perf_event_attr`打开对应的evsel，添加到evlist上，最终由`libperf`库调用`perf_event_open`系统调用打开perf_event。perf_event_attr.exclude_相关属性，用来配置pmu过滤器。
- **profiler.filter**设置ebpf过滤器、ftrace过滤器。最终由libperf库通过ioctl设置到内核。
- **profiler.sample**不断处理采样事件，完成分析工作。

# 2 Example: signal

一个最简单demo例子。

```
static profiler monitor_signal = {
    .name = "signal",
    .pages = 2,
    .init = signal_init,
    .filter = signal_filter,
    .deinit = signal_exit,
    .sample = signal_sample,
};
PROFILER_REGISTER(monitor_signal)
```

定义模块初始化、过滤、销毁、处理采样等接口。

# 3 profiler.init

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

## 3.1 perf_event_attr

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

# 4 profiler.sample

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

# 5 基础功能

## 5.1 模块化

每个profiler都是独立的模块文件，可扩展，可裁减，损耗低。适合高性能监控场景。

## 5.2 栈

  - 栈及符号打印。可控制内核态、用户态、地址、符号、偏移量、dso、正向栈、反向栈，每个栈帧的分隔符、栈的分隔符。
  - 支持解析内核符号(/proc/kallsyms)，用户态符号(.symtab/.dynsym)、MiniDebugInfo解析(.gnu_debugdata)。
  - 支持debuginfo包。/usr/lib/debug/.build-id/
  - key-value栈。以栈做为key，可以过滤重复栈，并能唯一寻址value。
  - 生成火焰图折叠栈格式。

## 5.3 用户态符号表

用户态符号表，使用`syms_cache`结构表示，通过pid找到特定于进程的`syms`符号集合。

syms符号集合由/proc/pid/maps内所有的文件映射组成，每一个文件映射由一个`dso`来表示，syms包含dso的集合。

每个dso由映射到进程地址空间内的[起始地址、结束地址、文件对象]表示。文件对象由`object`结构表示。

object结构表示一个动态库的符号集合，由多个`sym`组成。object是可以给多个进程共享的，通过引用计数管理object的引用和释放。

sym表示一个特定的符号。由符号名字，起始地址，大小组成。

```
syms_cache --> syms --> dso --> object --> sym
```

## 5.4 用户态内存泄露检测

```
LD_PRELOAD=/lib64/libtcmalloc.so HEAPCHECK=draconian PPROF_PATH=./perf-prof /path/to/bin
```

利用tcmalloc的内存泄露检测功能。

- **LD_PRELOAD=**，预先加载tcmalloc库，替换glibc库的malloc和free函数。
- **HEAPCHECK=**，内存泄露检测。draconian检测所有的内存泄露。
- **PPROF_PATH=**，指定符号解析命令。`perf-prof --symbols`具备跟`pprof --symbols`一样的符号解析能力。

## 5.5 栈的处理

栈的处理方式各种各样，如perf top风格的栈负载处理，火焰图风格的栈处理。

perf-prof目前支持的栈处理。

- 栈及符号打印。用`callchain_ctx`表示，定义了栈的打印风格，可控制内核态、用户态、地址、符号、偏移量、dso、正向栈、反向栈。每个栈帧的分隔符、栈的分隔符。
- key-value栈。以栈做为key，可以过滤重复栈，并能唯一寻址value。用`key_value_paires`结构表示，一般相同的栈都有类似的作用，如内存分配栈，可以分析相同的栈分配的总内存量，未释放的总内存量。类似于gperftools提供的HEAPCHECKE功能，最后报告的内存泄露是以栈为基准的。
- 火焰图。把相同的栈以及栈的每一帧聚合到一起。用`flame_graph`结构表示，能够生成折叠栈格式：反向栈、每帧以";"分隔、末尾是栈的数量。例子：`swapper;start_kernel;rest_init;cpu_idle;default_idle;native_safe_halt 1`。使用[flamegraph.pl](https://github.com/brendangregg/FlameGraph/blob/master/flamegraph.pl)生成火焰图。

## 5.6 火焰图

perf-prof仅输出折叠栈格式，并对输出栈比较多的模块做了支持。目前已支持：`profile, task-state, kmemleak, trace`

原先在stdout直接输出栈，目前切换成火焰图之后，不会再输出栈，而是会在命令结束时输出火焰图折叠栈文件。通过`[-g [--flame-graph file]]`参数启用火焰图，必须支持栈(-g)才能输出火焰图。折叠栈文件以`file.folded`命名。使用`flamegraph.pl`最终生成svg火焰图。

```
$ perf-prof task-state -S --than 100 --filter cat -g --flame-graph cat
$ flamegraph.pl cat.folded > cat.svg
```

### 5.6.1 按时间的火焰图

是以固定间隔输出折叠栈，折叠栈包含时间戳。最终生成的火焰图是按时间排序的。对于长时间的监控，可以根据时间戳查找问题。

```
$ grep "15:46:33" cat.folded | flamegraph.pl > cat.svg #生成15:46:33秒开始的火焰图
```

### 5.6.2 网络丢包火焰图

```
$ perf-prof trace -e skb:kfree_skb -g --flame-graph kfree_skb -m 128 #监控丢包
$ perf-prof trace -e skb:kfree_skb -g --flame-graph kfree_skb -i 600000 -m 128 #每600秒间隔输出火焰图
$ flamegraph.pl --reverse  kfree_skb.folded > kfree_skb.svg #生成火焰图
```

### 5.6.3 CPU性能火焰图

```
$ perf-prof profile -F 1000 -C 0,1 --exclude-user -g --flame-graph profile #采样内核态CPU利用率的火焰图
$ perf-prof profile -F 1000 -C 0,1 --exclude-user -g --flame-graph profile -i 600000 #每600秒间隔输出火焰图
$ grep "15:46:33" profile.folded | flamegraph.pl > profile.svg #生成15:46:33秒开始600秒的火焰图
```

## 5.7 延迟处理

perf-prof目前支持的延迟处理。

- 统计延迟。最大延迟，最小延迟，平均延迟。
- 直方图。log2和linear直方图，使用`print_log2_hist`和`print_linear_hist`函数打印。
- 热图。横坐标是时间轴，纵坐标是延迟信息。目前支持：`kvm-exit, mpdelay, multi-trace`

## 5.8 热图

```
$ perf-prof mpdelay -e "kvm:kvm_exit,kvm:kvm_entry" -C 1 --heatmap mpdelay
$ trace2heatmap.pl --unitstime=ns --unitslabel=ns --grid mpdelay-kvm_exit-kvm_entry.lat > mpdelay-kvm_exit-kvm_entry.svg
```

## 5.9 filter

目前支持3类过滤器：ebpf过滤器、pmu过滤器、ftrace过滤器。

通过`perf-prof -h`可以看到过滤器的选项：

```
Event selector. use 'perf list tracepoint' to list available tp events.
  EVENT,EVENT,...
  EVENT: sys:name[/filter/ATTR/ATTR/.../]
  filter: ftrace filter
  ATTR:
      ...
FILTER OPTION:
      --exclude-guest        exclude guest
      --exclude-kernel       exclude kernel
      --exclude-user         exclude user
      --exclude_pid=PID      ebpf, exclude pid
  -G, --exclude-host         Monitor GUEST, exclude host
      --irqs_disabled[=0|1]  ebpf, irqs disabled or not.
      --nr_running_max=N     ebpf, maximum number of running processes for CPU runqueue.
      --nr_running_min=N     ebpf, minimum number of running processes for CPU runqueue.
      --tif_need_resched[=0|1]   ebpf, TIF_NEED_RESCHED is set or not.
```

其中ebpf开头的是ebpf过滤器，其他的是pmu过滤器。ftrace过滤器，只能用于tracepoint事件。

#### 5.9.1 ebpf过滤器

内核perf_event可以通过`ioctl(PERF_EVENT_IOC_SET_BPF)`来设置bpf程序。bpf程序返回1，可以继续采样；bpf程序返回0，终止采样。可以依据这样的策略，来给每个perf_event增加一个过滤器。过滤不需要的采样点。

当前支持4个ebpf过滤器。

- `--irqs_disabled`，判断中断是否关闭。`--irqs_disabled, --irqs_disabled=1`中断关闭继续采样，中断打开终止采样。`--irqs_disabled=0`中断打开继续采样，中断关闭终止采样。
- `--tif_need_resched`，判断TIF_NEED_RESCHED标记是否设置。`--tif_need_resched, --tif_need_resched=1`标记设置继续采样，标记未设置终止采样。`--tif_need_resched=0`标记未设置继续采样，标记设置终止采样。
- `--nr_running_min,--nr_running_max`，判断runqueue中nr_running进程的数量。`nr_running_min <= nr_running <= nr_running_max`条件满足继续采样，否则终止采样。
- `--exclude_pid`，过滤掉进程pid。当前进程等于PID终止采样，否则继续采样。

#### 5.9.2 pmu过滤器

内核perf框架默认会带一些简单的过滤器，主要是基于perf_event_attr属性来设置。

当前支持4个pmu过滤器。

- `--exclude-guest`，过滤掉guest模式。
- `--exclude-host`，过滤掉host，只采样guest。一般用于硬件PMU。
- `--exclude-kernel`，过滤掉内核态。
- `--exclude-user`，过滤掉用户态。

#### 5.9.3 ftrace过滤器

每个tracepoint事件都可以设置ftrace过滤器。

```
$ perf-prof trace -e 'sched:sched_stat_runtime help

perf-prof trace -e "sched:sched_stat_runtime/./[stack/]" [-g] [--flame-graph .] [-C .] [-p .] [-i .] [--order] [--order-mem .] [-m .] 

sched:sched_stat_runtime
name: sched_stat_runtime
ID: 237
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:char comm[16];    offset:8;       size:16;        signed:1;
        field:pid_t pid;        offset:24;      size:4; signed:1;
        field:u64 runtime;      offset:32;      size:8; signed:0;
        field:u64 vruntime;     offset:40;      size:8; signed:0;

print fmt: "comm=%s pid=%d runtime=%Lu [ns] vruntime=%Lu [ns]", REC->comm, REC->pid, (unsigned long long)REC->runtime, (unsigned long long)REC->vruntime
```

通过在命令末尾加上`help`可以查看详细的帮助信息，其中包含tracepoint点的格式，可以找到可以作为过滤器的参数。

```
perf-prof trace -e 'sched:sched_stat_runtime/runtime>1000000/'
```

过滤出`runtime>1000000`的数据，放到ringbuffer，再由profiler进一步处理。

## 5.10 Attach to

perf-prof 使用一些公共参数来控制perf_event附加到CPU、线程、cgroup上。

```
Usage: perf-prof [OPTION...] profiler [PROFILER OPTION...] [help] [cmd [args...]]
 OPTION:
      --cgroups=cgroup,...   Attach to cgroups, support regular expression.
  -C, --cpu=CPU[-CPU],...    Monitor the specified CPU, Dflt: all cpu
  -p, --pids=PID,...         Attach to processes
  -t, --tids=TID,...         Attach to threads
```

可以使用逗号分隔多个CPU、PID、TID、cgroup。

### 5.10.1 Attach to CPU

附加到CPU，只能监控指定的CPU上发生的事件。

perf-prof trace -e sched:sched_stat_runtime `-C 0-1,3`

### 5.10.2 Attach to PID/TID

附加到PID/TID，只能监控指定的线程上发生的事件。

perf-prof trace -e sched:sched_stat_runtime `-p 205835,205982`

perf-prof trace -e sched:sched_stat_runtime `-t 205835,205982`

附加到PID，会读取该pid下的所有线程，转换成附加到TID。

### 5.10.3 Attach to workload

附加到workload，监控workload执行过程中的事件。

会通过fork、execvp来执行workload，并得到workload的pid。转换成附加到PID。

perf-prof task-state `ip link show eth0`

可以使用`--`强制分隔perf-prof的参数和workload的参数。

### 5.10.4 Attach to cgroups

附加到cgroups，监控cgroup内所有进程发生的事件。如果附加的PID太多，可以把这些PID放到perf_event cgroup内，附加到该cgroup，就能够监控到所有这些进程的事件。

```bash
# Example 1:
mkdir /sys/fs/cgroup/perf_event/prof
echo 205835 > /sys/fs/cgroup/perf_event/prof/tasks
cat /proc/205835/cgroup | grep perf_event
  5:perf_event:/prof
perf-prof trace -e sched:sched_stat_runtime --cgroups 'prof' # prof
perf-prof trace -e sched:sched_stat_runtime --cgroups 'pro*' # 正则表达式

# Example 2:
mkdir /sys/fs/cgroup/perf_event/prof1
echo 205845 > /sys/fs/cgroup/perf_event/prof/tasks
perf-prof trace -e sched:sched_stat_runtime --cgroups 'prof,prof1'
perf-prof trace -e sched:sched_stat_runtime --cgroups 'prof*' # prof, prof1
```

perf_event cgroup 需要手动把需要观察的进程放进去。

cgroup的指定相对于`/sys/fs/cgroup/perf_event/`目录，同时可以使用正则表达式，匹配多个perf_event cgroup。
