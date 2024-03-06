# 基于perf/ebpf的分析框架

基于`libperf`和`libtraceevent`库实现简单的分析框架，提供比perf更灵活的特性。

- 数据不落盘，数据实时处理并输出。
- 数据过滤，基于tracepoint的过滤机制，减少数据量。支持ebpf过滤器。
- 兼容更多内核版本。
- 用户态实现更安全，能快速迭代。

虽然比perf更灵活，但不能替代perf。perf灵活的符号处理，支持大量的event，支持很多硬件PMU特性。

![perf-prof框架](docs/images/perf-prof_framework.png)



# 1 框架介绍

整体框架由内核态和用户态 2 部分组成。

## 1.1 内核态

内核态分为几部分：事件源，filter，perf_event。

内核态，事件源的事件经过`filter`过滤之后，存放到`ringbuffer`上，并递增`counter`计数器。

***事件源***  目前有 5 种。

- ebpf。bpf 程序可以调用 bpf_perf_event_output()直接往 perf 的 ringbuffer 内写入数据。

- tracepoint。内核执行到 tracepoint 点的位置，就会采样事件。

- kprobe。动态 tracepoint 点。其功能跟 tracepoint 点一致。

- uprobe。跟 kprobe 类似，作用于用户态的二进制文件。

- pmu。硬件事件源。源自 CPU 内部，PMC 计数溢出后触发采样。

***filter*** 目前有3种。

这三个过滤器，全是内核态过滤器，过滤出的事件才会放到 ringbuffer，被用户态使用。

- ebpf 过滤器。可以在事件源 perf_event 上添加 bpf 程序。bpf 程序返回 1，可以继续采样；bpf 程序返回 0，终止采样。

- trace event 过滤器。内核可以对 tracepoint 点的字段进行过滤。只过滤有满足条件的事件。

- pmu 过滤器。仅支持 user、kernel 过滤。

***perf_event*** 内包含 counter 和 ringbuffer 两部分。

- counter，计数器，对事件发生次数进行计数。每个perf_event都有独立counter，不能共享。

- ringbuffer，环形缓冲区，用于存放过滤后的事件。采样的事件格式，由 `perf_event_attr::sample_type `字段指定，包含基本的 CPU、pid、tid、时间戳、堆栈、raw、寄存器等信息。采样默认关闭，通过`perf_event_attr.sample_period`参数开启采样。每个perf_event都有独立的ringbuffer，多个perf_event可以共用ringbuffer。

## 1.2 用户态

**perf-prof** 框架不断读取`ringbuffer`的采样事件和`counter`，经过`order`排序事件，最后送到`profiler`处理事件。

用户态分为 3 部分：基础功能、分析单元、联合分析。

- 基础功能给分析单元提供基础服务。帮助系统、火焰图、符号解析、过滤器、order、expr、comm。
- 分析单元：分成几个大类，每一个分析单元都是相互独立的，包含最小的分析功能。
- 联合分析，把多个分析单元联合起来一起参与分析。

# 2 分析单元

分析单元分为一些大类：trace、计数分析、延迟分析、进程、内存、虚拟化、硬件与调试、块设备。

每一个分析单元都是一个独立的 profiler(剖析器)。

## 2.1 trace

trace 是最基本的分析单元。直接显示采样的事件，不做任何其他处理。一般用于 profiler 开发初期，直接观察事件的原始信息，并配合脚本处

理事件。对于事件量比较少时，可以直观显示。

## 2.2 计数分析

1. stat。间隔输出事件的计数器。

2. percpu-stat。精选好的一些事件，不需要指定。

3. top。对事件的某些字段进行 top 分析。把字段的所有可能值拆分成独立的计数器，并按从大到小显示。

4. hrcount。高精度计数器。可以观察到 ms 粒度事件的发生次数。用于事件发生密度分析，是否有一定的集中性。

5. hrtimer。高精度条件采样。采样间隔内，事件发生一定次数时，输出采样的堆栈。

6. num-dist。数值分布。事件的某字段的分布情况，最小值，平均值，p99，最大值。

## 2.3 延迟分析

1. multi-trace。多功能分析，主要用于事件延迟分析，并确定延迟的中间细节。

2. syscalls。系统调用耗时分析。基于 multi-trace。只分析 sys_enter->sys_exit 之间的延迟。

3. nested-trace。嵌套的耗时分析。用于函数的发生关系分析，并统计每个函数的耗时。

4. rundelay。调度延迟分析。基于 multi-trace，自动设置 filter。

## 2.4 进程

1. task-state。进程状态。可以统计进程 R，RD，S，D 等状态的分布情况。

2. oncpu。进程运行在哪些 cpu 上。cpu 上运行过哪些进程。

## 2.5 内存

1. kmemleak。内存泄露分析。支持内核态多种内存分配器，以及用户态的内存分配器。

2. kmemprof。内存分配热点分析。能够采集到哪些路径会密集分配内存。

## 2.6 虚拟化

1. kvm-exit。虚拟化退出耗时。

2. kvmmmu。跟踪 mmu page 的分配和建立过程。

## 2.7 块设备

1. blktrace。跟踪块设备 request 在每个阶段的耗时。

## 2.9 硬件与调试

收集常用的硬件 PMU 事件。

1. profile。指定频率采样。Cpu-cycles 事件。硬件 PMU 采样 NMI 中断，不会受到关中断影响。

2. breakpoint。硬件断点。可以捕获对某个虚拟地址的读、写、执行。如：全局变量被修改。

3. page-faults。缺页异常。跟踪系统发生的缺页异常。

4. ldlat-loads。采样内存访问延迟。基于 PEBS。

5. llcstat。L3 缓存状态。命中率。
6. tlbstat。Tlb 状态。命中率。

# 3 联合分析

分析单元大致分成 2 类：

- 内建事件分析单元：不需要使用-e 指定事件，一般使用 ebpf、硬件 pmu 作为内建事件源，也可以使用 tracepoint 作为事件源。

- 指定事件分析单元：需要使用-e 等选项指定事件。

对于 tracepoint、kprobe、uprobe 事件源可以使用 sys:name 表示，能够通过-e选项直接使用。对于 ebpf、pmu 事件源，没办法使用 sys:name 表示，其是封装在 profiler 内部，属于 profiler 的内建事件，因此这些 profiler 本身可以看做事件源。经过扩展，所有含有内建事件的 profiler，都可以看做事件源。

联合分析，就是把这些 tracepoint、kprobe、uprobe 事件源，profiler 事件源产生的事件联合起来一起分析。

- multi-trace 可以接受 trace、profile、task-state、breakpoint、page-faults 这几个一起参与延迟分析。
- trace 可以接受 profile、task-state、breakpoint、page-faults 这几个一起排序后输出。

# 4 基础功能

## 4.1 模块化

每个profiler都是独立的模块文件，可扩展，可裁减，损耗低。适合高性能监控场景。

## 4.2 栈

  - 栈及符号打印。可控制内核态、用户态、地址、符号、偏移量、dso、正向栈、反向栈，每个栈帧的分隔符、栈的分隔符。
  - 支持解析内核符号(/proc/kallsyms)，用户态符号(.symtab/.dynsym)、MiniDebugInfo解析(.gnu_debugdata)。
  - 支持debuginfo包。/usr/lib/debug/.build-id/
  - key-value栈。以栈做为key，可以过滤重复栈，并能唯一寻址value。
  - 生成火焰图折叠栈格式。

## 4.3 用户态符号表

用户态符号表，使用`syms_cache`结构表示，通过pid找到特定于进程的`syms`符号集合。

syms符号集合由/proc/pid/maps内所有的文件映射组成，每一个文件映射由一个`dso`来表示，syms包含dso的集合。

每个dso由映射到进程地址空间内的[起始地址、结束地址、文件对象]表示。文件对象由`object`结构表示。

object结构表示一个动态库的符号集合，由多个`sym`组成。object是可以给多个进程共享的，通过引用计数管理object的引用和释放。

sym表示一个特定的符号。由符号名字，起始地址，大小组成。

```
syms_cache --> syms --> dso --> object --> sym
```

## 4.4 用户态内存泄露检测

```
LD_PRELOAD=/lib64/libtcmalloc.so HEAPCHECK=draconian PPROF_PATH=./perf-prof /path/to/bin
```

利用tcmalloc的内存泄露检测功能。

- **LD_PRELOAD=**，预先加载tcmalloc库，替换glibc库的malloc和free函数。
- **HEAPCHECK=**，内存泄露检测。draconian检测所有的内存泄露。
- **PPROF_PATH=**，指定符号解析命令。`perf-prof --symbols`具备跟`pprof --symbols`一样的符号解析能力。

## 4.5 栈的处理

栈的处理方式各种各样，如perf top风格的栈处理，火焰图风格的栈处理。

perf-prof目前支持的栈处理。

- 栈及符号打印。用`callchain_ctx`表示，定义了栈的打印风格，可控制内核态、用户态、地址、符号、偏移量、dso、正向栈、反向栈。每个栈帧的分隔符、栈的分隔符。
- key-value栈。以栈做为key，可以过滤重复栈，并能唯一寻址value。用`key_value_paires`结构表示，一般相同的栈都有类似的作用，如内存分配栈，可以分析相同的栈分配的总内存量，未释放的总内存量。类似于gperftools提供的HEAPCHECKE功能，最后报告的内存泄露是以栈为基准的。
- 火焰图。把相同的栈以及栈的每一帧聚合到一起。用`flame_graph`结构表示，能够生成折叠栈格式：反向栈、每帧以";"分隔、末尾是栈的数量。例子：`swapper;start_kernel;rest_init;cpu_idle;default_idle;native_safe_halt 1`。使用[flamegraph.pl](https://github.com/brendangregg/FlameGraph/blob/master/flamegraph.pl)生成火焰图。

## 4.6 火焰图

perf-prof仅输出折叠栈格式，并对输出栈比较多的模块做了支持。目前已支持：`profile, task-state, kmemleak, trace`

原先在stdout直接输出栈，目前切换成火焰图之后，不会再输出栈，而是会在命令结束时输出火焰图折叠栈文件。通过`[-g [--flame-graph file]]`参数启用火焰图，必须支持栈(-g)才能输出火焰图。折叠栈文件以`file.folded`命名。使用`flamegraph.pl`最终生成svg火焰图。

```
$ perf-prof task-state -S --than 100 --filter cat -g --flame-graph cat
$ flamegraph.pl cat.folded > cat.svg
```

### 4.6.1 按时间的火焰图

是以固定间隔输出折叠栈，折叠栈包含时间戳。最终生成的火焰图是按时间排序的。对于长时间的监控，可以根据时间戳查找问题。

```
$ grep "15:46:33" cat.folded | flamegraph.pl > cat.svg #生成15:46:33秒开始的火焰图
```

### 4.6.2 网络丢包火焰图

```
$ perf-prof trace -e skb:kfree_skb -g --flame-graph kfree_skb -m 128 #监控丢包
$ perf-prof trace -e skb:kfree_skb -g --flame-graph kfree_skb -i 600000 -m 128 #每600秒间隔输出火焰图
$ flamegraph.pl --reverse  kfree_skb.folded > kfree_skb.svg #生成火焰图
```

### 4.6.3 CPU性能火焰图

```
$ perf-prof profile -F 1000 -C 0,1 --exclude-user -g --flame-graph profile #采样内核态CPU利用率的火焰图
$ perf-prof profile -F 1000 -C 0,1 --exclude-user -g --flame-graph profile -i 600000 #每600秒间隔输出火焰图
$ grep "15:46:33" profile.folded | flamegraph.pl > profile.svg #生成15:46:33秒开始600秒的火焰图
```

## 4.7 延迟处理

perf-prof目前支持的延迟处理。

- 统计延迟。最大延迟，最小延迟，平均延迟。
- 直方图。log2和linear直方图，使用`print_log2_hist`和`print_linear_hist`函数打印。
- 热图。横坐标是时间轴，纵坐标是延迟信息。目前支持：`kvm-exit, multi-trace`

## 4.8 热图

```
$ perf-prof multi-trace -e kvm:kvm_exit -e kvm:kvm_entry -C 1 --heatmap mpdelay
$ trace2heatmap.pl --unitstime=ns --unitslabel=ns --grid mpdelay-kvm_exit-kvm_entry.lat > mpdelay-kvm_exit-kvm_entry.svg
```

## 4.9 filter

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

### 4.9.1 ebpf过滤器

内核perf_event可以通过`ioctl(PERF_EVENT_IOC_SET_BPF)`来设置bpf程序。bpf程序返回1，可以继续采样；bpf程序返回0，终止采样。可以依据这样的策略，来给每个perf_event增加一个过滤器。过滤不需要的采样点。

当前支持4个ebpf过滤器。

- `--irqs_disabled`，判断中断是否关闭。`--irqs_disabled, --irqs_disabled=1`中断关闭继续采样，中断打开终止采样。`--irqs_disabled=0`中断打开继续采样，中断关闭终止采样。
- `--tif_need_resched`，判断TIF_NEED_RESCHED标记是否设置。`--tif_need_resched, --tif_need_resched=1`标记设置继续采样，标记未设置终止采样。`--tif_need_resched=0`标记未设置继续采样，标记设置终止采样。
- `--nr_running_min,--nr_running_max`，判断runqueue中nr_running进程的数量。`nr_running_min <= nr_running <= nr_running_max`条件满足继续采样，否则终止采样。
- `--exclude_pid`，过滤掉进程pid。当前进程等于PID终止采样，否则继续采样。

### 4.9.2 pmu过滤器

内核perf框架默认会带一些简单的过滤器，主要是基于perf_event_attr属性来设置。

当前支持4个pmu过滤器。

- `--exclude-guest`，过滤掉guest模式。
- `--exclude-host`，过滤掉host，只采样guest。一般用于硬件PMU。
- `--exclude-kernel`，过滤掉内核态。
- `--exclude-user`，过滤掉用户态。

### 4.9.3 ftrace过滤器

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

## 4.10 Attach

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

### 4.10.1 Attach to CPU

附加到CPU，只能监控指定的CPU上发生的事件。

perf-prof trace -e sched:sched_stat_runtime `-C 0-1,3`

### 4.10.2 Attach to PID/TID

附加到PID/TID，只能监控指定的线程上发生的事件。

perf-prof trace -e sched:sched_stat_runtime `-p 205835,205982`

perf-prof trace -e sched:sched_stat_runtime `-t 205835,205982`

附加到PID，会读取该pid下的所有线程，转换成附加到TID。

### 4.10.3 Attach to workload

附加到workload，监控workload执行过程中的事件。

会通过fork、execvp来执行workload，并得到workload的pid。转换成附加到PID。

perf-prof task-state `ip link show eth0`

可以使用`--`强制分隔perf-prof的参数和workload的参数。

### 4.10.4 Attach to cgroups

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

## 4.11 USDT

usdt是用户态进程静态导出的trace点，编译之后存放在`.note.stapsdt`section中。解析该section，创建出uprobe就可以trace用户态执行。

目前提供3个功能：

- **list**，列出elf文件中的usdt。
- **add**，利用usdt添加uprobe点，通过profider:name方式来使用。
- **del**，删除已添加的uprobe点。

```bash
# Example:
perf-prof usdt add libc:memory_malloc_retry@/usr/lib64/libc.so.6 -v
perf-prof trace -e libc:memory_malloc_retry
```

当前已支持x86和arm64平台。

[Exploring USDT Probes on Linux](https://leezhenghui.github.io/linux/2019/03/05/exploring-usdt-on-linux.html)

