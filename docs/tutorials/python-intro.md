# perf-prof python：不学 eBPF，也能在内核层造你自己的 Linux 跟踪工具

> **一句话导读**：Linux 内核里埋了几百个 tracepoint，加上 kprobe、uprobe，观察系统里"每一次事件"的能力其实早就齐了；真正拦住普通开发者的，是 bcc、bpftrace 需要写 eBPF、要 4.1+ 新内核、学习曲线陡。perf-prof python 换了条路——**事件由内核抓、C 层转换成 `PerfEvent` 对象、你只在最上面用 Python 写一两百行业务逻辑**，就能得到一个属于自己的分析工具。老内核（3.10 就有的 `perf_event`）也能跑，生产环境可长期运行，改一行立刻见效。
>
> **本文写给谁看**：想在生产环境里"看到过去发生了什么"、但又不想为此专门学 eBPF 的 Linux 运维与后端开发者。读完你会知道：**为什么把主战场放在内核层是"降维打击"**、**perf-prof python 的三层架构（内核、C 搬运、Python 脚本）**、**回调函数和 `PerfEvent` 怎么用**、**两个真实工具（`func_latency` 看函数调用树 + 分位数、`exec_trace` 看谁在跑什么）是怎么工作的**，以及**怎么借助 AI 把"我有个想法"变成"跑起来的脚本"**。
>
> **建议的阅读节奏**：忙的时候直接跳到 §3 看 15 行代码的最小例子；想造自己的工具时看 §6 §7 两个实战 + §8 的 AI 工作流；对底层机制好奇再回头补 §2。
>
> **项目地址**：<https://github.com/OpenCloudOS/perf-prof>（本文提到的所有脚本、文档、示例都在此仓库中）

# 一、背景

日常运维和开发里，经常会碰到这些问题：

- **CPU 突然打满**：是哪个函数在烧 CPU？调用路径是什么？
- **进程响应慢**：从被唤醒到真的跑起来，中间等了多久？谁在挡它？
- **奇怪的进程被反复拉起**：哪个脚本、哪个服务在调它？完整命令行是什么？
- **内存慢慢涨**：谁在申请内存、又没释放？
- **磁盘 IO 抖动**：哪个进程、什么 pattern 的读写导致的？

这些问题的共同点：**光看 top、ps、iostat 这些"当前快照"不够**——这些工具本身没毛病，只是它们看的是"此刻的状态"，回答不了"过去这段时间到底发生了什么"。你需要看到"每一次事件"——每一次进程被唤醒、每一次函数被调用、每一次内存被申请。这就是所谓的 **tracing（跟踪）**。

## 1.1 跟踪的层级：越底层，维度越高

一个真实的系统可以从不同的层级去看，每一层能看到的东西不一样：

| 层级 | 你能看到什么 | 常见工具 |
|---|---|---|
| **业务层** | 订单成功率、接口 QPS、慢查询日志、用户体验指标 | APM、业务埋点、日志系统 |
| **系统层** | 进程状态、CPU 使用率、内存占用、文件描述符、网络连接 | top、ps、netstat、iostat |
| **内核层** | 进程调度、系统调用、锁竞争、内存分配、IO 请求、中断处理 | perf、ftrace、bcc、bpftrace、perf-prof |
| **硬件层** | CPU 周期、cache miss、TLB miss、指令流水线、内存带宽 | PMU（perf 硬件计数器）、Intel PT |

**层级越往下，视角越"低"，能看到的现象越"细节"，但覆盖的抽象概念也越"抽象"（维度越高）**——业务层的"接口慢了"，到系统层可能是"某进程 D 状态时间长"，到内核层可能是"某锁自旋 200ms"，到硬件层可能是"每次访存都 miss 到 LLC"。

**越底层发现的问题越接近本质**。业务日志只能告诉你"发生了什么"，系统层告诉你"哪个进程有问题"，内核层告诉你"进程在等什么"，硬件层告诉你"CPU 到底在干嘛"。反过来，**掌握了底层视角就形成了"降维打击"**：拿着内核层的证据讨论业务问题，往往一句话就能确定根因，比从业务日志里反复推理快得多。

Linux 内核里**到处都埋了跟踪点**（tracepoint），从进程调度、内存分配到网络收发、文件读写都有——它们就是通往内核层视角的入口。用得好，就能像内核开发者一样分析问题。

## 1.2 perf-prof 的定位

**perf-prof 把主战场定在内核层**。为什么选内核层？因为它是四层里性价比最高的观察面：**必经之路**（用户态所有行为最终都要穿过内核，跨语言跨框架统一覆盖）、**信息最全**（进程、CPU、锁、栈、文件描述符等上下文天然俱全）、**开销可控**（tracepoint 静态嵌入、未启用零开销；kprobe/uprobe 不改代码动态插桩）、**能解释看不见的时间**（业务日志只知道"这次请求 500ms"，但那 500ms 里被抢占多久、等 IO 多久、等锁多久，只有内核层能分解出来）。

内核层已经有一批成熟工具，各有各的位置：

| 工具 | 优点 | 短板 |
|---|---|---|
| **bcc / bpftrace** | 性能好，能在内核里聚合 | 需要 4.1+ 新内核；要会写 eBPF C，懂 prog 类型，学习bpftrace语法，学习曲线陡 |
| **perf / ftrace** | 内核自带，采样能力强 | 主要用于"短时采样再离线看"，长期跑不方便 |
| **strace / gdb** | 上手快 | 开销大，不能在生产环境长期开 |
| **perf-prof** | 3.10 老内核也能跑；可长运行（事件在内存里处理完就丢）；内建几十个分析器覆盖大部分场景 | 遇到覆盖不到的临时需求，需要自己写扩展 |

一句话说清 perf-prof 在这些工具里的定位：

> **面向"老内核 + 生产环境 + 长期实时观察 + 紧急拼命令"场景的用户态跟踪工具。**

拆开看：

- **老内核可用**：只依赖 `perf_event`（3.10 就有），不像 bcc/bpftrace 要 4.1+ 才行。国内很多生产环境还跑在 CentOS 7 系的 3.10 内核上，perf-prof 是少数还能直接上的选择。
- **生产环境安全**：完全跑在用户态，事件在内存里处理完就丢，不写文件，不注入内核，出问题 kill -9 就干净了。
- **性能够用**：事件出内核后在用户态实时处理，单机每秒几十万事件不是问题。达不到 bcc/bpftrace 在内核里聚合的极致性能，但对绝大多数生产场景足够扛住。
- **长期可跑**：内建几十个分析器覆盖"CPU 采样、进程状态、内存泄露、块设备 IO、虚拟化退出、延迟根因"等常见场景，可以像守护进程一样一运行。
- **紧急场景友好**：内建分析器直接拼命令行就能上，不用现学 eBPF、不用编译。

用编程语言类比性能梯度：如果 bcc/bpftrace 是 **C/C++**（事件在内核里聚合，性能最好），perf/ftrace 是 **Python**（先采样再离线处理，中等开销但只能事后看），那么 **perf-prof 就是 JavaScript**——事件出内核后在用户态实时处理，性能不是最顶，但足够扛住大部分生产场景，换来的是"随时改、随时跑、随时停"的部署便利，在"大部分工程师都能用得起来"的位置。

但即便现有工具再多（bcc、bpftrace、perf-prof 的内建分析器加起来数百个），也会有"临时的、和业务强相关的"需求覆盖不到——比如你想按"完整调用路径"聚合函数耗时、或者在进程 exec 那一刻把它的 `LD_PRELOAD` 环境变量打出来。为每个这样的临时需求单独造一个 C 分析器（甚至写一段 eBPF）都不划算，于是自然引出下面这个想法：**能不能让用户用 Python 写自己的分析逻辑？**

# 二、把 Python 引进来

Python 的优势对做分析的人特别友好：

- **生态丰富**——`collections.Counter` 做计数、`json` 做输出、`pandas` 做统计分析，随手就来
- **写完就跑**——不用编译，改一行立刻见效果
- **想调试就 print**——不用琢磨内核里的日志怎么捞

perf-prof 的 `python` 分析器就干这件事：把内核里发生的一个个事件抓出来、整理好，然后交给你的 Python 脚本处理。

我们从最粗的一张流程图开始，一步步把里面的每一块拆开讲清楚。

## 2.1 一张总览图

对着下面这条最简单的命令来看整张图：

```bash
perf-prof python -e sched:sched_wakeup -i 1000 counter.py
```

- `-e sched:sched_wakeup` 指定事件：告诉**内核**，把"进程被唤醒"这个事件报给我
- `perf-prof python … -i 1000` 是**perf-prof 自己**：抓事件、排序、解析、每 1 秒调一次 `__interval__`
- `counter.py` 是**你的 Python 脚本**：定义几个回调函数处理事件（完整代码见 [第三节](#三一个最简单的例子计数进程唤醒次数)）

三层各自的分工，就是下面这张图：

```
┌────────────────────────────────────────────────────────────────────┐
│  Linux 内核                                                        │
│  ─────────                                                         │
│  「内核里发生的的事件：进程唤醒、内存分配、系统调用、PMU……             │
│    按指定的事件格式，存放到环形缓冲区内。」                           │
│                                                                    │
│  ● tracepoint：内核开发者事先埋好的观察点                            │
│  ● kprobe / uprobe：你临时挂到任意内核/用户态函数上的探针             │
│  ● PMU 硬件计数器：CPU 每跑 N 个周期就报告一次                        │
│                                                                    │
│                每 CPU 一块环形缓冲区（ringbuffer）                   │
└──────────────────────────┬─────────────────────────────────────────┘
                           │ 内核把事件塞进 ringbuffer，用户态读出来
                           ▼
┌────────────────────────────────────────────────────────────────────┐
│  perf-prof（用户态 C 程序，跑苦活）                                  │
│  ────────────────────────────                                      │
│  「负责把这些原始字节抓出来，按时间排好序，解析事件的字段，             │
│    再包装成一个 Python 对象，找到对应的函数调用它。」                  │
│                                                                    │
│  ① epoll 等待事件到达                                               │
│  ② 多个 CPU 的事件按时间戳合并（--order）                            │
│  ③ 按内核给的事件格式解析为二进制字段（comm、pid、target_cpu …）       │
│  ④ 构造 `PerfEvent` 对象（公共字段直接填、特定字段惰性求值）           │
│  ⑤ 决定调用你脚本里的哪个函数                                        │
└──────────────────────────┬─────────────────────────────────────────┘
                           │ Python C API 调用你的函数
                           ▼
┌────────────────────────────────────────────────────────────────────┐
│  你的 Python 脚本（只写业务逻辑）                                    │
│  ─────────────────                                                 │
│  「处理事件：计数、聚合、打印、存文件、发告警…… 」                     │
│                                                                    │
│  def sched__sched_wakeup(event):                                   │
│      stats[event.comm] += 1                                        │
│                                                                    │
│  def __interval__():                                               │
│      print(stats)                                                  │
└────────────────────────────────────────────────────────────────────┘
```

三层各司其职：**内核负责产生事件，perf-prof 负责搬运整理，你只写最上面那一小片业务逻辑**。下面把每一层再细看一眼。

## 2.2 内核到底能给你哪些事件？

`-e` 后面能挂的事件源，Linux 内核提供了四大类，覆盖了绝大多数观察需求：

| 类别 | 长什么样 | 谁埋的 | 覆盖 |
|---|---|---|---|
| **tracepoint** | `sched:sched_wakeup`、`block:block_rq_issue` | 内核开发者预先埋在关键位置 | 调度、内存、IO、网络、文件系统等；用 `perf-prof list` 可以列出当前内核所有可用的 tracepoint |
| **kprobe / kretprobe** | `kprobe:vfs_read`、`kretprobe:tcp_sendmsg` | 你临时挂到内核任意函数入口/返回 | 补 tracepoint 覆盖不到的内核函数 |
| **uprobe / uretprobe** | `uprobe:/bin/bash:readline` | 你临时挂到用户态二进制任意函数 | 用户态应用/库的函数级观测 |
| **PMU 硬件事件** | `cpu-clock`、`cycles`、`cache-misses` | CPU 硬件计数器 | CPU 周期采样、cache/TLB 行为；PMU 事件在 perf-prof 里以**独立 profiler** 的形式暴露（如 `profile` / `breakpoint`），python 分析器目前只对接了常用的 PMU 事件，要用更多硬件事件需要自己写一个 profiler |

前三类是"事件驱动"（每发生一次就产一次事件），第四类是"周期采样"（每 N 个周期采一次栈）。**perf-prof python 分析器把这四类事件统一封装成同一种 `PerfEvent` 对象，你的脚本写法不用变。**

对一般用户来说，最难的其实是**"我这个问题该用哪个事件"**——第八节会讲一个重要技巧：**问 AI**。它比你自己翻内核文档快得多。

## 2.3 perf-prof 帮你做了什么苦活

内核产生事件、你的 Python 函数被调用，中间这段路 perf-prof 全包了。从内核往用户态走的六件事：

1. **打开事件**：调用 `perf_event_open` 系统调用，向内核申请把某个 tracepoint、kprobe、uprobe、PMU 事件采集出来。每个 CPU 都要单独打开一份。
2. **建 ringbuffer**：每个 CPU 一块共享内存环形缓冲区，内核把事件按二进制格式（`perf_event_attr.sample_type`）写进去，用户态直接 mmap 读，零拷贝。
3. **周期性拉取**：`epoll` 等在 fd 上，有事件就把 ringbuffer 里的原始字节读出来。
4. **跨 CPU 排序**（可选，加 `--order`）：不同 CPU 的 ringbuffer 独立写入，用户态处理多个 CPU 的事件不一定按时间顺序。做延迟配对（唤醒→切换、入口→返回）时若不排序会算出负数。但**每个 CPU 内部事件按时间顺序的**（同一个 CPU 上不会"晚发生的事件先入 ringbuffer"），有了这个前提，perf-prof 就能用最小堆把多个 CPU 的有序流合并成单一全局有序流，代价是 O(log N)。
5. **解析字段**：tracepoint 的二进制格式（每个字段的偏移、长度、类型）由内核在 `/sys/kernel/tracing/events/<sys>/<name>/format` 提供，perf-prof 读进来后按定义解析。你在脚本里写 `event.comm`，背后就是它在按类型定义读原始字节。
6. **构造 PerfEvent**：公共字段（`_pid`、`_tid`、`_time`、`_cpu`）直接填好；事件特定字段做**惰性求值**——你不访问就不解析，避免高频事件浪费 CPU。

这六步全部是 C 语言实现，性能足以扛住每秒几十万事件。你在 Python 层只需要处理业务逻辑。

## 2.4 事件怎么分发到你的 Python 函数

对象构造好后，perf-prof 按下面的规则决定调用你脚本里的哪个函数：

```
事件来了（比如 sched:sched_wakeup）
        │
        ▼
   ①脚本里有 sched__sched_wakeup 函数吗？
        │
    ┌───┴───┐
    有       没有
    │        │
    ▼        ▼
调它       ②脚本里有 __sample__ 吗？
              │
          ┌───┴───┐
          有       没有
          │        │
          ▼        ▼
        调它     丢弃事件
```

规则很简单：

1. **先找专属处理器**：事件名 `sys:name` 对应函数 `sys__name`（`:` 换成 `__`）。找到就调这个，专属处理器优先级最高。
2. **兜底通用处理器**：没有专属函数，看有没有 `__sample__`。有就调它，`event._event` 字段告诉你实际来的是什么事件。
3. **都没有**：事件被丢弃，不会报错。

除了事件回调，perf-prof 还会在特定时机调用**生命周期回调**——`__init__` 在启动时、`__interval__` 每 `-i` 毫秒一次、`__exit__` 在退出前——这些不需要事件参数，用于打表头、周期性输出、最终汇总。

## 2.5 小结与后续章节

到这里，写脚本的所有背景知识都齐了：

- **内核**：产生事件（tracepoint、kprobe、uprobe、PMU 四大类）
- **perf-prof C 层**：抓取、排序、解析、构造 `PerfEvent` 对象、分发
- **你的 Python 脚本**：写回调函数处理事件（`sys__name` 专属、`__sample__` 兜底），加生命周期钩子控制启动/周期/退出

**你只需要写一个 Python 脚本，告诉它"每个事件来了我要干嘛"**——其它全部由 perf-prof 处理。

接下来的章节按这条思路展开：

- **第三节**：用最短的例子先跑起来看看
- **第四、五节**：从"脚本骨架"（有哪些回调函数）和"事件数据"（`PerfEvent` 长什么样）两个角度，把第三节例子里没展开的细节补齐
- **第六、七节**：两个完整的实战工具，看看这套东西能做到什么深度
- **第八节**：如何借助 AI 快速把想法变成脚本

# 三、一个最简单的例子：计数进程唤醒次数

前面讲了一堆背景，先跑一个最短的完整脚本感受一下，再看细节：

```python
# counter.py
import time

count = 0

def __sample__(event):
    global count
    count += 1

def __interval__():
    global count
    now = time.strftime("%H:%M:%S")
    print(f"[{now}] 过去这段时间，有 {count} 次进程唤醒")
    count = 0
```

跑起来：

```bash
perf-prof python -e sched:sched_wakeup -i 1000 counter.py
```

这条命令的意思是：
- `-e sched:sched_wakeup` —— 我要看的事件是"进程被唤醒"
- `-i 1000` —— 每 1000 毫秒（1 秒）汇总一次
- `counter.py` —— 用这个 Python 脚本处理事件

每秒打印一行，真实运行 5 秒的输出：

```
Loaded module: counter.py
[11:47:18] 过去这段时间，有 14568 次进程唤醒
[11:47:19] 过去这段时间，有 10058 次进程唤醒
[11:47:20] 过去这段时间，有 8756 次进程唤醒
[11:47:21] 过去这段时间，有 10499 次进程唤醒
[11:47:22] 过去这段时间，有 8600 次进程唤醒
```

第一行 `Loaded module` 是 perf-prof 自己打的，表示它加载了你的脚本。之后每一行由 `__interval__()` 打印——时间戳按秒递增，正好对应 `-i 1000` 的时间间隔。

这十几行代码就是一个完整的、可以长期跑的分析工具了。脚本里的 `__sample__`（收到每个事件时被调用）和 `__interval__`（每 `-i` 毫秒被调用一次），一个是事件回调、一个是生命周期回调。

# 四、Python 脚本里可以定义哪些函数

perf-prof 会在特定时机调用你脚本里的一些函数。这些函数**不是必须的**，你想要哪个就写哪个，不写就跳过。

## 4.1 生命周期回调（不带 event 参数）

这几个函数控制"什么时候做什么"，参数为空：

| 函数名 | 什么时候被调用 | 典型用途 |
|---|---|---|
| `__init__()` | 脚本刚启动，事件还没开始处理时 | 初始化全局变量、打印表头 |
| `__interval__()` | 每隔 `-i` 指定的毫秒数 | 周期性输出统计、清空计数 |
| `__exit__()` | 脚本要退出前（Ctrl-C 也算）| 打印最终总结、保存文件 |
| `__print_stat__(indent)` | 收到 SIGUSR2 信号时 | 手动触发一次统计打印 |
| `__lost__(t1, t2)` | 有事件被丢弃时 | 提醒用户加大缓冲区 |

举例：

```python
stats = {}

def __init__():
    print("开始收集数据……")

def __interval__():
    print(f"当前统计: {stats}")

def __exit__():
    print(f"最终结果: {stats}")
    import json
    with open('result.json', 'w') as f:
        json.dump(stats, f)
```

## 4.2 事件处理回调（带 event 参数，也就是 PerfEvent）

这类函数**每来一个事件就会被调用一次**，参数是一个 `event` 对象（下一节详细讲）。有两种写法：

**写法一：通用处理器 `__sample__`**

```python
def __sample__(event):
    # 所有事件都走这里
    print(event._event, event._pid)
```

**写法二：给每种事件单独写一个处理器**

函数名的规则：把事件名里的 `:` 换成 `__`（两个下划线）。

比如事件是 `sched:sched_wakeup`，对应的函数就是 `sched__sched_wakeup`：

```python
def sched__sched_wakeup(event):
    # 只有 sched:sched_wakeup 事件走这里
    print("有进程被唤醒:", event.comm, event.pid)

def sched__sched_switch(event):
    # 只有 sched:sched_switch 事件走这里
    print("切换到进程:", event.next_comm)
```

**优先级**：如果你既写了 `sched__sched_wakeup` 又写了 `__sample__`，前者优先——`sched:sched_wakeup` 走专门处理器，其它没写专门处理器的事件才走 `__sample__` 兜底。

## 4.3 到底该写哪些？——一份速查

刚开始最常用的组合：

- **`__init__()`**：初始化几个全局字典/计数器
- **专属处理器 或 `__sample__`**：处理每个事件
- **`__interval__()`**：每隔一段时间打印、清空数据
- **`__exit__()`**：程序退出时打印最终结果

其它可选可不写。

**不知道该写什么？让 perf-prof 帮你生成模板：**

```bash
perf-prof python -e sched:sched_wakeup help > my_script.py
```

这会生成一份完整的脚本骨架，包含所有可选函数、所有可用字段的注释、访问示例。改一改就能用。

# 五、PerfEvent 对象：事件的样子

每次事件到来，perf-prof 会构造一个 `event` 对象传给你的回调函数。这个对象是 `PerfEvent` 类型，保存了事件的所有信息。

## 5.1 通用字段（所有事件都有）

以 `_` 开头的字段是**通用信息**，任何事件都能拿到：

| 字段 | 含义 |
|---|---|
| `event._pid` | 进程 ID |
| `event._tid` | 线程 ID |
| `event._cpu` | 事件发生在哪个 CPU |
| `event._time` | 事件时间戳（纳秒级），用来算延迟 |
| `event._realtime` | 真实时间（Unix 时间戳），只用来显示 |
| `event._event` | 事件名字（如 `"sched:sched_wakeup"`）|
| `event._callchain` | 调用栈（要开 `-g` 才有）|

## 5.2 事件特定字段

每种事件除了通用字段，还有自己独特的字段。比如 `sched:sched_wakeup` 有：

| 字段 | 含义 |
|---|---|
| `event.comm` | 被唤醒的进程名 |
| `event.pid` | 被唤醒的进程 PID |
| `event.prio` | 优先级 |
| `event.target_cpu` | 被唤醒到哪个 CPU 上 |

**怎么知道某个事件有哪些字段？** 四种办法，从"内核最权威"到"运行时最方便"排列：

1. **直接看内核暴露的格式定义**（最权威）：

   ```bash
   cat /sys/kernel/tracing/events/sched/sched_wakeup/format
   ```

   输出会列出这个 tracepoint 的每个字段名、类型、偏移和长度——这是 perf-prof 解析事件字段的原始依据。

2. **用 `perf-prof trace` 查看事件帮助**：

   ```bash
   perf-prof trace -e sched:sched_wakeup help
   ```

   会打印这个事件的字段列表和一个示例过滤器写法，比读 `format` 文件更易读。

3. **用 `perf-prof python help` 生成脚本模板**：

   ```bash
   perf-prof python -e sched:sched_wakeup help > my_script.py
   ```

   生成的脚本骨架里，每个事件处理器的 docstring 就列了所有可用字段及类型，边写边看，最省心。

4. **在脚本里运行时打一下**（临时探索最快）：

   ```python
   def __sample__(event):
       print(event.keys())     # 列出所有字段名
       print(event.to_dict())  # 转成字典看看具体内容
   ```

## 5.3 访问字段的几种方式

`PerfEvent` 用起来跟 Python 里的对象/字典差不多，怎么顺手怎么来：

```python
def sched__sched_wakeup(event):
    # 方式一：属性访问（推荐，最快）
    pid = event.pid
    comm = event.comm

    # 方式二：字典风格
    pid = event['pid']

    # 方式三：get，可以给默认值
    comm = event.get('comm', '未知')

    # 判断字段在不在
    if 'target_cpu' in event:
        print(event.target_cpu)

    # 遍历所有字段
    for name, value in event:
        print(f"{name} = {value}")
```

## 5.4 打印事件

如果你只想按 perf-prof 的通用格式把事件打出来看看，直接 `event.print()`：

```python
def __sample__(event):
    event.print()
```

输出会像这样：

```
2026-07-17 10:23:11.045123     mysqld  12345 [003]: sched:sched_wakeup: comm=worker pid=12346 target_cpu=003
```

不想要时间戳就 `event.print(timestamp=False)`，不想要调用栈就 `event.print(callchain=False)`。

## 5.5 一个稍完整的例子：调度延迟统计

把上面所有东西拼在一起，做一个"计算进程从被唤醒到真的开始跑之间的延迟"的小工具：

```python
# 记录每个进程的唤醒时间
pending = {}
# 收集所有延迟样本
latencies = []

def sched__sched_wakeup(event):
    # 有进程被唤醒了，记下时间
    pending[event.pid] = event._time

def sched__sched_switch(event):
    # 有进程真的开始跑了
    next_pid = event.next_pid
    if next_pid in pending:
        # 算一下从唤醒到跑起来隔了多久
        latency_us = (event._time - pending[next_pid]) / 1000
        latencies.append(latency_us)
        del pending[next_pid]

def __interval__():
    if latencies:
        avg = sum(latencies) / len(latencies)
        print(f"平均调度延迟: {avg:.1f} μs, 最大: {max(latencies):.1f} μs, 样本数: {len(latencies)}")
        latencies.clear()
```

跑起来：

```bash
perf-prof python -e sched:sched_wakeup,sched:sched_switch -i 1000 latency.py
```

30 行代码，就得到了一个能长期跑的调度延迟观测工具。

# 六、实战一：func_latency —— 看函数调用了谁、各花了多久

有了前面基础，我们来看第一个真实工具，感受下这套东西能走多远。源码：[tools/func_latency.sh](https://github.com/duanery/perf-prof/blob/main/tools/func_latency.sh) + [tools/func_latency.py](https://github.com/duanery/perf-prof/blob/main/tools/func_latency.py)。

## 6.1 场景

你怀疑某个函数慢，但它下面还调了一堆子函数，甚至跨用户态和内核态。你想知道：
- 这个函数**调用了哪些子函数**？每个被调了几次？
- **每一层各自耗时多少**？P50、P95、P99 是多少？
- **同一个子函数**从不同路径调进去，耗时有差别吗？

传统办法要么侵入性大（改源码打点、加 log）、要么粒度粗（gprof）、要么只覆盖一层（strace 只看系统调用）。

## 6.2 用什么内核机制

这里选的不是 tracepoint，而是 **uprobe 和 kprobe**——这俩是内核给我们的"动态插桩"能力：

- **uprobe**：挂在用户态二进制的任意函数入口
- **uretprobe**：挂在用户态函数的返回位置
- **kprobe / kretprobe**：内核态版本

好处是**零源码修改**：不用重编译目标程序，perf-prof 起来时挂上，退出时卸下，程序完全不知道被观察了。

## 6.3 核心思路：按线程维护调用栈

一次函数调用会产生两个事件：入口时的 `uprobe`（或 `kprobe`）和返回时的 `uretprobe`（或 `kretprobe`）。要算耗时，得把这两个事件配对起来。

**关键观察**：只有**同一个线程**上的入口和返回才能配对（不然就是不同调用了）。所以按线程 ID 维护一个栈：

```
call_stacks[tid] = [
    (函数名, 完整路径, 入口时间戳),
    ...
]
```

- **入口事件**：压栈，同时把它挂到父函数下面形成路径（如 `root_A → child_1`）
- **返回事件**：从栈顶找最近同名的那一帧，弹出来，用当前时间戳减入口时间戳就是耗时

> **例外说明**：极少数内核函数——如软中断、硬中断处理、进程切换相关函数——会横跨线程上下文，按 tid 维护调用栈时可能出现帧错位。非内核开发者遇到这种情况一般无需深究。

## 6.4 一个不那么显然的决策：按"完整调用路径"聚合

一开始最容易想到的是"按函数名聚合"——所有 `child_func_1` 的样本合起来算个平均值。但这样会误导：

同一个 `child_func_1`：
- 从 `root_A` 调进去时，可能走了短路径，几十微秒
- 从 `root_B` 调进去时，参数不同、命中锁竞争，可能几百微秒

混在一起看，你会看到一个奇怪的双峰分布，不知道哪种情况才是问题。

所以按**完整路径**作 key：`('root_A', 'child_1')` 和 `('root_B', 'child_1')` 分开统计。

## 6.5 另一个坑：跨 CPU 事件乱序

同一次函数调用的入口事件和返回事件，可能分别落在不同的 CPU 上。perf-prof 每个 CPU 有独立的事件缓冲区，如果不做全局排序，你的脚本可能**先收到返回事件、后收到入口事件**——算出来是负数。

解决办法就一个：加 `--order` 让 perf-prof 做全局时间排序。func_latency 的 shell 前端会自动补上这个参数，用户不用记。

## 6.6 真实案例：分析 QEMU virtio 设备状态变更耗时

以一个真实场景为例：**QEMU 虚拟机热迁移时，需要切换 virtio 设备状态，过程涉及数据面 enable/disable、通知机制切换、VFIO 中断切换等一系列内核和用户态操作**。想知道整条链路的耗时分布，就是 func_latency 的典型用武之地。

**命令：**

```bash
./func_latency.sh \
  -b /usr/local/bin/qemu-system-x86_64 \
  -u virtio_net_vhost_status \
  -u vhost_vfio_blk_set_status \
  -u enable_datapath \
  -u disable_datapath \
  -u vhost_vfio_dev_enable_intr \
  -k vfio_pci_set_msi_trigger \
  -u virtio_vmstate_change \
  -u virtio_pci_set_guest_notifiers \
  -u virtio_pci_set_host_notifier \
  -u virtio_pci_set_host_notifiers \
  -i 5000 -m 256
```

`-b` 指定 QEMU 二进制路径，`-u` 挂用户态函数、`-k` 挂内核态函数（`vfio_pci_set_msi_trigger` 是 VFIO 内核路径），`-i 5000` 每 5 秒出一次统计，`-m 256` 增大 ringbuffer（QEMU 事件较密）。shell 前端把这些 `-u/-k` 展开成 perf-prof 的 `-e uprobe:...,uretprobe:...,kprobe:...,kretprobe:...` 事件串，Python 侧完全不感知具体函数名——用户临时增删探针不用改脚本。

**输出：**

```
Loaded module: /data/func_latency.py
2026-07-19 10:04:33
function                                           N  TOTAL(us)    MIN(us)    AVG(us)    P50(us)    P95(us)    P99(us)    MAX(us)
---------------------------------------------------------------------------------------------------------------------------------
virtio_net_vhost_status                           16     168.28       6.93      10.52       7.46      46.30      46.30      46.30
vhost_vfio_blk_set_status                          8      74.44       7.20       9.30       7.38      21.87      21.87      21.87
virtio_vmstate_change                             34  179804.06      19.59    5288.35    2401.36   10997.95   11565.50   11565.50
  |- virtio_net_vhost_status                      16  150131.54    7447.80    9383.22    9416.98   11516.19   11516.19   11516.19
  |  |- disable_datapath                           8   32166.55    3597.70    4020.82    3905.96    4811.18    4811.18    4811.18
  |  |  |- vhost_vfio_dev_enable_intr              8   31823.50    3561.08    3977.94    3871.23    4746.97    4746.97    4746.97
  |  |  |  |→ vfio_pci_set_msi_trigger             8   31250.76    3495.59    3906.35    3812.97    4618.15    4618.15    4618.15
  |  |- virtio_pci_set_host_notifiers             16   29264.41    1458.70    1829.03    1714.65    2465.45    2465.45    2465.45
  |  |- virtio_pci_set_guest_notifiers            16   28846.73     355.71    1802.92    1135.78    4513.29    4513.29    4513.29
  |  |- enable_datapath                            8   51229.97    6258.62    6403.75    6297.70    6551.56    6551.56    6551.56
  |  |  |- vhost_vfio_dev_enable_intr              8   41071.35    4925.47    5133.92    5065.64    5367.77    5367.77    5367.77
  |  |  |  |→ vfio_pci_set_msi_trigger             8   40529.14    4859.90    5066.14    4998.69    5317.13    5317.13    5317.13
  |- vhost_vfio_blk_set_status                    16   28675.69     954.23    1792.23    2179.37    2475.19    2475.19    2475.19
  |  |- disable_datapath                           8    5611.09     589.53     701.39     667.96     952.80     952.80     952.80
  |  |  |- vhost_vfio_dev_enable_intr              8    5396.28     563.60     674.54     637.25     928.31     928.31     928.31
  |  |  |  |→ vfio_pci_set_msi_trigger             8    4657.22     517.04     582.15     531.75     865.36     865.36     865.36
  |  |- virtio_pci_set_guest_notifiers            16    4148.75     103.03     259.30     120.23     425.93     425.93     425.93
  |  |- virtio_pci_set_host_notifier              64    1791.04       7.26      27.99      13.15      54.81      63.81      63.81
  |  |- enable_datapath                            8   11796.75    1394.60    1474.59    1463.17    1571.13    1571.13    1571.13
  |  |  |- vhost_vfio_dev_enable_intr              8   11341.85    1336.28    1417.73    1408.43    1513.74    1513.74    1513.74
  |  |  |  |→ vfio_pci_set_msi_trigger             8   10866.85    1275.60    1358.36    1360.44    1445.57    1445.57    1445.57
```

用户态函数用 `|-` 缩进，内核态用 `|→`（这里 `vfio_pci_set_msi_trigger`）——一眼就能分清跨态边界。分位数是**精确算法**（对每条路径的样本排序后取相应位置），不用 T-Digest 近似，常规场景样本量不大，精确算法更简单可信。

**这个输出里能一眼看出的通用信息（不局限于 QEMU 场景）：**

1. **函数调用关系一目了然**——树形缩进直接呈现"谁调了谁"的完整拓扑：`virtio_vmstate_change` 下面挂着 `virtio_net_vhost_status`、`vhost_vfio_blk_set_status`，每个里面又展开出 `disable_datapath` - `enable_datapath` - `virtio_pci_set_*` 等子函数。要注意的是：**追踪哪些函数需要先读懂源码**，越熟悉源码越知道该跟哪几个函数；func_latency 做的是把源码里的调用关系用实测数据画出来，源码理解仍然是前置条件。

2. **同一函数在不同调用路径下独立统计**——`vhost_vfio_dev_enable_intr` 在输出里出现了 4 次，分别在 4 条不同的父路径下，耗时从 563 μs 到 5.1 ms 不等，差 **7 倍**。如果只按函数名聚合成一行"vhost_vfio_dev_enable_intr 平均 X μs"，这种差异就完全被淹没了——**慢在哪条路径根本看不出来**。这是 6.4 节讲的"按完整路径聚合"发挥价值的地方。

3. **用户态调到内核态无缝可见**——用户态帧用 `|-`，内核态帧用 `|→`（例子里的 `vfio_pci_set_msi_trigger`），一眼就分清跨态边界。传统上用户态调用链要用 gdb/perf，内核态调用链要用 ftrace/bpftrace，**两侧数据在两个工具里各拿一半再手工拼接是家常便饭**；func_latency 让 uprobe 和 kprobe 在同一棵调用树里出现，跨态热点一次性可见。

4. **每个函数的耗时分布（N/MIN/AVG/P50/P95/P99/MAX）**——只看均值容易被极端值带偏，只看 MAX 又会被单次抖动误导。`virtio_vmstate_change` 平均 5.3 ms、P99 11.6 ms，说明**平均值和长尾差 2 倍**——是长尾问题还是稳定慢一目了然。P50/P95/P99 的组合足以判断分布形态，无需再手工整理直方图。

5. **调用路径上各函数的耗时占比**——父函数的 TOTAL 减去所有子函数的 TOTAL，剩下的就是父函数"自己的"开销。以 `enable_datapath`（TOTAL 51 ms）→ `vhost_vfio_dev_enable_intr`（41 ms）→ `vfio_pci_set_msi_trigger`（40 ms）为例，**几乎所有时间都在最内层的内核函数里**——优化重心立刻锁定，不用再猜。

6. **调用次数 × 单次耗时 = 累积开销**——N 列直接给出调用次数。`virtio_pci_set_host_notifier` 单次只有 28 μs，看起来无害，但 N=64 意味着每轮要调 64 次；如果单次涨到 1 ms 就是 64 ms 的隐藏瓶颈。**"高频小调用累积成大开销"是最容易被忽略的性能陷阱**，这份输出能一眼捕捉到。

在没有 func_latency 之前，做这类分析往往要靠**在每个函数入口/出口手工加 `clock_gettime()` + printf**——侵入代码、要重编译。用 func_latency 直接挂 uprobe/kprobe，**零源码修改、一条命令拿到调用树 + 精确分位数**，紧急问题分析场景下差别就是"当天能定位"和"下次上线才能定位"。

## 6.7 已知边界

| 情况 | 表现 | 缓解 |
|---|---|---|
| 忘了加 `--order` | 跨 CPU 事件乱序，返回事件早于入口，算出负耗时 | shell 前端默认自动补上，用户显式传就跟随用户 |
| 事件太多缓冲区丢 | 部分样本漏 | 增大 `-m` |
| 编译器 inline 了函数 | uprobe 挂不上 | 加 `__attribute__((noinline))` |
| 尾调用优化 | `foo() { return bar(); }` 变成 jmp | 编译时 `-O0` 或 `-fno-optimize-sibling-calls` |
| 高频（>10k/s）函数 | 开销明显 | 用 `-p PID` 限定进程范围 |

# 七、实战二：exec_trace —— 谁在跑什么

源码：[tools/exec_trace.py](https://github.com/duanery/perf-prof/blob/main/tools/exec_trace.py)。

## 7.1 场景

- 有个奇怪的短命进程反复被拉起，是谁调的？完整命令行是什么？
- 排查安全事件：某个二进制被 setuid 起来，从哪个 shell、cron、service 出来？
- 怀疑 `LD_PRELOAD` 被劫持
- 排查"进程看着像 `/usr/bin/ls`，但真实二进制已被删除或来自匿名内存"的 fileless 攻击

传统办法各有短板：
- `ps` 轮询会漏短命进程；间隔越短开销越大且仍会漏
- `auditd` 配置繁琐、日志格式重、要求内核带 audit 支持
- `bpftrace execsnoop` 需要 4.1+ 内核，默认只打 argv，父进程、cwd、环境变量都要自己扩

## 7.2 用什么内核机制

选的是内核 tracepoint **`sched:sched_process_exec`**——每次进程 exec 都会触发，字段有：

| 字段 | 含义 |
|---|---|
| `filename` | 内核请求执行的文件路径 |
| `pid` | 新的进程 ID（TGID）|
| `old_pid` | exec 前发起线程的 TID |

3.10 内核就有这个 tracepoint，兼容性极佳。

## 7.3 核心思路：事件到达后立刻读 /proc

`sched:sched_process_exec` 只给了文件名和 PID，其它上下文（父进程、cwd、环境变量、真实二进制路径……）内核没直接塞进事件里。这些信息其实都在 `/proc/<pid>/` 下面：

| 我们想要 | 从哪读 |
|---|---|
| 完整命令行 | `/proc/<pid>/cmdline` |
| 父进程 PID | `/proc/<pid>/status` 里的 `PPid` |
| 工作目录 | `/proc/<pid>/cwd`（软链接）|
| 身份 | `/proc/<pid>/status` 里的 `Uid`, `Gid`, `loginuid` |
| 环境变量 | `/proc/<pid>/environ` |
| 真实二进制 | `/proc/<pid>/exe`（软链接）|
| 标准输入输出 | `/proc/<pid>/fd/{0,1,2}` |

**必须立即读**——短命进程可能几毫秒后就退出，环境变量、cwd 也可能被程序自己改掉。所以脚本在收到 exec 事件的第一时间就把要的东西全读了。

## 7.4 三个关键的工程决策

**决策一：`//batch=1/` 让事件立刻醒**

perf-prof 默认会攒一批事件再唤醒用户态，这在高吞吐场景是好事，但对 exec 这种"每次都珍贵"的低频事件，会把打印延迟拉到几百毫秒甚至秒级。加 `//batch=1/` 让每个 exec 事件立刻唤醒，实时性拉满。

**决策二：`--order` 保证因果推理正确**

多 CPU 事件乱序问题（第六节讲过）在这里更微妙：如果 A 进程 fork 出 B 进程，B 又立刻 exec，你想推理"是 A 拉起了 B"就需要事件严格按时间序到达。加 `--order` 保证这一点。

**决策三：每个上下文字段独立开关**

`--parent`, `--cwd`, `--uid`, `--env`, `--exe`, `--std` 是六个独立开关，默认全关。这样：

- 主行始终最紧凑：`时间 CPU PID 完整命令行`
- 用户只为自己关心的信息付出读 procfs 的成本
- 排查安全事件时想看 `LD_PRELOAD`，只开 `--env LD_PRELOAD` 一项，别的都不显示

## 7.5 一堆需要小心处理的边界

exec_trace 里最花心思的部分不是主逻辑，而是各种边界。**"信息缺失"和"没这个东西"必须能区分**——不然用户看到空白只会更懵：

| 场景 | 处理 |
|---|---|
| 短命进程在读 procfs 前已退出 | 主行仍用事件字段里的 `filename` 打，上下文行标 `(unavailable)` |
| `loginuid` 未设置（内核给 `0xFFFFFFFF`）| 打 `-`，别让用户以为"这是个 42 亿用户" |
| shebang、符号链接、memfd、二进制被删了 | `--exe` 显示真实路径；跟 `filename` 不一致时追加一行 `filename: ... (!= exe)` 把异常推到用户眼前 |
| `--env A,B` 里 `A` 存在但 `B` 未设 | `A=xxx` `B=(unset)`，让"没读到"和"没设"分明 |

## 7.6 输出

```bash
./exec_trace.py --name bash --parent --uid --exe
```

`--name bash` 只关心 basename 为 `bash` 的 exec，`--parent`/`--uid`/`--exe` 分别按需打开父进程、身份、真实二进制这三段上下文。跑起来后，某次有人 `sudo` 起脚本时的输出：

```
[2026-07-17 10:23:11.045123] CPU:2 PID:20481 /bin/bash /tmp/deploy.sh --stage=1
    parent:  PPID:1234  /usr/bin/sudo /tmp/deploy.sh --stage=1
    uid:     uid=0/0 gid=0/0 loginuid=1000
    exe:     /usr/bin/bash
    filename: /tmp/deploy.sh  (!= exe)
```

这个输出的意思：sudo 起了一个 `bash /tmp/deploy.sh`，真实运行的是 `/usr/bin/bash`（filename 是脚本路径，`!=` 提示读者），loginuid 是 1000（登录用户 uid=1000），但当前有效 uid 已被 sudo 提到 0（root）。

**这份看似平淡的输出里能一眼看出的通用信息：**

1. **事件与上下文一次到齐**——`sched:sched_process_exec` 只给了 `filename` + `pid`，其它信息（父进程、cwd、真实二进制、身份）全是脚本在事件到达那一刻**主动去 procfs 补回来**的。用户看到的是完整一行，不需要事后再去 `ps` / `readlink` 拼。
2. **`!=` 一眼定位到异常**——正常情况下 `filename` 与 `exe` 的 basename 一致，脚本对齐后无输出；一旦不一致（shebang、符号链接、memfd、二进制被删）就自动多一行，把"看起来在跑 X，实际在跑 Y"这种排查安全事件时最关键的证据推到用户眼前。
3. **loginuid 揭示"是谁在操作"**——effective uid 已经是 0，但 loginuid=1000 保留了"最初以哪个用户身份登录"的事实，`sudo`、`setuid` 提权链条一目了然。这个字段 `ps` 是不给的，只有直接读 `/proc/<pid>/loginuid` 才拿得到。

在没有 exec_trace 之前，同样的信息要靠 `ps` 轮询（漏短命进程）、`auditd`（配置繁琐、日志重）或 `bpftrace execsnoop`（4.1+ 内核、默认只有 argv 要自己扩）拼出来。exec_trace 用一个 tracepoint + 一段 procfs 读取代码，就把这些短板一次补齐。

## 7.7 命令行

工具自带 shebang，直接跑：

```bash
./exec_trace.py --name 'python*'                       # 所有 python 相关的启动
./exec_trace.py --name sudo --parent --cwd --uid       # 谁在哪儿跑 sudo
./exec_trace.py --uid --env LD_PRELOAD,LD_LIBRARY_PATH # 排查 LD_PRELOAD 劫持
./exec_trace.py --exe                                  # 排查已删除的二进制
```

## 7.8 和 func_latency 对比一下

放到一起看，两个工具的形状很像：

1. 都是**事件驱动的用户态执行**——用户态代码不是靠定时器周期性醒来轮询、也不是主动去采样，而是"**内核里发生了对应事件，才把用户态回调叫起来**"。没事件就零开销，有一次事件才处理一次，实时性和精确性兼得。定时器/轮询式的做法要么错过短暂事件，要么空转烧 CPU，事件驱动天然绕开了这两头。
2. 事件源都是**内核提供的机制**（tracepoint 或 uprobe/kprobe），perf-prof 只是把内核已经埋好的观察点转成 Python 事件——没有内核那一层原生支持，用户态无论怎么写都做不到"每次进程 exec 都醒来一次"。
3. Python 层做的都是"**内核给不了的事**"——func_latency 做跨事件配对和路径聚合，exec_trace 做进程外的上下文回读。
4. 都是**一个 Python 脚本 + 可选一个 shell 前端**，加起来一两百行。
5. 用户命令行像日常工具，看不到 perf-prof 的原始事件字符串。

这就是 perf-prof python 的典型用法：**C 层负责把事件读出来，你用 Python 处理"业务层面"的分析逻辑**。

## 7.9 这个模式还能做很多其它工具

func_latency 和 exec_trace 只是"事件源 + Python 处理"这个模式的两个具体样本。同样的骨架换一组事件，就能长出一批不同用途的工具。抛砖引玉几个方向：

| 想解决的问题 | 用哪些事件 | Python 层做什么 |
|---|---|---|
| **进程调度延迟根因** | `sched:sched_wakeup` + `sched:sched_switch` | 按 pid 配对唤醒与真正 running 的时间差，输出 P50/P99 |
| **谁在打开/关闭大量 fd** | `syscalls:sys_enter_openat` + `sys_exit_close` | 按进程聚合 open/close 计数，找 fd 泄漏 |
| **短命进程分析** | `sched:sched_process_exec` + `sched:sched_process_exit` | 按 pid 配对算存活时间，找 fork 风暴 |
| **锁等待时长** | `sched:sched_switch`（`prev_state=D`）+ 内核锁 tracepoint | 按 pid 聚合"因锁阻塞"的时间分布 |
| **块设备 IO 延迟拆解** | `block:block_rq_issue` + `block:block_rq_complete` | 按 dev/pid 聚合下发→完成延迟 |
| **网络重传定位** | `tcp:tcp_retransmit_skb` | 按 (src, dst, port) 聚合重传次数，找异常连接 |
| **页错误来源** | `exceptions:page_fault_user` + PMU 栈采样 | 按用户态栈聚合 major/minor 缺页 |
| **业务函数被谁调的** | 目标函数 `uprobe` + PMU stack sample | 每次调用取一次栈，聚合成火焰图 |

每个想法在 perf-prof python 里通常只是**几十到一两百行 Python**：选一两个内核事件、定义相应的回调函数、维护少量跨事件状态、周期性输出。真正难的是"想清楚要观察什么、怎么定义'一次事件'"——这一步是**分析思维**而不是编程能力。

对于普通用户来说，还有一个更实际的门槛：**上面那张表里"用哪些事件"这一列你根本不知道怎么填**——Linux 内核里到底有哪些 tracepoint、每个字段是什么、能不能拿到你要的信息，翻内核代码/文档是长路径。好在这类问题恰好是 AI 最擅长回答的。下面第八节就讲：**从"我有个想法"到"跑起来的脚本"，怎么一步步借助 AI 快速生成**。

# 八、借助 AI 快速生成分析脚本

前面看到，写一个分析工具的关键其实就三件事：
1. **选对内核事件**——从哪里能拿到我需要的信息？
2. **写好状态维护**——跨事件要保存什么？
3. **组织输出**——想看到什么？

其中第 1 步对普通用户是最陌生的——**你根本不知道 Linux 内核里有哪些跟踪点**。第 2、3 步好办，是纯 Python 编程。所以下面重点讲第 1 步怎么用 AI 弥补。

## 8.0 先给 AI 装上 perf-prof 的"知识包"

AI 通用模型知道 tracepoint、uprobe 是什么，但**不一定知道 perf-prof 的具体接口**（`__sample__`, `sched__sched_wakeup` 命名规则、`PerfEvent` 字段、`-e` 语法、`//batch=1/` 之类的事件属性）。让 AI 少猜错，最有效的做法就是在会话开头让它先读两份文档：

- **[skills/perf-prof/SKILL.md](https://github.com/duanery/perf-prof/blob/main/skills/perf-prof/SKILL.md)** —— 面向 AI 的整体 Skill 包（perf-prof 使用规范、工作流程、常见陷阱）。
- **[skills/perf-prof/references/profilers/python.md](https://github.com/duanery/perf-prof/blob/main/skills/perf-prof/references/profilers/python.md)** —— python 分析器的完整参考（回调函数、`PerfEvent` API、事件字段访问、示例脚本）。

## 8.1 第一步：先问 AI "有哪些内核事件能给我这个信息"

不用查内核源码，直接向 AI 提问：

> "我想观察 XXX 现象，Linux 内核里有哪些 tracepoint / kprobe 可以拿到相关信息？"

举几个例子看 AI 会怎么回答：

**例 1：想看进程调度延迟**

> **你**："我想看每个进程从被唤醒到真的开始运行之间等了多久，Linux 内核有哪些跟踪点能拿到这些信息？"
>
> **AI**：需要两个 tracepoint：
> - `sched:sched_wakeup` —— 进程被唤醒时触发，字段有 `comm/pid/target_cpu`
> - `sched:sched_switch` —— CPU 切换到新进程时触发，字段有 `prev_pid/next_pid/prev_state`
>
> 用 `sched_wakeup` 的时间戳减 `sched_switch` 的时间戳（按 `next_pid == 唤醒的 pid` 匹配），就是调度延迟。

**例 2：想看谁在启动进程**

> **你**："我想实时知道每次有新进程通过 exec 启动，Linux 有对应的跟踪点吗？"
>
> **AI**：`sched:sched_process_exec` tracepoint，事件字段有 `filename/pid/old_pid`。3.10 内核就有。补充信息（父进程、环境变量等）需要事件到达后读 `/proc/<pid>/*`。

**例 3：想看某个用户态函数的耗时**

> **你**："我想看 mysqld 的某个函数被调了多少次、每次多久，怎么做？"
>
> **AI**：用 uprobe。挂 `uprobe:/path/to/mysqld:函数名` 拿入口事件，挂 `uretprobe:/path/to/mysqld:函数名` 拿返回事件，两个时间戳相减即是耗时。

这一步把你从"要读内核代码/文档"的鸿沟里直接拉出来。**AI 是内核跟踪点的活字典**，用对了比自己查快得多。

## 8.2 第二步：让 AI 帮你查事件字段

拿到事件名后，可以进一步问 AI 有哪些字段。或者用 perf-prof 自带的模板生成器：

```bash
perf-prof python -e sched:sched_wakeup help > draft.py
```

模板里每个事件处理器的 docstring 都列了所有字段和类型。把这份模板连同你的目标发给 AI，AI 就不用凭空猜接口，直接对着字段清单写业务代码。

## 8.3 第三步：把需求拆成三段给 AI

跟 AI 说需求时，切成三段能大大提高一次成型率：

1. **每种事件代表什么业务动作**
   例：`uprobe` = 进入函数，`uretprobe` = 函数返回
2. **需要跨事件保存什么状态、以什么为 key**
   例：以线程 ID 为 key 维护调用栈
3. **输出什么样子**
   例：树形表格，每 5 秒一次

用这个模板给 AI 写 prompt：

```
我想用 perf-prof python 写一个分析器，目标：<一句话>

第一步（AI 先回答我）：我要观察的现象是 XXX，
Linux 内核里有哪些 tracepoint / kprobe / uprobe 可以拿到相关信息？

第二步（选定事件后再进行）：
事件：<-e 表达式>
每种事件的语义：
  <事件1> = <做了什么>
  <事件2> = <做了什么>

需要维护的状态：
  key = <什么>
  value = <什么>
  异常场景怎么处理：<丢事件 / 跨窗口 / ……>

输出格式：<树形 / 表格 / JSON>
间隔：<每 N 毫秒 / 仅退出时>

请先用 `perf-prof python -e ... help` 生成骨架，
再基于它实现完整代码。
```

## 8.4 第四步：让 AI 帮你想边界情况

初版跑通后，把代码交回 AI，明确要求："**列出所有可能失败或不符合直觉的场景**"。第七节里 exec_trace 那一堆边界（`loginuid` 未设置显示成 42 亿、短命进程读不到 procfs、二进制路径不一致……）都是这样捞出来的：AI 提候选、人来判断该不该处理，迭代出来的。

## 8.5 第五步：先跑通脚本，再补 shell 前端

先把 Python 脚本跑通，再让 AI 写 shell 前端。前端只做参数拆分和事件串组装，短小、无状态，AI 出错概率低。一开始就纠结命令行反而分散注意力。

# 九、结语

perf-prof python 想做的事其实很朴素：**让每一个熟悉 Python 的人，都能给自己的问题写一个专门的分析工具**。

事件从内核里抓出来这件苦活让 perf-prof 干，业务分析这件轻活让你用最熟悉的 Python 干。至于"哪个内核事件能给我需要的信息"这道门槛，交给 AI 就好——AI 熟悉 Linux 内核的每一个跟踪点，你只要会描述现象。

从"想到一个问题"到"跑起一个工具"，通常一个下午就够了。

老内核、生产环境长期跑、临时紧急排障、想用 Python 生态做二次分析——遇到这些场景，试试 perf-prof python。

# 参考

- [docs/profilers/python.md](https://github.com/duanery/perf-prof/blob/main/docs/profilers/python.md) — python 分析器完整参考手册
- [tools/func_latency_design.md](https://github.com/duanery/perf-prof/blob/main/tools/func_latency_design.md) — func_latency 设计文档
- [tools/exec_trace_design.md](https://github.com/duanery/perf-prof/blob/main/tools/exec_trace_design.md) — exec_trace 设计文档