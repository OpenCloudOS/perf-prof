# exec_trace 设计文档

> **关于名字**：这个脚本原本是 exec-only 的追踪器（默认 shebang 挂
> `sched:sched_process_exec`），后来泛化成"任意事件触发时，快照 on-CPU
> 进程的 cmdline + /proc 上下文"。文件名保留 `exec_trace` 是历史兼容 +
> 常见默认场景（追踪 exec）的直观锚点；实际能力已远不止 exec，把它当作
> "trace anything, get exec-like context"的工具就好。

## 1. 背景与动机

排查 Linux 系统上"谁在做什么"时，常见问题有：

- 谁在卸载 / 加载内核模块？触发那一刻的 cmdline、父进程、身份分别是什么？
  （这是本轮泛化的直接动机——只有 exec 事件是不够的，任何"我关心的内核路
  径"都需要同一份"是谁在操作"的答案。）
- 谁在写某个 sysctl / debugfs 项？谁在 open 一个可疑文件？
- 有个奇怪的短命进程正在被反复拉起，是谁在调它？调的完整命令行是什么？
- 某个二进制被 setuid 提权跑起来了，是从哪个 shell / cron / service 出来的？
- 容器/服务器上突然出现 CPU 尖峰，怀疑是 fork 风暴，需要看到每次 exec 的
  实时命令行、父进程、工作目录、LD_PRELOAD 等上下文。
- 排查 fileless / memfd 类攻击：进程"看着像"跑 `/usr/bin/ls`，实际二进制
  已被删除或来自匿名内存文件。

这些问题的**共性**是：在某个内核事件触发的瞬间，我想要一份"当前 CPU 上
正在跑的进程是谁、它的完整上下文是什么"的快照。事件本身可以是 tracepoint /
kprobe / uprobe，脚本的核心逻辑（读 `/proc/<pid>/*`、格式化输出）对事件
种类无感。

传统办法（`ps` 轮询、`auditd`、`bpftrace execsnoop`）各有短板：

- `ps` 轮询会漏掉短命进程；间隔越短，开销越大且仍会漏。
- `auditd` 能记录但配置繁琐、日志格式重、要求内核带 audit 支持。
- `bpftrace execsnoop` 需要 4.1+ 内核，不覆盖 3.10 老内核；且默认只打
  argv，需要手写扩展才能带上父进程 / cwd / uid / env / stdio。而且它只针
  对 exec 一件事，换个事件（比如 `sched_process_fork` 或 `openat`）还得重
  写脚本。

本工具建立在 perf-prof 的 `python` 分析器之上：

- 默认场景（shebang 直接跑）挂 `sched:sched_process_exec`，事件到达后在
  用户态读 `/proc/<pid>/*` 补齐所有其它上下文——形成一份**低侵入、老内核
  可用、上下文可选打开**的 exec 观测工具。
- 更广义地，脚本本身与"exec"这个具体事件解绑：处理器是 `__sample__`（所
  有事件的默认回调），只要通过 `perf-prof python -e <EVENT> -- exec_trace.py`
  换事件，同一套采集与格式化逻辑就自动作用于任意 tracepoint / kprobe /
  uprobe——变成一个"事件触发 + 进程上下文快照"的通用工具。

## 2. 目标与非目标

### 2.1 目标

1. **默认即 exec 追踪器**：单文件 `chmod +x` 即可执行，shebang 里
   写死 `-e sched:sched_process_exec//batch=1/ --order -m 64`，用户无需
   再手拼命令。
2. **通用事件触发器**：脚本处理器是 `__sample__`，因此只要在命令行覆盖
   `-e <EVENT>`，任何事件都可以复用同一份上下文采集逻辑（fork、openat、
   自定义 kprobe 等）。
3. 每次事件都实时输出：时间戳、CPU、PID、事件名、完整命令行
   （`/proc/<pid>/cmdline`）。
4. 名称/路径过滤（`--name` / `--path`），支持 shell 通配符、可重复。
   过滤基于事件的 `filename` 字段——**仅**对携带该字段的事件（
   `sched:sched_process_exec`、`syscalls:sys_enter_execve` 等）有意义；
   其它事件启用 `--name/--path` 时会被丢弃（无从匹配）。
5. **可选的进程上下文**，逐项开关，默认全部关闭以保留最紧凑输出：
   - `--parent`：父进程 PID + cmdline
   - `--tree`：向上递归 PPid 直到 PID 1，逐层打印祖先 cmdline；覆盖 `--parent`
   - `--cwd`：工作目录
   - `--uid`：real/effective uid/gid + loginuid
   - `--env KEY[,KEY..]`：选择性打印环境变量
   - `--exe`：真实二进制（`/proc/<pid>/exe`），若事件带 filename 且不匹配时给出提示
   - `--std`：stdin/stdout/stderr 各自的 fd 目标
   - `--cgroup-path [SUBSYS,..]`：`/proc/<pid>/cgroup` 所在 cgroup 路径；不带参数打全部，带参数只保留匹配的子系统。命名 `--cgroup-path` 而非 `--cgroup`，是为了避开 `perf-prof python --cgroups` 的长选项前缀缩写匹配
6. 默认 shebang 里带 `//batch=1/` 事件属性做**每事件立即唤醒**，避免
   exec 到打印之间被 batching 延迟拖长；同时不影响用户覆盖 `-e` 后自选
   的事件属性。
7. 兼容 3.10 老内核，仅依赖 `perf_event` + tracepoint + procfs。
8. 单文件、可 `chmod +x` 直接执行（shebang 组装好了 perf-prof 事件串）。

### 2.2 非目标

- 不追求把每个 exec 的完整调用链（execveat / clone→execve 时序、
  memfd_create、seal 等 syscall 参数）都还原。要那个深度请用 bpftrace /
  bcc。
- 不做长期审计存档（无写文件、无 rotate）——本工具用于**紧急 / 交互式
  排障**，日志由使用者自行重定向 (`-o file`)。
- 不做告警/规则匹配；输出是纯文本，供人眼阅读和上游 grep/awk 加工。
- 不做事件间配对/延迟计算；那属于 multi-trace 的领域。
- 不为每种事件手写字段特化。除了通用的 `filename`（用于名字过滤和
  `--exe` 比对）和 `pid`（用于挑 /proc 目标），其它字段一律不解读——
  事件语义由用户在选择 `-e` 时自己承担，这里只提供"进程上下文快照"。

## 3. 系统架构

```
┌──────────────────────┐   任意 tracepoint / kprobe / uprobe   ┌─────────────────────┐
│ Linux kernel         │ ──────────────────────────────────>   │ perf-prof (C)       │
│  (默认: exec 钩子)    │                                       │ ringbuffer + order  │
└──────────────────────┘                                       └────────┬────────────┘
                                                                        │ PerfEvent
                                                                        ▼
                                       ┌──────────────────────────────────────────────┐
                                       │ exec_trace.py (__sample__ callback)          │
                                       │  - event.filename 过滤（有该字段才启用）        │
                                       │  - /proc/<pid>/* 读取 (按开关)                │
                                       │  - 单行主输出 + 可选缩进上下文                   │
                                       └──────────────────────────────────────────────┘
                                                                        ▲
                                       ┌────────────────────────────────┴─────────────┐
                                       │ shebang 默认事件串（可被 -e 覆盖）：             │
                                       │ `-e sched:sched_process_exec//batch=1/       │
                                       │      --order -m 64`                          │
                                       └──────────────────────────────────────────────┘
```

两个组件：

| 组件 | 语言 | 职责 |
|---|---|---|
| `perf-prof python`（C 端） | C | 打开事件、收 ringbuffer、按时序 order、调用回调 |
| `exec_trace.py` | Python | 名称过滤、`/proc/<pid>/*` 上下文采集、格式化输出、统计 |

三种使用姿势：

1. `./exec_trace.py [options]` — 直接跑，shebang 的 `-e` 生效，等价于 exec 追踪器。
2. `perf-prof python -e <EVENT> -- exec_trace.py [options]` — 显式覆盖事件，
   用同一份 Python 逻辑处理任意事件。
3. `perf-prof python -e <EVENT> ... exec_trace.py` — 同上，perf-prof 侧的
   `--order` / `-m` / `-C` / `-p` / `-G` 等选项照常传。

## 4. 组件详细设计

### 4.1 事件通道

**默认事件**：`sched:sched_process_exec`。该 tracepoint 在
`do_execveat_common` 里、`bprm` 展开、地址空间切换完成之后触发，字段：

| 字段 | 语义 |
|---|---|
| `filename` | 内核请求执行的文件路径（`bprm->filename`），可能与真实二进制不同（shebang/memfd） |
| `pid` | 新的 TGID（用户空间意义的 PID） |
| `old_pid` | exec 前发起线程的 TID |

perf-prof python 把上述字段暴露为 `event.filename` / `event.pid` / `event.old_pid`；
`event._cpu` / `event._pid` / `event._realtime` / `event._event` 来自采样公共头。

**处理器选择 `__sample__`**：如果写成 `sched__sched_process_exec`，就跟这
一个事件名字绑死了；改成 `__sample__`（perf-prof python 对"没有专用处理
器的事件"的默认回调）后，任何事件都会走进来，脚本立刻从"exec 追踪器"变
成"事件触发 + 上下文快照"。

**事件属性 `//batch=1/`**（仅默认 shebang）：
`tp->batch` 会被写进 `perf_event_attr.wakeup_events = 1`，效果等价于全局
`--watermark 0`，但只作用于本 profiler 单条事件，不会影响后续用户在同一
event group 里挂的其它事件。**理由**：exec 事件的价值高度依赖时效性
（"当前正在跑什么"），batching 会把打印延迟拉到几百 ms 甚至秒级，做实时
观察时反而误导。用户覆盖 `-e` 后是否加 `//batch=1/` 由自己决定。

**`--order`**：多 CPU ringbuffer 之间独立写入，若不做全局排序，短时间内
连续的事件可能乱序，让"是 A 拉起了 B"这种因果推理失效。开销可控
（exec 频率远低于常规 sched 事件）。

**`-m 64`**：默认 ringbuffer 64 页 / CPU。exec 事件负载小、峰值频率通常
< 1k/s，64 页留有充足头空间。真的碰到 fork 风暴级别时，用户可以在命令行
覆盖 `-m`。

### 4.2 名称过滤

`_match(filename)` 三种情况：

- **未设置** `--name` / `--path`：全部放行（不看 filename）。
- **设置了过滤器，事件无 `filename` 字段**：`_event_filename()` 返回
  `None` → 无从判定，**忽略过滤器**并放行。这样在混合事件（有些带
  filename、有些不带）的场景下，不会因为选了 `--name` 就把 fork /
  wakeup 等事件也一起清掉，用户仍能看到全景。
- **设置了过滤器，事件有 `filename`**：
  - `--name`：与 `basename(filename)` 做 `fnmatch`。
  - `--path`：与完整 filename 做 `fnmatch`。
  - 任一命中即通过。

可重复选项让 `--name ps --name top` 天然成立，避免用户手写正则或 `|` 分隔。

**注意**：用户态 filter 是"事件到达后丢弃"，高频场景仍会付出 syscall +
copy_from_user 的代价。文档里的 `Kernel-side filter` 示例把过滤下推到
tracepoint 层（`sched:sched_process_exec/filename~"*/ps"/batch=1/`），
在忙碌系统上更省。

### 4.3 PID 选择

`_event_pid(event)` 永远返回 `event._pid`——perf sample header 里记录的
采样任务 PID，即"事件触发那一刻正在 CPU 上跑的进程"。

**为什么不用 `event.pid`**：很多事件字段里的 `pid` 语义不是"当前进程"：

- `sched:sched_wakeup` 的 `pid` 是**被唤醒**的进程，不是执行唤醒动作的
  那个进程；
- `sched:sched_switch` 的 `next_pid` / `prev_pid` 是切换双方，"当前进
  程"是哪一个取决于你把哪一侧当作"事件时刻"；
- 其它事件字段里的 `pid` 可能是"目标进程 PID"、"父进程 PID"、甚至恒
  为 0（占位）。

事件太多、字段语义太杂，不可能逐事件特化。统一用 `_pid` 换来一个稳定
不变的语义："这个进程当时正在 CPU 上"——正好也是"应该读它 /proc 快照"
的那个进程。

`sched:sched_process_exec` 里两者恰好相等（exec 由目标进程自己执行），
所以默认场景没有区别；一旦切到 `sched_wakeup` 这类事件，选 `_pid` 才不
会读错 /proc 目标。

**PID 0 直接跳过**：`_pid == 0` 表示事件采样在 idle 任务上（CPU 当时空
闲）。`/proc/0` 没有 cmdline / status / cwd 等可读项，逐条打
`(cmdline unavailable)` 只是噪音，因此在 `__sample__` 里直接
`return`——不计入 `matched`，也不产生输出。

### 4.4 主输出与上下文

**主输出**（无条件）：

```
[YYYY-MM-DD HH:MM:SS.uuuuuu] CPU:N   PID:P   [event]   <cmdline>
```

其中 `[event]` 是 `event._event`（tracepoint 是 `sys:name`，profiler
事件是 profiler 名或别名）。默认场景下这里恒为
`sched:sched_process_exec`；换事件后能一眼看出触发源。

`cmdline` 从 `/proc/<pid>/cmdline` 读回来，`\0` 分隔的 argv 用空格拼接。
拿不到时（进程已退出 / PID 对不上等）主行的 cmdline 位置固定显示
`(cmdline unavailable)`——用"失败"和"成功"两种视觉状态区分开。若事件
带 `filename` 字段，把它追加在标记后面（例如
`(cmdline unavailable) /tmp/deploy.sh`），既保留失败信号，又给出"当时想
跑的是什么"这条最小上下文。

**上下文行**：每个 `--xxx` 开关对应一段读取函数 + 一行（`--std` 三行）
输出，统一 4 空格缩进、label 宽 8 对齐冒号。设计上：

- 每项都是独立开关，用户按需付出 procfs 读的成本。
- 读取尽早：事件到来立即读，避免进程回收、cwd 后续 `chdir`、
  environ 被覆盖等造成的失真。
- 读失败一律**不阻塞其它字段**、显式打印 `(unavailable)` / `(gone)` /
  `(closed)`，让残缺状态可见（"信息缺失"和"没这个东西"必须能区分）。

**为什么 `--exe` 才对比 filename**：常规 exec 里 `filename == exe`，同
时打两个是噪音。只有当二者 basename 不一致（shebang / symlink / memfd /
deleted）才追加一行 `filename: ... (!= exe)`，把异常场景推到用户眼前。
basename 而非全路径比较：symlink 的 dirname 天然不同（`/usr/bin/python`
→ `/usr/bin/python3.9`），我们关心的是**跑的程序本身变没变**。事件不带
`filename` 时不做这一对比，只打 `exe:` 一行。

**loginuid 特判**：内核在未设置时返回 `0xFFFFFFFF`，此时打印 `-`，避免用
户以为"这是一个奇怪的 42 亿用户"。

**--env 顺序**：保留用户指定的 KEY 顺序（`--env A,B` 与 `--env B,A` 输出
不同），便于列 grep；漏掉的 KEY 显式 `(unset)`，让"没设"和"没读到"分明。

**--cgroup-path（cgroup 路径）**：直接把 `/proc/<pid>/cgroup` 摊平打印。
设计要点：

- **命名 `--cgroup-path` 而非 `--cgroup`**：`perf-prof python` 自身有
  `--cgroups <cgroup,...>` 选项（把 python 分析器 attach 到指定 cgroup），
  而 subcmd 的 `parse-options` 支持长选项**前缀缩写匹配**
  （`lib/subcmd/parse-options.c:449`）。shebang 模式下 kernel 把整行拼成
  `perf-prof python ... exec_trace.py --cgroup xxx` 一起交给 perf-prof
  解析，`--cgroup` 会被贪匹配成 `--cgroups`，把 `xxx` 吃走后再报错。中
  间加一个 `-` 就打破前缀关系，脚本的选项就能干净地穿透到 python argparse。
- **有无参数两种模式**：`--cgroup-path` 无参 → 全部 controllers 行；
  `--cgroup-path cpu,memory` → 只保留匹配的行。
- **子串匹配、覆盖 v1 的联合 controller**：kernel 会把 `cpu,cpuacct`、
  `net_cls,net_prio` 这种绑在一起的 controller 放在同一行。用户输入
  `--cgroup-path cpu` 是"我想看 cpu 这一支"的意思，因此匹配拆分后的每
  个名字，命中任一即保留。
- **`name=systemd` 也接受 `systemd`**：cgroup v1 的 named hierarchy 表
  达为 `name=systemd`；`--cgroup-path systemd` 也认这一行。
- **`unified` 关键字对应 cgroup v2**：v2 unified hierarchy 那行
  `hier_id=0`、`controllers` 为空，用 `--cgroup-path unified` 明确匹配。
- **和 `--tree` 一样放到多行块位置**：v1 有十几行输出，与前面对齐的
  label:value 一行行混在一起会撑破视觉；放在 `--std` 之后、`--tree` 之
  前，保证"整齐块 → 多行块"两段分明。
- **匹配为空时显式说 `(no match for ...)`**：让"文件读到了、只是没这个子
  系统"和"读不到（unavailable）"两种失败可分。

**--tree（祖先链）**：从事件当时的 on-CPU 进程出发，反复读
`/proc/<pid>/status` 的 `PPid:` 字段向上追溯，直到 PID 1（init）——这样能
一眼看出"是 init/systemd/sshd/bash/rmmod 这条链在卸载模块"，而不是只知道
最外层是谁在直接调。

设计要点：

- **打印位置固定放在所有上下文块之后**。tree 是多行输出，行内格式又是缩
  进树而不是 `label: value`，与前面的 parent/cwd/uid/env/exe/std 这些整
  齐对齐的一行行放在一起会破坏视觉列对齐；放最后可以让"整齐的元数据块 +
  独立的树块"各自成段。
- 输出**倒序**（PID 1 在最上、当前进程在最下），像调用链一样从"责任源
  头"读到"事件当事人"，缩进和 `` `- `` 箭头强化层级视觉。
- 与 `--parent` 组合时**抑制 `--parent`**：`--parent` 是 tree depth=1 的
  特例，同时打两遍冗余；仅在没开 `--tree` 时才输出 parent 行。
- 终止条件三类，每一种都有明确的 `(stopped: ...)` 尾行：
  - 到达 PID 1 → 正常结束，不打尾行；
  - `PPid` 读不到 → `ppid unavailable`（进程已退，或 procfs 不可读）；
  - `PPid == 0` → `reached kernel`（当前是 kthread，父是 swapper）；
  - 出现环 → `loop at PID N`（procfs 竞态或极端异常）；
  - 超过 32 层深度上限 → `depth limit (32)`。
- **32 层硬上限**：真实系统的进程树深度个位数就够（init → systemd →
  service → shell → user program），32 已经宽裕；只是防止极端异常（procfs
  在切换 PID 视图时出现循环等）把脚本挂死。命中上限本身是异常信号，用
  尾行显式暴露。
- **祖先 cmdline 可能为空**：内核线程、僵尸、已回收进程读不到
  `/proc/<ppid>/cmdline`，用 `(gone)` 顶位——保证层级完整，不会因为中间
  某一层拿不到而中断整条链。

### 4.5 生命周期

- `__init__`：打印 header，汇总过滤条件和已启用上下文，作为运行时留痕。
- `__sample__`：每事件回调（perf-prof python 对无专属处理器的事件的默认入口）。
- `__exit__`：打印统计汇总（总事件、匹配数、cmdline 成功/失败计数）。

统计计数放在全局 dict 里，因为回调是无状态函数，Python 闭包的写入语义
不适合 `nonlocal`；dict 就近解决。

## 5. 接口 (CLI)

```
./exec_trace.py [options]         # 默认：exec 追踪器 (shebang -e ...)
    or
perf-prof python -e <EVENT> --order -m 64 -- exec_trace.py [options]
```

| 选项 | 语义 |
|---|---|
| `--name PAT` | 按 basename(event.filename) 过滤（fnmatch），可重复。无 filename 的事件忽略此项 |
| `--path PAT` | 按完整 event.filename 过滤（fnmatch），可重复。无 filename 的事件忽略此项 |
| `--parent`   | 打印父进程 PID + cmdline |
| `--tree`     | 递归向上打印祖先链直到 PID 1（覆盖 `--parent`，深度上限 32） |
| `--cwd`      | 打印工作目录 |
| `--uid`      | 打印 uid/gid（real/effective）和 loginuid |
| `--env K[,K..]` | 打印选择的环境变量，可重复 |
| `--exe`      | 打印真实二进制路径；事件带 filename 且不一致时追加 `filename` 行 |
| `--std`      | 打印 stdin/stdout/stderr 目标 |
| `--cgroup-path [SUBSYS,..]` | 打印 `/proc/<pid>/cgroup`。无参数展示全部；带逗号分隔子系统列表则只保留匹配行（子串匹配；`unified` 匹配 cgroup v2 空 controllers 行）。命名带 `-path` 是为了避开 `perf-prof python --cgroups` 的前缀匹配 |

`-h` 输出完整帮助（含 Output layout、多个 Examples、Notes 段落）。

### 5.1 使用示例

```bash
# 默认：追踪所有 exec（shebang 里的 -e sched:sched_process_exec 生效）
./exec_trace.py

# 按名字过滤（作用于 event.filename）
./exec_trace.py --name 'python*'

# 谁在哪儿跑 sudo：父进程 + cwd + 身份
./exec_trace.py --name sudo --parent --cwd --uid

# 排查 LD_PRELOAD 劫持
./exec_trace.py --uid --env LD_PRELOAD,LD_LIBRARY_PATH

# 排查 fileless / 已删除二进制
./exec_trace.py --exe

# 换成 fork 事件（无 filename 字段，--name/--path 不适用）
perf-prof python -e 'sched:sched_process_fork' \
    --order -m 64 -- exec_trace.py --parent --cwd --uid

# 换成 openat 系统调用
perf-prof python -e 'syscalls:sys_enter_openat' \
    --order -m 64 -- exec_trace.py --parent

# 谁卸载了内核模块？打印完整祖先链
perf-prof python -e 'kprobes:free_module' \
    --order -m 64 -- exec_trace.py --tree --uid

# 高频系统，把过滤下推到内核
perf-prof python -e 'sched:sched_process_exec/filename~"*/ps"/batch=1/' \
    --order -m 64 -- exec_trace.py
```

### 5.2 输出样例

```
========================================================================
  event tracer (default: sched:sched_process_exec)
  Filter:  (all)
  Context: parent, uid, exe
========================================================================

[2026-07-17 10:23:11.045123] CPU:2   PID:20481   [sched:sched_process_exec] /bin/bash /tmp/deploy.sh --stage=1
    parent:  PPID:1234    /usr/bin/sudo /tmp/deploy.sh --stage=1
    uid:     uid=0/0 gid=0/0 loginuid=1000
    exe:     /usr/bin/bash
    filename: /tmp/deploy.sh  (!= exe)
```

带 `--tree` 时（示例：谁在 rmmod）：

```
[2026-07-17 10:24:52.117008] CPU:0   PID:20732   [kprobes:free_module] rmmod nf_conntrack
    tree:
        PID:1       /sbin/init splash
          `- PID:987     /usr/lib/systemd/systemd --user
            `- PID:5011    sshd: alice [priv]
              `- PID:5013    -bash
                `- PID:20732   rmmod nf_conntrack
```

## 6. 边界与限制

| 项 | 说明 | 缓解方案 |
|---|---|---|
| 短命进程 | `sh -c 'true'` 级别的进程可能在 `/proc` 读之前已退出 | 主行固定标 `(cmdline unavailable)`，带 filename 的事件追加 filename；上下文行标 `(unavailable)` |
| environ 被覆盖 | 程序 exec 后可主动改 environ 内存 | 事件到达立即读，最大限度贴近事件那一刻的状态 |
| cwd 之后会变 | `chdir` 会改 `/proc/<pid>/cwd` 软链接 | 同上，只读事件那一刻的值 |
| filename 与真实二进制 | shebang / symlink / memfd / deleted 会造成不一致 | `--exe` 显式对比；不一致时追加 filename 行 |
| 命名空间视图 | procfs 视图受 mnt/pid namespace 影响 | 在同一 ns 里运行 perf-prof；跨 ns 观测需用 `--pid` 或宿主命名空间 |
| 高频事件 | 换到 `openat` / `sys_enter_read` 等高频事件时会刷屏 | 用 kernel-side filter（`event/expr/`）或 perf-prof 的 `-C` / `-p` / `-G` 收窄 |
| _pid == 0 | 事件采样在 idle 任务上，/proc/0 无内容 | 在 `__sample__` 里直接 return，不计入 matched、无输出 |
| event.pid 语义不定 | 部分事件字段是 wakee / 目标进程 / 恒 0 | 一律用 `event._pid`，即"事件触发时 CPU 上的进程" |
| 事件无 filename | fork、schedule、大多数 syscall entry | `--name/--path` 忽略并放行；主行退化到 `(cmdline unavailable)` |
| Python 回调开销 | 每事件几十 μs（procfs 读多则线性放大） | 关闭不需要的上下文开关；把过滤下推到内核 |

## 7. 扩展点

以下方向留出了口子，但当前实现里没有：

1. **`--ancestors`（折叠祖先链）**：`--tree` 的单行版，把父→父→...→自身
   用 `→` 折叠成一行。tree 好读、ancestors 好 grep，面向不同人。
2. **`--ns`**：把 `/proc/<pid>/ns/{pid,mnt,net,...}` 的 inode 打出来，直
   接看到进程属于哪个 pid/mnt/net namespace，容器场景下与 `--cgroup-path` 配
   合定位跨 host 视角。
3. **`--exit`**：额外挂 `sched:sched_process_exit`，按 PID 配对算存活时间
   —— 用来定位"频繁 fork 的短命进程"。现在 `__sample__` 已经能吃多事件，
   实现主要成本是配对状态机与内存回收，而不是多事件本身。
4. **JSON 输出**：把 print 抽象成 `render_text` / `render_json`，便于喂到
   ELK / Prometheus / SIEM。
5. **cgroup 过滤**：`-G <cgroup>` 让 perf-prof 只 attach 到某个 cgroup，
   容器场景更精准。这是 perf-prof 已有能力，不需要脚本侧改动，仅需在文档
   里补充示例。
6. **fd 全景 `--fd`**：不只 0/1/2，而是把 `/proc/<pid>/fd/*` 全部 readlink
   打印；开销大，仅在需要时开启。
7. **按事件类型分派**：现在只有 `__sample__` 一个入口，如果未来对
   `sched_process_fork` / `sched_process_exit` 想给出不同上下文，可以引入
   `sys__event_name` 专属处理器（perf-prof python 原生支持），把当前逻辑
   拆成 dispatcher。

## 8. 文件清单

| 文件 | 大小量级 | 说明 |
|---|---|---|
| `exec_trace.py` | ~370 行 | 单文件工具（含 shebang、CLI、`__sample__` 回调、procfs 读取、渲染） |
| `exec_trace_design.md` | 本文 | 设计文档 |

两个文件同目录、独立自洽。按项目 `tools/` 目录规范，属于同一次提交
（tools 每个独立工具的源码、脚本、文档作为一个整体提交）。