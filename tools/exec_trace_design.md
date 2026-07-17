# exec_trace 设计文档

## 1. 背景与动机

排查 Linux 系统上"谁在跑什么"时，常见问题有：

- 有个奇怪的短命进程正在被反复拉起，是谁在调它？调的完整命令行是什么？
- 某个二进制被 setuid 提权跑起来了，是从哪个 shell / cron / service 出来的？
- 容器/服务器上突然出现 CPU 尖峰，怀疑是 fork 风暴，需要看到每次 exec 的
  实时命令行、父进程、工作目录、LD_PRELOAD 等上下文。
- 排查 fileless / memfd 类攻击：进程"看着像"跑 `/usr/bin/ls`，实际二进制
  已被删除或来自匿名内存文件。

传统办法（`ps` 轮询、`auditd`、`bpftrace execsnoop`）各有短板：

- `ps` 轮询会漏掉短命进程；间隔越短，开销越大且仍会漏。
- `auditd` 能记录但配置繁琐、日志格式重、要求内核带 audit 支持。
- `bpftrace execsnoop` 需要 4.1+ 内核，不覆盖 3.10 老内核；且默认只打
  argv，需要手写扩展才能带上父进程 / cwd / uid / env / stdio。

本工具建立在 perf-prof 的 `python` 分析器之上：`sched:sched_process_exec`
tracepoint 上兼容 3.10，事件到达后在用户态读 `/proc/<pid>/*` 补齐所有其它
上下文——形成一份**低侵入、老内核可用、上下文可选打开**的 exec 观测工具。

## 2. 目标与非目标

### 2.1 目标

1. 每次 exec 都实时输出：时间戳、CPU、PID、完整命令行（`/proc/<pid>/cmdline`）。
2. 名称/路径过滤（`--name` / `--path`），支持 shell 通配符、可重复。
3. **可选的进程上下文**，逐项开关，默认全部关闭以保留最紧凑输出：
   - `--parent`：父进程 PID + cmdline
   - `--cwd`：工作目录
   - `--uid`：real/effective uid/gid + loginuid
   - `--env KEY[,KEY..]`：选择性打印环境变量
   - `--exe`：真实二进制（`/proc/<pid>/exe`），不匹配 filename 时给出提示
   - `--std`：stdin/stdout/stderr 各自的 fd 目标
4. 使用 `//batch=1/` 事件属性做**每事件立即唤醒**，避免 exec 到打印之间被 batching 延迟拖长，
   同时不影响其它事件的 wakeup 配置。
5. 兼容 3.10 老内核，仅依赖 `perf_event` + tracepoint + procfs。
6. 单文件、可 `chmod +x` 直接执行（shebang 组装好了 perf-prof 事件串）。

### 2.2 非目标

- 不追求把每个 exec 的完整调用链（execveat / clone→execve 时序、
  memfd_create、seal 等 syscall 参数）都还原。要那个深度请用 bpftrace /
  bcc。
- 不做长期审计存档（无写文件、无 rotate）——本工具用于**紧急 / 交互式
  排障**，日志由使用者自行重定向 (`-o file`)。
- 不做告警/规则匹配；输出是纯文本，供人眼阅读和上游 grep/awk 加工。
- 不做 exec 后行为跟踪（fd 生命周期、后续 execve、exit code 等）；那属于
  multi-trace 的领域。

## 3. 系统架构

```
┌──────────────────────┐   sched:sched_process_exec   ┌─────────────────────┐
│ Linux kernel         │ ────────────────────────────>│ perf-prof (C)       │
│  do_execve → exec    │                              │ ringbuffer + order  │
│  tracepoint hook     │                              └────────┬────────────┘
└──────────────────────┘                                       │ PerfEvent
                                                               ▼
                                       ┌─────────────────────────────────────┐
                                       │ exec_trace.py (Python callback)   │
                                       │  - name/path 过滤                    │
                                       │  - /proc/<pid>/* 读取 (按开关)       │
                                       │  - 单行主输出 + 可选缩进上下文       │
                                       └─────────────────────────────────────┘
                                                               ▲
                                       ┌───────────────────────┴─────────────┐
                                       │ shebang 里内嵌 perf-prof 事件串       │
                                       │ `-e sched:sched_process_exec        │
                                       │      //batch=1/ --order -m 64`      │
                                       └─────────────────────────────────────┘
```

两个组件：

| 组件 | 语言 | 职责 |
|---|---|---|
| `perf-prof python`（C 端） | C | 打开 tracepoint、收 ringbuffer、按时序 order、调用回调 |
| `exec_trace.py` | Python | 名称过滤、`/proc/<pid>/*` 上下文采集、格式化输出、统计 |

无独立 shell 前端——所有事件参数写在文件首行 shebang 里，用户只需
`./exec_trace.py [options]`，或显式 `perf-prof python -e ... -- exec_trace.py`。

## 4. 组件详细设计

### 4.1 事件通道

**事件选择**：`sched:sched_process_exec`。该 tracepoint 在
`do_execveat_common` 里、`bprm` 展开、地址空间切换完成之后触发，字段：

| 字段 | 语义 |
|---|---|
| `filename` | 内核请求执行的文件路径（`bprm->filename`），可能与真实二进制不同（shebang/memfd） |
| `pid` | 新的 TGID（用户空间意义的 PID） |
| `old_pid` | exec 前发起线程的 TID |

perf-prof python 把上述字段暴露为 `event.filename` / `event._pid`；`event._cpu`
和 `event._realtime` 来自采样公共头。

**事件属性 `//batch=1/`**：
`tp->batch` 会被写进 `perf_event_attr.wakeup_events = 1`，效果等价于全局
`--watermark 0`，但只作用于本 profiler 单条事件，不会影响后续用户在同一
event group 里挂的其它事件。**理由**：exec 事件的价值高度依赖时效性
（"当前正在跑什么"），batching 会把打印延迟拉到几百 ms 甚至秒级，做实时
观察时反而误导。

**`--order`**：多 CPU ringbuffer 之间独立写入，若不做全局排序，短时间内
连续的 exec 事件可能乱序，让"是 A 拉起了 B"这种因果推理失效。开销可控
（exec 频率远低于常规 sched 事件）。

**`-m 64`**：默认 ringbuffer 64 页 / CPU。exec 事件负载小、峰值频率通常
< 1k/s，64 页留有充足头空间。真的碰到 fork 风暴级别时，用户可以在命令行
覆盖 `-m`。

### 4.2 名称过滤

`_match(filename)` 双通道：

- `--name`：与 `basename(filename)` 做 `fnmatch`。
- `--path`：与完整 filename 做 `fnmatch`。

两组任一命中即通过；两组均为空则全部放行。可重复选项让 `--name ps --name top`
天然成立，避免用户手写正则或 `|` 分隔。

**注意**：用户态 filter 是"事件到达后丢弃"，高频场景仍会付出 syscall +
copy_from_user 的代价。文档里的 `Kernel-side filter` 示例把过滤下推到
tracepoint 层（`sched:sched_process_exec/filename~"*/ps"/batch=1/`），
在忙碌系统上更省。

### 4.3 主输出与上下文

**主输出**（无条件）：

```
[YYYY-MM-DD HH:MM:SS.uuuuuu] CPU:N   PID:P        <cmdline>
```

`cmdline` 从 `/proc/<pid>/cmdline` 读回来，`\0` 分隔的 argv 用空格拼接。
拿不到时（进程已退出）主行退化成 `<filename> (cmdline unavailable)`——
仍能给出"跑了什么"的最小可用信息（`filename` 来自事件字段，不依赖 procfs）。

**上下文行**：每个 `--xxx` 开关对应一段读取函数 + 一行（`--std` 三行）
输出，统一 4 空格缩进、label 宽 8 对齐冒号。设计上：

- 每项都是独立开关，用户按需付出 procfs 读的成本。
- 读取尽早：exec 事件到来立即读，避免父进程回收、cwd 后续 `chdir`、
  environ 被覆盖等等造成的失真。
- 读失败一律**不阻塞其它字段**、显式打印 `(unavailable)` / `(gone)` /
  `(closed)`，让残缺状态可见（"信息缺失"和"没这个东西"必须能区分）。

**为什么 --exe 才对比 filename**：常规 exec 里 `filename == exe`，同时打
两个是噪音。只有当二者 basename 不一致（shebang / symlink / memfd /
deleted）才追加一行 `filename: ... (!= exe)`，把异常场景推到用户眼前。
basename 而非全路径比较：symlink 的 dirname 天然不同（`/usr/bin/python`
→ `/usr/bin/python3.9`），我们关心的是**跑的程序本身变没变**。

**loginuid 特判**：内核在未设置时返回 `0xFFFFFFFF`，此时打印 `-`，避免用
户以为"这是一个奇怪的 42 亿用户"。

**--env 顺序**：保留用户指定的 KEY 顺序（`--env A,B` 与 `--env B,A` 输出
不同），便于列 grep；漏掉的 KEY 显式 `(unset)`，让"没设"和"没读到"分明。

### 4.4 生命周期

- `__init__`：打印 header，汇总过滤条件和已启用上下文，作为运行时留痕。
- `sched__sched_process_exec`：每事件回调（perf-prof python 按事件名解析）。
- `__exit__`：打印统计汇总（总事件、匹配数、cmdline 成功/失败计数）。

统计计数放在全局 dict 里，因为回调是无状态函数，Python 闭包的写入语义
不适合 `nonlocal`；dict 就近解决。

## 5. 接口 (CLI)

```
./exec_trace.py [options]
    or
perf-prof python -e 'sched:sched_process_exec//batch=1/' --order -m 64 \
    -- exec_trace.py [options]
```

| 选项 | 语义 |
|---|---|
| `--name PAT` | 按 basename 过滤（fnmatch），可重复 |
| `--path PAT` | 按全路径过滤（fnmatch），可重复 |
| `--parent`   | 打印父进程 PID + cmdline |
| `--cwd`      | 打印工作目录 |
| `--uid`      | 打印 uid/gid（real/effective）和 loginuid |
| `--env K[,K..]` | 打印选择的环境变量，可重复 |
| `--exe`      | 打印真实二进制路径；不一致时追加 `filename` 行 |
| `--std`      | 打印 stdin/stdout/stderr 目标 |

`-h` 输出完整帮助（含 Output layout、多个 Examples、Notes 段落）。

### 5.1 使用示例

```bash
# 追踪所有 python 相关 exec
./exec_trace.py --name 'python*'

# 谁在哪儿跑 sudo：父进程 + cwd + 身份
./exec_trace.py --name sudo --parent --cwd --uid

# 排查 LD_PRELOAD 劫持
./exec_trace.py --uid --env LD_PRELOAD,LD_LIBRARY_PATH

# 排查 fileless 二进制 / 已删除二进制
./exec_trace.py --exe

# 高频系统，把过滤下推到内核
perf-prof python -e 'sched:sched_process_exec/filename~"*/ps"/batch=1/' \
    --order -m 64 -- exec_trace.py
```

### 5.2 输出样例

```
========================================================================
  exec command line tracer
  Filter:  (all)
  Context: parent, uid, exe
========================================================================

[2026-07-17 10:23:11.045123] CPU:2   PID:20481    /bin/bash /tmp/deploy.sh --stage=1
    parent:  PPID:1234    /usr/bin/sudo /tmp/deploy.sh --stage=1
    uid:     uid=0/0 gid=0/0 loginuid=1000
    exe:     /usr/bin/bash
    filename: /tmp/deploy.sh  (!= exe)
```

## 6. 边界与限制

| 项 | 说明 | 缓解方案 |
|---|---|---|
| 短命进程 | `sh -c 'true'` 级别的进程可能在 `/proc` 读之前已退出 | 主行仍打（用事件字段 filename），上下文行标 `(unavailable)` |
| environ 被覆盖 | 程序 exec 后可主动改 environ 内存 | 事件到达立即读，最大限度贴近 exec 那一刻的状态 |
| cwd 之后会变 | `chdir` 会改 `/proc/<pid>/cwd` 软链接 | 同上，只读 exec 那一刻的值 |
| filename 与真实二进制 | shebang / symlink / memfd / deleted 会造成不一致 | `--exe` 显式对比；不一致时追加 filename 行 |
| 命名空间视图 | procfs 视图受 mnt/pid namespace 影响 | 在同一 ns 里运行 perf-prof；跨 ns 观测需用 `--pid` 或宿主命名空间 |
| 高频 exec | 高峰期可能刷屏 | 用 `--name` / `--path` 或 kernel-side filter 收窄 |
| Python 回调开销 | 每事件几十 μs（procfs 读多则线性放大） | 关闭不需要的上下文开关；把过滤下推到内核 |

## 7. 扩展点

以下方向留出了口子，但当前实现里没有：

1. **`--ancestors`（祖先链）**：把父→父→...→自身按 `→` 折叠成一行；实现要
   点是递归 `/proc/<pid>/status` 的 `PPid`，遇到已退出祖先显示占位。上一
   轮讨论过折叠 vs 缩进两种呈现，倾向折叠以不吞屏。
2. **`--cgroup` / `--ns`**：容器场景下把 `/proc/<pid>/cgroup` 与 `ns/*`
   inode 打出来，直接看到进程属于哪个容器 / pid ns。
3. **`--exit`**：额外挂 `sched:sched_process_exit`，按 PID 配对算存活时间
   —— 用来定位"频繁 fork 的短命进程"。会把工具从"单事件"变成"配对事件"，
   复杂度显著上升，因此保持可选。
4. **JSON 输出**：把 print 抽象成 `render_text` / `render_json`，便于喂到
   ELK / Prometheus / SIEM。
5. **cgroup 过滤**：`-G <cgroup>` 让 perf-prof 只 attach 到某个 cgroup，
   容器场景更精准。这是 perf-prof 已有能力，不需要脚本侧改动，仅需在文档
   里补充示例。
6. **fd 全景 `--fd`**：不只 0/1/2，而是把 `/proc/<pid>/fd/*` 全部 readlink
   打印；开销大，仅在需要时开启。

## 8. 文件清单

| 文件 | 大小量级 | 说明 |
|---|---|---|
| `exec_trace.py` | ~360 行 | 单文件工具（含 shebang、CLI、事件回调、procfs 读取、渲染） |
| `exec_trace_design.md` | 本文 | 设计文档 |

两个文件同目录、独立自洽。按项目 `tools/` 目录规范，属于同一次提交
（tools 每个独立工具的源码、脚本、文档作为一个整体提交）。
