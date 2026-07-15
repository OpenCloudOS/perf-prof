# func_trace 设计文档

## 1. 背景与动机

在排查用户态或内核函数的调用关系与耗时特性时，往往需要回答两类问题：

- **调用关系**：某个 root 函数下，实际调用了哪些子函数？调用了几次？
- **耗时分布**：每个函数各自耗时多少？P50 / P95 / P99 / MAX 是多少？
  同一子函数在不同 root 下的耗时是否有系统性差异？

传统做法（改源码打点、gprof、strace 等）要么侵入性大、要么粒度粗、要么
只覆盖用户态或系统调用层。perf-prof 的 uprobe/kprobe + Python 脚本处理
能力提供了另一条路径：

- **零源码修改**：uprobe/kprobe 直接挂在二进制符号或内核符号上，不需要
  重编译目标程序。
- **按需开关**：只在需要观测时启动，退出即清理。
- **调用路径可辨识**：同名函数在不同调用链下可以独立聚合。

本工具就是围绕这条路径构建的一层用户友好的封装。

## 2. 目标与非目标

### 2.1 目标

1. 用户态、内核态函数混合追踪，同一棵调用树呈现，内核函数明确标记。
2. **按完整调用路径**（root → ... → leaf）聚合，不同路径的同名函数独立统计。
3. 输出：`N / TOTAL / MIN / AVG / P50 / P95 / P99 / MAX`，全部精确值。
4. 周期性输出（`-i` 间隔），每个窗口独立统计，历史数据不累积。
5. 追踪函数集合可通过命令行任意增删，脚本本身不需要感知具体函数名。
6. 单一 shell 入口，屏蔽 perf-prof 事件字符串组装细节。

### 2.2 非目标

- 不追求百万级 QPS 的极高频函数追踪。
- 不做火焰图、跨函数关联时序（有需要请用 profile / multi-trace）。
- 不做近似分位数（T-Digest 等）—— 常规场景样本量不大，精确算法更简单可信。
- 不做 GUI；输出纯文本，方便直接贴到 CR、bug 单里。

## 3. 系统架构

```
┌─────────────────┐   uprobe/kprobe events   ┌────────────────────┐
│  target binary  │ ─────────────────────────>│   perf-prof (C)    │
│  + Linux kernel │                           │  ringbuffer I/O    │
└─────────────────┘                           └────────┬───────────┘
                                                       │ PerfEvent obj
                                                       ▼
                              ┌────────────────────────────────────┐
                              │  func_trace.py  (Python callback)  │
                              │  - per-tid call stack              │
                              │  - path-keyed sample list          │
                              │  - percentile & tree renderer      │
                              └────────────────────────────────────┘
                                                       ▲
                              ┌────────────────────────┴───────────┐
                              │  func_trace.sh                     │
                              │  组装 -e 字符串, 透传 perf-prof 选项 │
                              └────────────────────────────────────┘
```

三个组件：

| 组件 | 语言 | 职责 |
|---|---|---|
| `func_trace.sh` | bash | 命令行接口；把 `-b/-u/-k` 转成 perf-prof 的 `-e` 事件串；其它参数原样透传 |
| `perf-prof python` | C | 事件采集、ringbuffer 管理、tracepoint 字段解析，调用 Python 回调 |
| `func_trace.py` | Python | 事件语义处理、状态维护、聚合、输出 |

## 4. 组件详细设计

### 4.1 func_trace.sh —— 命令行封装

**参数分成两类**：

- **本脚本独占**：`-b BINARY`、`-u FUNC`（可重复）、`-k FUNC`（可重复）、`-n`、`-h`。
- **透传给 perf-prof**：其余全部（`-p`、`-C`、`-i`、`-m`、`-o`、`--order`、`-v` …）。

**解析实现**：手写 `while` 循环 + `case`（不用 `getopts`，因为 `getopts`
会在遇到未声明选项时报错停机）。支持 `-uFOO`（贴一起）和 `-u FOO`（分开）
两种写法。遇到 `--` 后剩余参数原样收集并 break。

**事件串组装**：

```
uprobe:<binary>:<func1>,uretprobe:<binary>:<func1>,
uprobe:<binary>:<func2>,uretprobe:<binary>:<func2>,
kprobe:<kfunc1>,kretprobe:<kfunc1>,
...
```

每个 `-u FUNC` 展开成 uprobe + uretprobe 一对；每个 `-k FUNC` 展开成
kprobe + kretprobe 一对。用逗号连接后作为单个 `-e` 参数传给 perf-prof。

**默认 Python 模块**：若透传参数里没有 `--`，脚本自动追加 `-- <script_dir>/func_trace.py`；
若用户已经写了 `--`，则完全按用户的走，脚本不再插手。

**dry-run**：`-n` 打印最终命令（`printf %q` 转义），不 exec，便于排错。

### 4.2 func_trace.py —— 事件处理与聚合

#### 4.2.1 事件解析

`__sample__` 是 perf-prof python 的默认事件回调，`event._event` 形如
`"uprobe:foo"` / `"kretprobe:bar"`。用 `str.partition(':')` 切成 `kind`
和 `func`，四种 kind 归为两类语义：

| kind | 语义 | 是否标记内核 |
|---|---|---|
| `uprobe` / `kprobe` | 进入函数 | `kprobe` → 记 kernel |
| `uretprobe` / `kretprobe` | 函数返回 | `kretprobe` → 记 kernel |

不采用 per-event handler（`uprobe__foo`）是有意的：脚本无需与追踪函数集合
耦合，跟着 perf-prof 的 `-e` 走即可。

#### 4.2.2 每线程调用栈模型

只有**同一线程**上的 entry 和 return 才能匹配延迟，因此以 `event._tid`
为 key 维护栈：

```
call_stacks[tid] = [ (func_name, full_path, start_ts_ns), ... ]
```

- **入栈**（`_entry`）：`parent_path = stack[-1][1] if stack else ()`，
  新帧的 `full_path = parent_path + (func,)`。栈空时表明是本线程的一个
  根调用。
- **出栈**（`_return`）：从栈顶向下**找最近一个同名帧**，pop 它及其上方
  所有帧（`del stack[idx:]`），把耗时 append 到 `path_samples[full_path]`。
  找不到则计入 `unmatched_returns`。

**为什么 pop 时删除上方所有帧**：假设进入 A → B → C，但因为 `-m` 太小或
探针漏采导致 C 的 uretprobe 丢了，接着 B 返回。用"最近同名"策略，B 返回
时会把 C 和 B 一起清出栈，避免栈永久错位污染后续所有帧。代价是 C 那次
调用不计入统计，可通过 `pending-frames` 观察到异常。

#### 4.2.3 路径聚合（Path-keyed Aggregation）

**核心决策**：以完整 path 元组（如 `('root_func', 'child_func')`）作为聚合
key，而不是单纯函数名。

**动机**：同一个子函数在不同调用链下的实现路径、参数、上下文可能不同，
耗时特性也不同，必须独立统计才能得到有意义的对比。

**数据结构**：

```python
path_samples: dict[tuple[str,...], list[int]]   # path → durations (ns)
kernel_func:  dict[str, bool]                   # 函数名 → 是否内核态
```

样本列表原始保存，`_dump` 时统一 `sorted + sum` 一次算出所有聚合值。

#### 4.2.4 精确分位数

采用 **nearest-rank** 定义：

```
rank = ceil(pct / 100 * n),  clamp to [1, n]
percentile = sorted_samples[rank - 1]
```

- 精确、无插值，与 P4/HDR 之类工具的默认行为一致。
- 排序 O(n log n)、每次 dump 只做一次；n 很小时（如 5 秒内 3 个样本）
  依然给出合理结果（P50 = 中间那个）。

**为什么不用近似算法**：常规使用场景样本量不大（每秒 O(10)~O(1000) 级），
排序开销可以忽略；近似算法带来的实现复杂度和"数字对不上"的解释成本更高。

#### 4.2.5 窗口生命周期

`_dump()` 在两个时机被调用：
- `__interval__()` —— 每 `-i` 毫秒；
- `__exit__()` —— 程序退出前（含 Ctrl-C）。

`_dump` 结束时执行：

```python
path_samples.clear()
unmatched_returns = 0
```

**关键：`call_stacks` 不清**。假设一个调用横跨窗口边界（uprobe 在窗口 A、
uretprobe 在窗口 B），清 `call_stacks` 会丢一整棵调用树；而不清的策略下，
它会正确记账到窗口 B。代价是"跨窗口调用的耗时归属到完成窗口"—— 对本场景
足够合理。

#### 4.2.6 输出格式

树形，用 `|- / |  |-` 缩进呈现调用嵌套；内核函数前缀 `[K]`。

```
function                                     N  TOTAL(us)  MIN(us)  AVG(us)  P50(us)  P95(us)  P99(us)  MAX(us)
---------------------------------------------------------------------------------------------------------------
root_func_A                                 10    5000.00   200.00   500.00   480.00   890.00   990.00  1000.00
  |- child_func_1                            5    2100.00   350.00   420.00   410.00   500.00   500.00   500.00
  |  |- [K] kernel_helper                   20    1600.00    50.00    80.00    75.00   150.00   180.00   200.00
  |- child_func_2                            5    2900.00   500.00   580.00   570.00   700.00   700.00   700.00
```

**排序**：孩子按**首次出现顺序**打印（`defaultdict` + Python 3.7+ 有序 dict），
避免每次运行输出顺序抖动。

**异常提示**：`unmatched_returns` 和 `pending-frames`（未匹配的 uretprobe /
仍在栈上的 uprobe 帧）在有值时单独打印，用于观测事件丢失和跨窗口调用。

## 5. 接口 (API)

### 5.1 命令行

```bash
./func_trace.sh -b BINARY [-u FUNC]... [-k FUNC]... [perf-prof options]
```

**本脚本参数**：

| 选项 | 语义 |
|---|---|
| `-b BINARY` | 目标二进制路径（用 `-u` 时必填） |
| `-u FUNC`   | 二进制内的用户态函数（可重复） |
| `-k FUNC`   | 内核函数（可重复） |
| `-n`        | dry-run，只打印最终命令 |
| `-h`        | 帮助 |

**常用透传参数**（perf-prof 侧）：

| 选项 | 语义 |
|---|---|
| `-p PID`      | 只观测指定进程 |
| `-C CPUS`     | 只观测指定 CPU |
| `-i MS`       | 周期输出间隔（默认 5000ms） |
| `-m PAGES`    | perf ringbuffer 大小（页数），事件丢失时增大 |
| `-o FILE`     | stdout/stderr 重定向 |

### 5.2 使用示例

```bash
# 基本用法：追踪二进制内的一组用户态函数
./func_trace.sh \
  -b /path/to/target_binary \
  -u root_func_A \
  -u root_func_B \
  -u child_func_1 \
  -u child_func_2 \
  -p $(pgrep -x target_binary | head -1) \
  -i 5000

# 混入内核函数（会以 [K] 标记）
./func_trace.sh -b /path/to/target_binary -u root_func_A -k some_kernel_func -i 3000

# 只看事件串，不真跑
./func_trace.sh -b /path/to/target_binary -u root_func_A -n
```

## 6. 边界与限制

### 6.1 已知限制

| 项 | 说明 | 缓解方案 |
|---|---|---|
| 事件丢失 | 高频事件下 ringbuffer 可能溢出 | 增大 `-m`；用 `-o` 输出到文件避免终端瓶颈 |
| 跨窗口调用 | 耗时归属到"完成"窗口 | 已在设计中接受；`pending-frames` 可观测 |
| uretprobe 漏采 | 会污染栈顶几层帧 | 就近同名匹配 + `del stack[idx:]`，控制爆炸半径 |
| 尾调用优化 | 编译器可能把 `foo() {return bar();}` 优化成 jmp | 编译时使用 `-O0` 或 `-fno-optimize-sibling-calls` |
| inline 函数 | uprobe 挂不到 inline 展开点 | 必要时给关键函数加 `__attribute__((noinline))` |
| 多线程共享 uprobe | 所有进程都会被 trace | 用 `-p PID` 限定 |

### 6.2 性能开销

- uprobe/uretprobe 每次触发引入一次陷入 + 一次事件写入，约 1~10μs 量级
  取决于内核版本和是否有 optimized kprobe。
- 目标函数**每秒调用 < 1000 次**时开销可忽略；> 10k/s 需谨慎。
- Python 回调本身是每事件 O(栈深度) 的常数级操作；瓶颈几乎总在事件传输
  层，不在回调。

## 7. 扩展点

以下方向不在当前实现中，但设计上留出了口子：

1. **按线程分组输出**（`--perins` 风格）：目前 `path_samples` 是全局
   聚合。改成 `dict[tid, path_samples]` 即可分线程展示，用于排查线程间
   争用。
2. **参数记录**：uprobe 事件可以带参数（通过 `p:kprobe_name` 语法配置
   `%di / %si` 等寄存器），未来在 `_entry` 里读取并把 path 加上参数
   区分，可以做到"按某个业务 ID 分开统计"。
3. **CDF / 直方图**：`path_samples` 已经保留了原始样本，加一个
   `--histogram` 参数在 `_dump` 里输出即可。
4. **JSON 输出**：`_dump` 目前只做文本渲染，抽象成 `render_text` /
   `render_json` 可以喂到监控系统。
5. **多二进制**：当前 `-b` 只允许一个。改成 `-u BINARY:FUNC` 或
   `-b BINARY -u FUNC` 按最近 `-b` 匹配，即可支持跨二进制追踪。

## 8. 文件清单

| 文件 | 大小量级 | 说明 |
|---|---|---|
| `func_trace.sh` | ~100 行 | shell 前端，命令行解析 + 透传 |
| `func_trace.py` | ~150 行 | perf-prof python 回调，全部聚合逻辑 |
| `func_trace_design.md` | 本文 | 设计文档 |

三个文件同目录、独立自洽，可整体复制到其它项目。
