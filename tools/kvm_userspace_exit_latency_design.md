# kvm_userspace_exit_latency 设计文档

## 1. 背景与动机

KVM 虚拟机在运行期间会因为各种原因触发 VM-Exit：多数在内核态由 KVM
就地处理后直接 VM-Entry 回 guest；少数（如 KVM_EXIT_IO / KVM_EXIT_MMIO
/ KVM_EXIT_HLT 等）会**继续升级到用户态**，返回给 QEMU 处理，QEMU 处理
完再通过 `ioctl(KVM_RUN)` 重入 guest。这段"QEMU 处理时间"是虚拟机 I/O
路径上的一大延迟来源，需要能定量测量：

- **每种退出原因的耗时分布**（IO / MMIO / HLT / INTR / ...）
- 是否有**长尾**（P99 / MAX 明显偏离 P50）
- 是否**集中在某个 vcpu 线程**（NUMA / 亲和性问题）

现有工具：
- `kvm-exit` 分析器测的是 **VM-Exit → VM-Entry** 全路径，无法区分"在
  KVM 内核态处理"和"升级到 QEMU 处理"两段
- `bpf:kvm_exit` 同样是全路径 + BPF 依赖

本工具补上"**只测量升级到 QEMU 的那段耗时**"的能力，用 perf-prof python
不依赖 BPF、也不侵入 QEMU 源码。

## 2. 目标与非目标

### 2.1 目标

1. 精确测量 `kvm:kvm_userspace_exit → 同 vcpu 线程下一次 ioctl(KVM_RUN)`
   的耗时。
2. 按 **exit reason** 聚合，输出 COUNT / TOTAL / MIN / P50 / P95 / P99 / MAX。
3. 支持 **`--per-tid`** 拆到每个 vcpu 线程，观察 vcpu 之间是否有系统
   性差异。
4. 支持 **周期性输出**（`-i ms`）和 **一次性汇总**（无 `-i`），两种模式共
   享同一份统计状态。
5. 支持 **`--than <dur>`** 阈值：超过阈值的每一对事件都直接
   `event.print()` 输出起点/终点原始事件，便于追根因。
6. `--than` 支持 `20us / 5ms / 1s / 500ns` 单位后缀。

### 2.2 非目标

- 不测 KVM 内部（VM-Exit → 内核处理完 → VM-Entry）的耗时——那是
  `kvm-exit` 分析器的领地。
- 不做 QEMU 内部函数级火焰图（需 uprobe，见 `func_latency`）。
- 不做近似分位数（T-Digest 等）。userspace exit 单个 vcpu 每秒通常在
  1k 量级以内，精确排序算法足够。
- 不支持 Windows / 非 KVM 虚拟化后端。

## 3. 系统架构

```
┌────────────┐   kvm:kvm_userspace_exit    ┌───────────────────────┐
│  KVM  (内核)│ ────────────────────────── >│                       │
│            │   (reason, errno)           │   perf-prof (C)       │
│            │                             │   ringbuffer I/O      │
│  QEMU vcpu │   syscalls:sys_enter_ioctl  │   --order 排序        │
│  线程      │   (cmd == 0xAE80 = KVM_RUN) │                       │
│            │ ────────────────────────── >│                       │
└────────────┘                             └────────────┬──────────┘
                                                        │ PerfEvent obj
                                                        ▼
                        ┌──────────────────────────────────────────┐
                        │  kvm_userspace_exit_latency.py           │
                        │  - pending[tid] = (t, code, exit_event)  │
                        │  - records[key]  = [latency_ns, ...]     │
                        │  - percentile & table renderer           │
                        └──────────────────────────────────────────┘
```

只有一个组件：一个自带 shebang 的 Python 脚本，可以直接
`./kvm_userspace_exit_latency.py -p <qemu_pid>` 跑起来。

| 组件 | 语言 | 职责 |
|---|---|---|
| `perf-prof python` | C | 事件采集、ringbuffer、`--order` 全局时序、tracepoint 字段解析、调用 Python 回调 |
| `kvm_userspace_exit_latency.py` | Python | 事件配对、按 reason 聚合、分位数计算、表格输出 |

## 4. 组件详细设计

### 4.1 事件选择

**起点**：`kvm:kvm_userspace_exit`
- KVM 决定把当前 VM-Exit 交给用户态处理时发射
- 关键字段：`reason`（IO / MMIO / HLT / ...）、`errno`（负值表示 restart /
  error，非负表示正常 reason）
- `common_pid` 是当前 vcpu 线程 tid

**终点**：`syscalls:sys_enter_ioctl/cmd==0xAE80/`
- QEMU 处理完退出后调用 `ioctl(KVM_RUN)` 重入 guest
- `KVM_RUN = _IO(KVMIO=0xAE, 0x80) = 0xAE80`，用内核态过滤器
  `cmd==0xAE80` 直接剔除掉其它无关 ioctl（QEMU 每次退出都会做非常多
  ioctl，如 KVM_INTERRUPT / KVM_GET_REGS 等，不过滤会白白吞掉 ringbuffer）

**为什么终点不用 `kvm:kvm_entry`**：`kvm_entry` 在 KVM 每次 VM-Entry 都
会发射，包括那些**没有升级到用户态**的内核态自处理退出的重入，噪声太
大且难以区分。而"下一次 KVM_RUN"是干净的、只在 QEMU 主动重入时发射，
和 `kvm:kvm_userspace_exit` 一一对应。

### 4.2 事件配对模型

**Key = `common_pid`（vcpu 线程 tid）**：
- vcpu 线程可能在两个事件之间被调度到其它 CPU，因此不能按 CPU 配对
- 同一个 vcpu 线程内 exit → KVM_RUN 是严格串行的（QEMU 处理完才会再
  KVM_RUN），不会重叠

**必须 `--order`**：起点是 tracepoint 事件（挂在 kvm 模块），终点是
syscall tracepoint（挂在系统调用路径），它们可能落在不同 ringbuffer；
`--order` 保证 Python 回调看到的 `event._time` 是全局时间序，否则可能
出现 "return 事件早于 entry 事件被处理"，进而 latency < 0 或错配。

**状态机**：

```
pending[tid] = (exit_time_ns, code, exit_event_or_None)

kvm:kvm_userspace_exit  → pending[tid] = (now, code, self if --than>0 else None)
syscalls:sys_enter_ioctl → if tid in pending:
                              latency = now - exit_time
                              records[key].append(latency)
                              if --than and latency > threshold:
                                  print exit_event, this event
                           else:
                              unmatched_run += 1  # 首次 KVM_RUN
```

### 4.3 单值 code 表示

exit 事件里有两个字段：`reason`（u32 ≥ 0）和 `errno`（int，通常负值表
示 restart / error）。两者互斥使用：内核只在 `errno < 0` 时把 errno 作
为"退出原因"，否则用 reason。

因此把两者**合并成一个有符号 int**：

```python
code = errno if errno < 0 else reason
```

好处：
- 事件回调路径少一个字段访问
- `pending` / `records` 的 bucket key 从二元组降为标量
- `reason_name(code)` 单参数：`code < 0` → `"error(N)"` / `"restart"`；
  `code ≥ 0` → 查表得 `"IO"` / `"MMIO"` / ...

### 4.4 名称转换延迟到输出时

`reason_name()` 涉及字典查表和字符串格式化，事件回调路径**每次退出都
被打**，一旦每秒退出数上万就会明显吃 CPU。

因此：
- **热路径**只处理裸整数 code
- 只有在 `__interval__` / `__exit__` 打印表格时、以及 `--than` 命中打
  印明细时，才调用 `reason_name()`

### 4.5 聚合与分位数

**数据结构**：

```python
records: dict[key, list[int]]         # key -> [latency_ns, ...]
    # key = code:int          if not --per-tid
    # key = (tid, code):tuple if --per-tid
```

**为什么保留原始样本列表**（而不是滚动更新 count/sum/min/max）：需要
精确的 P50 / P95 / P99，只能保留全部样本 sort + 索引。userspace exit
每 vcpu 每秒 < 1k 量级，一个 1s 窗口的样本量在 10k 内，排序开销可忽略。

**分位数算法**（nearest-rank）：

```python
idx = int((p / 100.0) * (n - 1))   # p ∈ [0, 100]
return sorted_ns[idx]
```

不做插值，语义清晰、可复现。

### 4.6 输出格式

```
2026-07-21 11:36:35
REASON              COUNT    TOTAL(us)    MIN(us)    P50(us)    P95(us)    P99(us)    MAX(us)
----------------------------------------------------------------------------------------------
IO                    120      3542.11      12.20      21.03      88.40     125.60     318.90
MMIO                   45      1120.55      18.50      22.10      67.80      92.30     140.20
INTR                    8       410.20      45.00      50.10      60.00      60.00      60.00
```

`--per-tid` 时表头前置 `THREAD` 列。

**单位**：所有延迟列固定 us、2 位小数，单位放在列头（`TOTAL(us)` 等），
避免每个数值都带尾缀影响对齐。

**排序**：可选 `total / count / max / p99`，默认 `total`（重心在"哪
类退出总体最耗时"）。

### 4.7 窗口生命周期

- `-i <ms>` 指定时：每 ms 调用 `__interval__` → 打印当前 `records` →
  `records = defaultdict(list)` 清空
- 未指定 `-i` 时：`__interval__` 不会触发，`__exit__` 里 dump 一次全量
  记录（`if any(records.values())`）

**关键：`pending` 不清**。跨窗口的 exit → KVM_RUN 会记账到"完成窗口"，
和 `func_latency` 的策略一致。

**事件丢失**：`__lost__` 回调里清空 `pending`——丢事件会破坏配对，宁
可漏几个 pair 也不要让 pending 里的过期条目错配到后续 ioctl。

### 4.8 `--than` 明细输出

当延迟超过阈值时，除了记入统计外，还调用 `exit_event.print()` /
`event.print()` 打印两条原始事件（timestamp / comm / cpu / 全字段），
方便和其它日志、监控数据对齐时间轴。

为了 `event.print()` 能拿到 exit 事件，`pending` 里存的第三项在
`--than > 0` 时才保留 event 对象引用；否则存 `None`，避免在不需要明细
的场景下白白拖着事件对象不释放。

### 4.9 单位后缀解析

```
20us    → 20_000        ns
5ms     → 5_000_000     ns
1s      → 1_000_000_000 ns
500ns   → 500           ns
500     → 500_000       ns   (裸数字兼容旧写法, 按 us 解释)
```

解析后 `args.than` 是 ns 单位整数，回调里直接 `latency_ns > args.than`
比较，热路径省去除法。

## 5. 接口 (API)

### 5.1 命令行

```bash
./kvm_userspace_exit_latency.py [-p PID] [-t TID] [-C CPUS] [-i MS] [-m PAGES] \
                                [--than DUR] [--top N] [--sort FIELD] [--per-tid]
```

**脚本自有参数**：

| 选项 | 语义 |
|---|---|
| `--than <dur>`   | 超过该阈值的每一对事件打印起点/终点原始事件；支持 `us/ms/s/ns` 单位后缀 |
| `--top <n>`      | 只显示 top N 行（按 `--sort` 字段），默认 20 |
| `--sort <field>` | 排序字段：`total` / `count` / `max` / `p99`，默认 `total` |
| `--per-tid`      | 按 `(vcpu-tid, reason)` 分组，而非仅按 `reason` |

**常用透传参数**（perf-prof 侧，写在 shebang 里或命令行传入）：

| 选项 | 语义 |
|---|---|
| `-p PID`      | 只观测指定进程（QEMU 主进程；会自动包含所有 vcpu 线程） |
| `-t TID`      | 只观测指定线程（某几个 vcpu） |
| `-C CPUS`     | 只观测指定 CPU |
| `-i MS`       | 周期输出间隔（默认无：只在退出时打印一次） |
| `-m PAGES`    | perf ringbuffer 大小；默认 shebang 里 `-m 16`（64KB/实例），丢事件时翻倍加大 |
| `-o FILE`     | stdout/stderr 重定向 |
| `--watermark` | 唤醒水位，一般无需调整 |

### 5.2 使用示例

```bash
# 一次性统计整个 qemu 进程，Ctrl-C 打印结果
./kvm_userspace_exit_latency.py -p $(pgrep -f 'qemu.*vm-name' | head -1)

# 每秒统计一次
./kvm_userspace_exit_latency.py -p 12345 -i 1000

# 只关心 >500us 的长尾，直接 dump 每个长尾对的原始事件
./kvm_userspace_exit_latency.py -p 12345 --than 500us -i 1000

# 5ms 阈值 + 按 max 排序，看最大延迟发生在哪个 reason
./kvm_userspace_exit_latency.py -p 12345 --than 5ms --sort max

# 拆到每个 vcpu 线程，找出异常 vcpu
./kvm_userspace_exit_latency.py -p 12345 --per-tid --sort p99 -i 5000

# 结合 CPU 定位：只看 CPU 0-3 上的退出
./kvm_userspace_exit_latency.py -p 12345 -C 0-3 -i 1000
```

## 6. 边界与限制

### 6.1 已知限制

| 项 | 说明 | 缓解方案 |
|---|---|---|
| 事件丢失 | 高频退出时 ringbuffer 可能溢出 | 增大 `-m`；`-o` 输出到文件；`__lost__` 会清 pending 保证后续正确 |
| 首次 KVM_RUN | vcpu 线程创建后的第一次 KVM_RUN 没有对应 exit | 计入 `unmatched_run`，不污染统计 |
| pending 残留 | 若 exit 后 vcpu 长期不再 KVM_RUN（vcpu 挂起 / 停止），条目会一直挂在 pending | 影响极小；下次进程退出即释放 |
| 跨窗口调用 | exit 在窗口 A、KVM_RUN 在窗口 B → 延迟归入 B | 已在设计中接受 |
| 不区分 QEMU 子逻辑 | 只测总耗时，看不到 QEMU 内部哪里慢 | 需进一步用 `func_latency` 或 uprobe 打点 QEMU 关键函数 |
| 仅 KVM | Xen / VMware / Hyper-V 不支持 | 非目标 |

### 6.2 性能开销

- `kvm:kvm_userspace_exit` 触发频率 = QEMU 每次用户态处理的退出次数，
  典型 VM 每 vcpu 每秒 10~1000 次；`syscalls:sys_enter_ioctl` 因内核
  过滤器 `cmd==0xAE80` 已经与之 1:1 匹配，不会额外多
- 每个事件的 Python 回调是 O(1)（一次 dict 操作 + 一次列表 append）
- 单个 32 vcpu 的 VM 常规负载下，脚本本身 CPU 占用 < 1%

## 7. 扩展点

以下方向不在当前实现中，但设计上留出了口子：

1. **多虚机对比**：目前 `-p` 只支持单个 QEMU 进程。改成同时 attach 多
   个 pid + 输出中带 `pid` 列即可。
2. **原因过滤**：只关心 IO / MMIO 时，可以增加 `--reason IO,MMIO`
   过滤器（用户态 dict 判断，无需内核过滤器，因为 reason 字段无法通
   过 tracepoint filter 过滤到符号名）。
3. **调用栈**：给 `kvm:kvm_userspace_exit` 打开 `stack` 属性可以看到内
   核态触发 exit 的调用链，帮助定位是哪类硬件访问（vmx / svm / pio / mmio）
   导致升级到用户态。
4. **JSON 输出**：当前 `_print_table` 只做文本渲染，抽出
   `render_text` / `render_json` 后可以接监控系统。
5. **和 QEMU 内部计时联动**：`--than` 命中时除了 dump 事件，还可以触发
   一次 `SIGUSR1` 让 QEMU 自己 dump 内部 trace。
6. **eBPF 版**：pending / 配对逻辑完全可以搬到 eBPF prog，用户态只收
   聚合结果。适合 5.x+ 内核 + 事件密度更高的场景。

## 8. 文件清单

| 文件 | 大小量级 | 说明 |
|---|---|---|
| `kvm_userspace_exit_latency.py` | ~270 行 | perf-prof python 回调 + argparse 前端 |
| `kvm_userspace_exit_latency_design.md` | 本文 | 设计文档 |

两个文件同目录、独立自洽，可整体复制。