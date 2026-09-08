# BPF 事件源的内核态过滤

本文说明 perf-prof 如何为 **BPF 程序生成的事件** 提供内核态过滤器：用户给一个 C 表达式，
它被编译成 eBPF 指令、在加载前注入到 BPF 程序内部，事件在内核态就被裁决，不满足条件的
根本不会送到用户态。

一句话概括机制：**表达式就是 `expr_filter()` 这个函数的函数体**。

```c
--filter 'exit_reason == 12 && latency > 1000000'

/* 等价于让 BPF 程序里的 expr_filter() 变成： */
int expr_filter(struct kvm_vcpu_event *event)
{
    return event->exit_reason == 12 && event->latency > 1000000;
}
```

BPF 程序里预留了一个 `expr_filter()` 占位符（默认恒返回 1，即全部放行），用户态把表达式编译
成 eBPF 指令后，在 BPF 程序加载**之前**把占位符的指令替换掉。表达式里能直接写字段名，是因为
`event->字段` 在 eBPF 里就是一条 `r1 + 偏移` 的加载指令。

面向的读者是要**给新的 BPF 程序加过滤能力**、或要**改动表达式后端**的人。表达式语法本身见
[expr.md](expr.md)。

> **本文的示例全部以 `src/bpf-skel/kvm_exit.bpf.c`（`bpf:kvm_exit` 分析器）为例**，它是目前
> 唯一接入这套机制的 BPF 程序，事件结构体是 `src/bpf-skel/kvm_exit.h` 里的
> `struct kvm_vcpu_event`。文中出现的字段名（`exit_reason`、`latency`、`sched_latency` 等）
> 和字段偏移都来自它；换成别的 BPF 程序时，字段由该程序自己的事件结构体决定——机制本身
> 与事件结构体无关，布局是运行时从 BTF 读出来的（见 5.3）。
>
> 第七节的 VM 指令与 eBPF 指令清单，均为 `perf-prof bpf:kvm_exit --filter '...' -v` 的实际
> 输出，非手工构造。

## 一、为什么需要这一层

perf-prof 的事件源都有内核态过滤手段，唯独 BPF 程序原来没有：

| 事件源 | 内核态过滤器 |
|--------|-------------|
| tracepoint | ftrace filter（`PERF_EVENT_IOC_SET_FILTER`） |
| kprobe / uprobe | ftrace filter |
| PMU | `perf_event_attr` 位（`--exclude-user/kernel/guest/host`） |
| **BPF 程序** | **原来没有** |

BPF 程序把事件 `bpf_perf_event_output()` 出来，想缩小范围只能改 `.bpf.c` 里硬编码的条件再
重新编译。这一层就是补上这个缺口：把 BPF 程序当成普通事件源，给它配一个过滤器。

### 为什么不能复用 tracepoint 的思路

值得先说清楚，因为这决定了实现形态。给 tracepoint 挂 BPF 过滤器（`PERF_EVENT_IOC_SET_BPF`）
在这里行不通，有三个硬障碍：

1. **ctx 前 8 字节被内核覆盖**。`perf_trace_run_bpf_submit()` 执行
   `*(struct pt_regs **)raw_data = regs`，而 `tp_prog_is_valid_access()` 又要求
   `off >= sizeof(void *)`。`common_type`/`common_pid` 这些字段直接读不到。
2. **过滤器是 per-tracepoint 共享的**。程序挂进 `tp_event->prog_array`，
   `bpf_prog_run_array()` 对所有程序的返回值取与，任一程序返回 0 就丢事件——会影响该
   tracepoint 上**所有**消费者，包括其他 perf-prof 实例和无关的 bcc/bpftrace。
3. **只读**。`tp_prog_is_valid_access()` 拒绝 `BPF_WRITE`。

而本文的方案把过滤逻辑放在 BPF 程序**内部**，这三条全部不成立：事件是程序自己的
`.bss` 或 map value（不是 tracepoint ctx，偏移 0 也能访问、可读写），`perf_output()`
调不调用完全自主，不影响任何其他消费者。

## 二、整体流程

```
                          用户态                              │        内核态
                                                              │
  --filter 'exit_reason == 12'                                │
            │                                                 │
            ▼                                                 │
    ┌───────────────────┐   BTF: FUNC → FUNC_PROTO            │
    │ bpf_expr_filter.c │◄──  → PTR → STRUCT → members        │
    │  读事件结构体布局  │      (name/offset/size/signed)       │
    └────────┬──────────┘                                     │
             │ struct global_var_declare[]                     │
             ▼                                                 │
    ┌───────────────────┐                                     │
    │  expr_compile()   │  词法/语法/类型检查（与用户态 VM 共用）│
    └────────┬──────────┘                                     │
             │ struct expr_prog (VM 指令流)                    │
             ▼                                                 │
    ┌───────────────────┐                                     │
    │  expr_to_bpf()    │  VM 指令 → eBPF 指令                 │
    └────────┬──────────┘                                     │
             │ struct bpf_insn[]                              │
             ▼                                                 │
   bpf_program__set_insns()  替换 expr_filter() 占位符          │
             │                                                 │
             ▼                                                 │
      bpf_object__load() ─── libbpf 把 subprog 复制进各调用点 ──┼──► verifier
                                                              │       │
                                                              │       ▼
                                                              │  if (expr_filter(event))
                                                              │      perf_output(...)
```

关键在于**注入时机**。`expr_filter()` 是 `__noinline` 函数，即 `.text` 里的一个
subprogram。它在 `bpf_object__load()` 内部才被 `bpf_object__relocate_calls()` 复制进每个
调用者并修正 call 偏移。所以：

- 必须在 `bpf_object__open()` 之后、`bpf_object__load()` 之前替换；
- 因为复制发生在替换之后、且按 subprog **当时的**长度进行，**替换后的指令数可以和占位符不同**
  （不需要预留固定大小的补丁区）。

`bpf_program__set_insns()` 自身有 `if (prog->obj->loaded) return -EBUSY`，所以这个窗口是
被强制的。

## 三、涉及的文件

| 文件 | 职责 |
|------|------|
| `src/bpf-skel/expr_filter.bpf.h` | `DEFINE_EXPR_FILTER()` 宏、`EXPR_FILTER_FUNC` 名字。BPF 侧和用户态**共同包含**，保证名字单点定义 |
| `src/expr.c` | `expr_to_bpf()` 后端。`CONFIG_LIBBPF` 包裹。不依赖 libbpf/BTF |
| `src/bpf_expr_filter.c` | 全部 BPF 相关逻辑：找占位符、读 BTF 布局、安装指令 |
| `lib/bpf/libbpf.c` | `bpf_object__find_subprog_by_name()`（本地新增） |
| `include/linux/filter.h` | `BPF_LDX_MEM` 等指令构造宏。**逐字取自内核 `tools/include/linux/filter.h`**，升级时整体替换，不要在里面打补丁 |

职责边界是刻意的：`expr.c` 只认 `prog->data + offset` 这个抽象，对事件源、libbpf、BTF 零
依赖；所有 BPF/BTF 知识集中在 `bpf_expr_filter.c`。

## 四、给一个 BPF 程序加过滤能力

初版约定：**一个 BPF 程序只生成一个事件**，过滤函数恒为 `expr_filter()`。

### 4.1 BPF 侧

以 `kvm_exit.bpf.c` 为例：

```c
#include "expr_filter.bpf.h"

DEFINE_EXPR_FILTER(struct kvm_vcpu_event)     /* 声明占位符 */

SEC("raw_tp/kvm_entry")
int BPF_PROG(kvm_entry)
{
    ...
    if (expr_filter(data))                    /* 在输出前裁决 */
        perf_output(ctx, data, sizeof(*data));
}
```

`DEFINE_EXPR_FILTER()` 的参数就是该程序自己的事件结构体类型，换成别的程序时改这里即可。

### 4.2 用户态侧，在 open 与 load 之间

以 `src/bpf_kvm_exit.c` 为例：

```c
if (dev->env->filter &&
    bpf_expr_filter_apply(ctx->obj->obj, dev->env->filter, dev->env->verbose) < 0)
    goto failed;

if (kvm_exit_bpf__load(ctx->obj))
    goto failed;
```

### 4.3 事件结构体的要求

- 定长 struct，成员是标量（整型或枚举）或标量数组；
- 数组可以按下标访问（`comm[0]`、`tag[5]`），下标必须是 verifier 能定界的：常量或掩码过的
  值（`tag[i & 7]`）可以，裸变量下标会在加载时被拒（`invalid access to map value`）。常量
  下标**不做**范围检查，越界会读到相邻字段——和用户态 VM 行为一致；
- 位域、指针、嵌套聚合会被跳过（位域没有字节偏移可加载，指针需要 `bpf_probe_read()`，
  聚合没有表达式能用的值语义）。被跳过的字段在表达式里引用会报 `undefined variable`；
- 事件必须在**可写内存**里（`.bss` 或 map value），因为表达式允许赋值。

## 五、翻译成 eBPF 指令集

### 5.1 调用约定

生成的代码遵循 BPF subprogram 调用约定：

| 寄存器 | 用途 |
|--------|------|
| `r1` | 事件指针（入口参数），全程不被破坏。代码里叫 `BPF_EVENT` |
| `r0` | 累加器，对应 VM 的 `a` 寄存器；同时是返回值：非 0 保留事件，0 丢弃。代码里叫 `BPF_ACC`——不能叫 `BPF_A`，那是 `<uapi/linux/filter.h>` 里传统 BPF 的一个寻址模式 |
| `r2`–`r9` | 表达式栈槽 |

### 5.2 栈槽映射到寄存器

表达式 VM 是栈式的，但 `expr()` 只发射一种模式：

```
<子表达式>; PSH; <子表达式>; <二元运算>
```

因此**每一点的栈深度在编译期已知**，栈槽 N 可以直接映射到寄存器 `r(2+N)`，完全不碰内存。

> verifier 要求 subprogram 读 r6–r9 之前必须先写
> （`callee cannot access r0, r6 - r9 for reading and has to write into its own stack
> before reading from it`）。这天然满足：栈槽总是先 `PSH` 写入、才被读取。

栈深度超过 8 会报错（`expression too deeply nested`），实践中不会触及。

#### 5.2.1 破坏 r2–r9 为什么是安全的

占位符的函数体只有 `r0 = 1; exit`，只读 r1；替换进去的表达式却会写 r2–r9。调用点是
clang 在**编译 BPF 程序时**生成的，那时表达式还不存在——它会不会假设这些寄存器跨调用不变？
不会，但两半的理由不同。

**r2–r5：caller-saved，是 ABI 规定，与被调用者的函数体无关。** clang 从不把跨调用存活的
值留在这里，哪怕它能看穿被调用者只用了 r1。构造一个 8 个值跨调用存活的高压场景，编译出来是：

```
    0: r2 = *(u64 *)(r1 + 0x38)
    1: *(u64 *)(r10 - 0x8) = r2     ← r2 只作搬运的中转，值溢出到栈
    ...
    8: r8 = *(u64 *)(r1 + 0x18)     ← 要跨调用存活的，进 r6-r9
   11: r7 = *(u64 *)(r1 + 0x0)
   12: call 0x13                    ← expr_filter()，函数体只有 r0 = 1; exit
   13: r0 <<= 0x20                  ← 调用后只认 r0
```

跨调用存活的值全在 r6–r9 和栈上，r2 只用作同一条指令内的搬运中转。BPF 后端也没有启用
IPRA（跨过程寄存器分配，`-mllvm -enable-ipra`，正是"看穿被调用者实际用了哪些寄存器"的那个
优化）——开着它编译，代码一模一样。

verifier 还会再兜一层：`clear_caller_saved_regs()` 在每个 subprog 调用后把 r0–r5 标成
`NOT_INIT`，调用方若真敢读就是 `R2 !read_ok`。

**r6–r9：callee-saved，由 JIT 按替换后的指令流现场决定保存哪些。** 这一半才是真问题：栈槽
从 `r2` 起编号，深度超过 4 就用到 r6，而占位符里这些寄存器根本不出现。

```
--filter 'latency > (run_delay + (sched_latency + (exit_reason + (isa + (switches + (pid + tgid))))))'

    1: (bf) r2 = r0                 ← 栈槽 0，caller-saved 区
    3: (bf) r3 = r0
    5: (bf) r4 = r0
    7: (bf) r5 = r0                 ← 栈槽 3，到这里 caller-saved 用尽
    9: (bf) r6 = r0                 ← 栈槽 4 起进 callee-saved，占位符里不出现
   11: (bf) r7 = r0
   13: (bf) r8 = r0
```

关键在于**内核从头到尾没见过占位符**：替换发生在 `bpf_object__load()` 之前（见第二节的注入
窗口），verifier 和 JIT 拿到的只有最终指令。`jit_subprogs()` 把每个 subprog 做成独立的
`bpf_prog` 单独 JIT，x86 后端在 `do_jit()` 里现场扫描当前指令流：

```c
detect_reg_usage(insn, insn_cnt, callee_regs_used);   /* 逐条看 dst_reg/src_reg 是否命中 r6-r9 */
emit_prologue(...);
push_callee_regs(&prog, callee_regs_used);            /* 命中的才 push，epilogue 对称 pop */
```

arm64 的 `push_callee_regs()` / `pop_callee_regs()` 同理。解释器路径的机制不同但同样安全：
`DEFINE_BPF_PROG_RUN_ARGS` 给每一帧一个全新的 `u64 regs[MAX_BPF_EXT_REG]`，调用者的 r6–r9
在自己的数组里，物理上碰不到。

所以后端不需要为了保护调用者而限制可用寄存器。真正被编译期约定绑死的只有**入口**——参数必须
在 r1、返回值必须在 r0，这正是第六节里 `asm volatile` 必须消费 `event` 的原因。

### 5.3 核心：字段访问

这是整个翻译的关键，也是"表达式里的 `exit_reason` 怎么变成 `event->exit_reason`"的答案。

`expr_compile()` 给全局变量分配的地址是 `prog->data + offset`（`src/expr.c` 中
`id->value = (long)data + declare->offset`），所以 VM 指令 **`IMM addr; LI type`** 的语义
恰好就是 `*(type *)(event + offset)`——**它本来就是指针访问**，只是基址是用户态地址。

后端只需反解偏移，把这一对指令折叠成一条加载：

```c
offset = id->value - (long)prog->data;
EMIT(BPF_LDX_MEM(size, BPF_ACC, BPF_REG_1, offset));
```

赋值是完全对偶的：**`IMM addr; PSH; <值>; SI type`** → `BPF_STX_MEM`。

`LI`/`SI` 的操作数携带类型，size 由它换算：

| VM 类型 | 字节 | BPF size |
|---------|------|----------|
| `CHAR` | 1 | `BPF_B` |
| `SHORT` | 2 | `BPF_H` |
| `INT` | 4 | `BPF_W` |
| `LONG` / 指针 | 8 | `BPF_DW` |

#### 5.3.1 IMM 的三种归类

`IMM` 的操作数可能是字段地址、字符串字面量地址，或者一个普通立即数。三者只能靠**地址区间**
区分，因此区间两端都要收紧，否则足够大的常量会被误判成地址：

| 判据 | 归类 | 生成 |
|------|------|------|
| `data ≤ v < data + datalen`，且下一条是 `LI` | 字段读 | `BPF_LDX_MEM`（折叠） |
| `data ≤ v < data + datalen` | 字段取址 | `MOV r0,r1` + `ADD imm` |
| `str ≤ v < str + strsize` | 字符串字面量 | 报错，见 5.9 |
| 其余 | 立即数 | `BPF_MOV64_IMM` / `ld_imm64`，见 5.5.1 |

两处上界的取值有讲究：

- 用 `datalen` 而不是 `datasize`。`datalen` 是声明字段占据的实际范围 `max(offset + size)`；
  `datasize` 是按 256 字节向上取整的**分配容量**——tracepoint 记录有变长部分，
  `expr_load_data()` 要按容量拷贝，所以 `datasize` 必须保持是容量。用容量做判据会把最后一个
  字段之后的空隙也算成字段。eBPF 事件是定长结构体，`datalen` 即精确值。
- `prog->str` 只存放表达式自己的字符串字面量；声明的全局变量名另存在 `prog->names`。
  两者分开，"这个地址是不是字面量"才是一个干净的区间判断，变量名不会落进来。
  `-v` 输出的 `Strings:` 一节也因此只列真正的字面量。

### 5.4 数组下标

数组不需要后端做任何特殊处理，是 5.3 那个"地址在 data 范围内就换成 `r1 + 偏移`"的分支顺带
支撑起来的。

`tag[5]` 编译出的 VM 指令里，`IMM` 后面跟的是 `PSH` 而不是 `LI`，所以走**取址**路径——基址
在那一步就已经变成 `r1 + 40` 这个合法的 map value 指针，后面的下标运算和解引用都在它上面做，
verifier 自然接受。缩放也是前端做的：`IMM 4; MUL` 里那个 4 就是 `elementsize`。

以 `int tag[8]`（偏移 40）为例，`tag[5] == 7`：

```
VM                  eBPF
IMM 0x1562428        0: r0 = r1        1: r0 += 40    ← &tag
PSH                  2: r2 = r0
IMM 0x5              3: r0 = 5                        ← 下标
PSH                  4: r3 = r0
IMM 0x4              5: r0 = 4                        ← elementsize
MUL                  6: r3 *= r0       7: r0 = r3     ← 5 * 4 = 20
ADD                  8: r2 += r0       9: r0 = r2     ← 40 + 20 = 60
LI  0x2             10: r0 = *(u32 *)(r0 + 0)         ← BPF_W，一个元素
```

注意加载宽度是 `BPF_W`（4 字节，元素宽）而不是整个数组的 32 字节 —— `size` 与
`elementsize` 的区分贯穿整条链路。

**下标必须能被 verifier 定界**：常量、或掩码过的变量（`tag[i & 7]`）都行；裸变量（`tag[isa]`）
会被拒：

```
invalid access to map value, value_size=299080 off=561116 size=4
```

常量下标**不做**范围检查，`tag[16]` 能加载、读到相邻字段——和用户态 VM 一致。

### 5.5 指令映射表

| VM 指令 | eBPF | 说明 |
|---------|------|------|
| `IMM`（字段）+ `LI` | `BPF_LDX_MEM` / MEMSX | 折叠成一条，见 5.3；有符号窄字段见 5.8 |
| `IMM`（字段），无 `LI` | `MOV r0,r1` + `ADD imm` | 取址：`&pid`，以及数组下标的基址，见 5.4 |
| `IMM`（立即数） | `BPF_MOV64_IMM` / `ld_imm64` | 超过 32 位用后者，见 5.5.1 |
| `IMM addr;PSH;值;SI` | `BPF_STX_MEM` | 赋值。store 侧不需要符号处理，见 5.8 |
| `PSH` | `BPF_MOV64_REG(slot, r0)` | 栈槽即寄存器 |
| `OR XOR AND ADD SUB MUL` | `BPF_ALU64_REG` | 一对一 |
| `SHL SHR SAR` | `BPF_LSH / BPF_RSH / BPF_ARSH` | |
| `DIVu MODu` | `BPF_DIV / BPF_MOD` | 无符号，`off=0` |
| `DIV MOD` | `BPF_DIV / BPF_MOD` + `off=1` | 有符号，6.6+，见 5.5.2 |
| `EQ NE LT GT LE GE`（含 u 变体） | 4 条，见 5.6 | eBPF 无 set-on-condition |
| `BZ / BNZ` | `BPF_JMP_IMM(JEQ/JNE, r0, 0, ...)` | 目标需回填 |
| `JMP` | `BPF_JMP_A` | 目标需回填 |
| `NTHL / NTHS` | `BPF_ENDIAN(BPF_TO_BE, 32/16)` | 一条搞定 |
| `EXIT` | `BPF_EXIT_INSN` | 结果已在 r0 |

#### 5.5.1 宽立即数

`BPF_MOV64_IMM` 只能带 32 位、且做符号扩展，更宽的常量用 `ld_imm64`：它占**两个指令槽**，
低 32 位在第一个槽的 `imm`，高 32 位在第二个槽的 `imm`。

```
--filter 'latency > 10000000000'          10000000000 = 0x2_540BE400

    0: r0 = *(u64 *)(r1 + 16)             ← latency
    1: r2 = r0
    2: code=0x18  imm=1410065408          ← ld_imm64 低半：0x540BE400
    3: code=0x00  imm=2                   ← 高半；opcode 为 0，不是独立指令
    4: if r2 > r0 goto +2
```

第二个槽的 opcode 必须是 0，它不是一条独立指令，但**占一个槽位**。跳转偏移本来就按槽位计数，
所以回填（5.7）不需要为它做任何特殊处理。

#### 5.5.2 有符号 `/` `%`

BPF 指令集第 4 版（clang 的 `-mcpu=v4`，内核 6.6）没有为有符号除法新增 opcode，而是
**复用 `BPF_DIV`/`BPF_MOD`，用 `off` 字段区分**：`off=0` 无符号，`off=1` 有符号。这是唯一
一处 ALU 指令的 `off` 有含义，其余 ALU 指令都要求它为 0。

因此后端不能用 `BPF_ALU64_REG()`——它把 `off` 写死成 0——只能用 `BPF_RAW_INSN()`。

```
--filter 'latency / 1000 > 5'

    0: r0 = *(u64 *)(r1 + 16)             ← latency
    1: r2 = r0
    2: r0 = 1000
    3: code=0x3f dst=r2 src=r0 off=1      ← BPF_ALU64|BPF_DIV|BPF_X，off=1 即有符号
    4: r0 = r2
    7: code=0x6d if r2 s> r0 goto +2      ← JSGT
```

verifier 也是这么读的（`adjust_scalar_min_max_vals()`）：

```c
if (off == 1) scalar_min_max_sdiv(dst_reg, &src_reg);
else          scalar_min_max_udiv(dst_reg, &src_reg);
```

6.6 之前的内核没有这个例外，所有 ALU 指令都必须 `off=0`，`off=1` 会被拒：

```
BPF_ALU uses reserved fields
```

所以版本判断必须在生成指令**之前**做（`--filter 'latency / 1000 > 5'` 在低版本内核上直接报
`signed division requires a 6.6+ kernel`），否则错误会推迟到 verifier，且信息晦涩。

> 版本判断是**运行时**的：perf-prof 编译一次、可能跑在任意内核上，过滤器是为"即将加载进去的
> 那个内核"生成的。`kernel_release()` 要读 `uname()`，结果缓存在 `struct bpf_emit` 里，每次
> 翻译只取一次。

### 5.6 比较：顺序很关键

eBPF 没有 set-on-condition，布尔值要用分支构造。这里有个陷阱：**右操作数就在累加器
（r0）里**，如果先把结果写进 r0 就会把它冲掉。所以必须先比较、后写结果：

```
if (slot <cond> r0) goto +2
r0 = 0
goto +1
r0 = 1
```

（第一版实现写成了 `r0 = 1; if(...) goto +1; r0 = 0`，正好踩中这个 bug。）

### 5.7 跳转回填

`BZ`/`BNZ`/`JMP` 的目标是 VM 指令地址，需要映射到 eBPF 指令下标。做法是：

- `pc_map[VM pc] = eBPF insn 下标`，边翻译边记录；
- 跳转指令的位置和目标 VM pc 记进 `fixup_at[]`/`fixup_to[]`；
- 全部翻译完后统一回填，`off = target - at - 1`（BPF 偏移相对**下一条**指令）。

> 只回填记录过的跳转。第一版遍历所有 `BPF_JMP` 类指令去 patch，把 5.5 里比较指令自己
> 已经算好的相对偏移也改坏了。

### 5.8 符号扩展

`BPF_LDX_MEM` 是**零扩展**。用户态 VM 的 `LI` 按字段自己的类型解引用，窄的有符号字段读出来
就是符号扩展过的，所以后端必须补上，否则后面每一个有符号比较的结果都和用户态 VM 不一致。

按内核版本走两条路径：

| 内核 | 生成 |
|------|------|
| 6.6+ | 一条 `ldx` 走 MEMSX 模式（`code = BPF_LDX \| size \| BPF_MEMSX`），尺寸只有 B/H/W——DW 加载已填满寄存器，无可扩展 |
| 更早 | 零扩展加载后，把符号位移到 bit 63 再算术移回 |

```c
/* 6.6 之前 */
EMIT(BPF_ALU64_IMM(BPF_LSH,  BPF_ACC, bits));
EMIT(BPF_ALU64_IMM(BPF_ARSH, BPF_ACC, bits));
```

两个加载点共用 `emit_load()`：5.3 里折叠成一条的字段读，以及 `LI` 单独出现、地址已经在累加器
里的情况（`*(char *)((char *)&latency + 1)` 这种先算地址的形式）。

以 `*(char *)((char *)&latency + 1) < 0` 为例，`latency` 偏移 16，取第 1 个字节：

```
    5: r0 = r2                        ← 地址算完在累加器里
    6: code=0x71 r0 = *(u8 *)(r0+0)   ← BPF_LDX|B|MEM，零扩展
    7: r0 <<= 56                      ← 补符号扩展
    8: r0 s>>= 56
   11: code=0xcd if r2 s< r0 goto +2  ← JSLT，有符号
```

### 5.9 不支持的构造

全部在**编译期**报错并给出具体原因，不会生成让 verifier 报晦涩错误的代码：

| 构造 | 原因 |
|------|------|
| `_cpu` / `_pid` | perf 采样头字段，内核侧不存在（见下文） |
| 有符号 `/` `%`（6.6 以下） | 该编码是 6.6+，低版本内核无对应指令，见 5.5.2 |
| `ksymbol()` | 依赖用户态 `/proc/kallsyms` 符号表 |
| `comm_get()` | 依赖用户态 pid→comm 缓存 |
| `printf()` / `system()` | 是输出/执行动作，不是过滤 |
| `strncmp()` / `~` / 字符串 `==` `!=` | 需要无界循环 |
| `syscall_name()` / `exit_reason_str()` | 返回字符串，内核侧无意义 |
| 数组的**裸变量**下标 | verifier 无法定界，报 `invalid access to map value`。常量和掩码下标可以，见 4.3 |

字段名写错仍然走原有诊断，带 `^` 定位并列出可用字段：

```
$ perf-prof bpf:kvm_exit --filter 'nosuchfield == 1'
nosuchfield == 1
             ^ undefined variable
Available variables:
     unsigned int tgid
     unsigned int pid
     ...
```

`_cpu` / `_pid` 是 perf 采样头里的字段（从 `PERF_SAMPLE_CPU` / `PERF_SAMPLE_TID` 填入），
在内核侧 BPF 过滤器里不存在，使用它们同样会报 `undefined variable`。

### 5.10 赋值：为什么允许写事件

后端**支持** `SI`（赋值），这是有意的，两个理由：

1. **就地修正/标注要输出的事件**——掩码某个字段、缩放一个延迟，比送到用户态再改便宜；
2. **表达式语言没有自己的变量**，闲置的事件字段是唯一能放临时值的地方：
   `sched_latency = latency / switches, sched_latency > 100` 必须有处安放那个商。

⚠️ **注意**：事件可能是 BPF 程序**跨事件保留**的存储，而不是一份临时副本。写掉程序后续
还要用的字段，会扰动之后的事件，不只是当前这一个。

## 六、占位符为什么要写成那样

> 只在改动 `DEFINE_EXPR_FILTER()` 或移植到新内核时才需要，跳过不影响使用。

`DEFINE_EXPR_FILTER()` 展开出的函数体看着很怪，每一处都是必需的——都是靠 verifier 日志
才定位到的：

```c
static __noinline int expr_filter(event_type *event)
{
    int ret = 1;
    asm volatile("" : "+r"(ret) : "r"(event));
    return ret;
}
```

| 写法 | 去掉会怎样 |
|------|-----------|
| `__noinline` | 函数被内联，`.text` 里没有 subprogram 可找 |
| `asm volatile` 包裹返回值 | 光有 `__noinline` 不够：`return 1` 被常量折叠，`.text` 变成 **0 字节** |
| 不引用任何全局变量 | 用 `const volatile int` 防折叠会把变量放进 `.rodata`，libbpf 把 map 重定位**重新盖到替换后的 `insn[0]`** 上，把 `imm` 改成 map fd。verifier 报 `BPF_LDX uses reserved fields` |
| asm 里消费 `event` | clang 判定参数是死的、调用点不再往 r1 放指针。生成代码解引用 r1 时 verifier 报 `R1 is not a pointer`（日志里能看到 `frame1: R1=invP1000`——r1 里是个标量） |
| 生成指令数 ≥ 2 | libbpf 用**原始**指令数搬运 BTF line_info、却按**新**长度校验，更短会报 `Invalid line_info[N].insn_off`。任何表达式至少需要一条加载和一条 exit，所以实际总能满足 |

## 七、实例

以下全部取自 `bpf:kvm_exit`，用 `-v` 可以看到 VM 指令和 eBPF 指令两份输出。

`struct kvm_vcpu_event`（`src/bpf-skel/kvm_exit.h`）的布局，由 BTF 读出：

| 字段 | 偏移 | 大小 |
|------|------|------|
| `tgid` | 0 | 4 |
| `pid` | 4 | 4 |
| `isa` | 8 | 2 |
| `switches` | 10 | 2 |
| `exit_reason` | 12 | 4 |
| `latency` | 16 | 8 |
| `run_delay` | 24 | 8 |
| `sched_latency` | 32 | 8 |

### 7.1 简单比较

```
--filter 'exit_reason == 12'

等价于 expr_filter() 被实现成：

    int expr_filter(struct kvm_vcpu_event *event)
    {
        return event->exit_reason == 12;
    }

VM:  IMM 0x266c40c; LI 0xa; PSH; IMM 0xc; EQ; EXIT

BPF: 0: r0 = *(u32 *)(r1 + 12)      ← IMM+LI 折叠，偏移 12 = exit_reason
     1: r2 = r0                      ← PSH
     2: r0 = 12
     3: if r2 == r0 goto +2          ← 先比较
     4: r0 = 0
     5: goto +1
     6: r0 = 1
     7: exit
```

### 7.2 逻辑与（含跳转回填）

```
--filter 'exit_reason == 12 && latency > 1000000'

等价于 expr_filter() 被实现成：

    int expr_filter(struct kvm_vcpu_event *event)
    {
        return event->exit_reason == 12 && event->latency > 1000000;
    }

VM:  ... EQ; BZ 0x1472098; IMM 0x1458410; LI 0x3; PSH; IMM 0xf4240; GT; EXIT

BPF: 0-6: 同上，exit_reason == 12 的结果在 r0
     7: if r0 == 0 goto +7           ← BZ 短路，回填后指向 15
     8: r0 = *(u64 *)(r1 + 16)       ← latency，偏移 16，BPF_DW
     9: r2 = r0
    10: r0 = 1000000
    11: if r2 > r0 goto +2           ← 有符号 JSGT（latency 是 int64_t）
    12: r0 = 0
    13: goto +1
    14: r0 = 1
    15: exit
```

### 7.3 赋值 + 用字段当临时变量

```
--filter 'sched_latency = latency, sched_latency > 1000'

等价于 expr_filter() 被实现成（逗号运算符：求值全部，返回最后一个）：

    int expr_filter(struct kvm_vcpu_event *event)
    {
        event->sched_latency = event->latency;      /* 赋值，写回事件 */
        return event->sched_latency > 1000;
    }

VM:  IMM 0x14f8420; PSH; IMM 0x14f8410; LI 0x3; SI 0x3; ...

BPF: 0: r0 = r1
     1: r0 += 32                     ← &sched_latency，取址（IMM 无 LI）
     2: r2 = r0                      ← PSH，目标地址进栈槽
     3: r0 = *(u64 *)(r1 + 16)       ← latency
     4: *(u64 *)(r2 + 0) = r0        ← SI：赋值
     5: r0 = *(u64 *)(r1 + 32)       ← 回读 sched_latency
     6: r2 = r0
     7: r0 = 1000
     8: if r2 > r0 goto +2
     9: r0 = 0
    10: goto +1
    11: r0 = 1
    12: exit
```

## 八、调试

第一步永远是 `-v`，它把字段表、VM 指令、eBPF 指令三样都打出来：

```bash
perf-prof bpf:kvm_exit --filter '...' -v
```

按报错来源分三类：

| 报错来自 | 形态 | 怎么查 |
|---------|------|--------|
| 表达式前端 | `undefined variable` 等，带 `^` 指位置 | 对照 `-v` 打出的字段表，确认字段名，以及该字段是不是标量（见 4.3） |
| `expr_to_bpf()` | `expr: cannot compile to BPF: ...` | 用了不支持的构造，见 5.9 |
| 内核 verifier | 加载失败，附带逐指令日志 | 日志会给出问题指令和寄存器状态；若怀疑是占位符本身的问题，见第六节的对照表 |

verifier 日志比看起来好用——它标出出错指令的下标和当时每个寄存器的类型，和 `-v` 打出的
eBPF 指令清单逐条对照即可定位。第六节那三条报错就都是这么找到的。

## 相关文档

- [expr.md](expr.md) — 表达式语法
- [Event_filtering.md](Event_filtering.md) — tracepoint（ftrace）过滤器语法