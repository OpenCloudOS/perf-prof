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

- 定长 struct，成员是标量（整型或枚举）；
- 位域、指针、嵌套聚合会被跳过（位域没有字节偏移可加载，指针需要 `bpf_probe_read()`，
  聚合没有表达式能用的值语义）。被跳过的字段在表达式里引用会报 `undefined variable`；
- 事件必须在**可写内存**里（`.bss` 或 map value），因为表达式允许赋值。

## 五、翻译成 eBPF 指令集

### 5.1 调用约定

生成的代码遵循 BPF subprogram 调用约定：

| 寄存器 | 用途 |
|--------|------|
| `r1` | 事件指针（入口参数），全程不被破坏 |
| `r0` | 累加器，对应 VM 的 `a` 寄存器；同时是返回值：非 0 保留事件，0 丢弃 |
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

### 5.3 核心：字段访问

这是整个翻译的关键，也是"表达式里的 `exit_reason` 怎么变成 `event->exit_reason`"的答案。

`expr_compile()` 给全局变量分配的地址是 `prog->data + offset`（`src/expr.c` 中
`id->value = (long)data + declare->offset`），所以 VM 指令 **`IMM addr; LI type`** 的语义
恰好就是 `*(type *)(event + offset)`——**它本来就是指针访问**，只是基址是用户态地址。

后端只需反解偏移，把这一对指令折叠成一条加载：

```c
offset = id->value - (long)prog->data;
EMIT(BPF_LDX_MEM(size, BPF_A, BPF_REG_1, offset));
```

赋值是完全对偶的：**`IMM addr; PSH; <值>; SI type`** → `BPF_STX_MEM`。

`LI`/`SI` 的操作数携带类型，size 由它换算：

| VM 类型 | 字节 | BPF size |
|---------|------|----------|
| `CHAR` | 1 | `BPF_B` |
| `SHORT` | 2 | `BPF_H` |
| `INT` | 4 | `BPF_W` |
| `LONG` / 指针 | 8 | `BPF_DW` |

### 5.4 指令映射表

| VM 指令 | eBPF | 说明 |
|---------|------|------|
| `IMM`（字段）+ `LI` | `BPF_LDX_MEM` | 折叠成一条，见 5.3 |
| `IMM`（字段），无 `LI` | `MOV r0,r1` + `ADD imm` | 取址，如 `&pid` |
| `IMM`（立即数） | `BPF_MOV64_IMM` | |
| `IMM addr;PSH;值;SI` | `BPF_STX_MEM` | 赋值 |
| `PSH` | `BPF_MOV64_REG(slot, r0)` | 栈槽即寄存器 |
| `OR XOR AND ADD SUB MUL` | `BPF_ALU64_REG` | 一对一 |
| `SHL SHR SAR` | `BPF_LSH / BPF_RSH / BPF_ARSH` | |
| `DIVu MODu` | `BPF_DIV / BPF_MOD` | 仅无符号 |
| `EQ NE LT GT LE GE`（含 u 变体） | 4 条，见 5.5 | eBPF 无 set-on-condition |
| `BZ / BNZ` | `BPF_JMP_IMM(JEQ/JNE, r0, 0, ...)` | 目标需回填 |
| `JMP` | `BPF_JMP_A` | 目标需回填 |
| `NTHL / NTHS` | `BPF_ENDIAN(BPF_TO_BE, 32/16)` | 一条搞定 |
| `EXIT` | `BPF_EXIT_INSN` | 结果已在 r0 |

### 5.5 比较：顺序很关键

eBPF 没有 set-on-condition，布尔值要用分支构造。这里有个陷阱：**右操作数就在累加器
（r0）里**，如果先把结果写进 r0 就会把它冲掉。所以必须先比较、后写结果：

```
if (slot <cond> r0) goto +2
r0 = 0
goto +1
r0 = 1
```

（第一版实现写成了 `r0 = 1; if(...) goto +1; r0 = 0`，正好踩中这个 bug。）

### 5.6 跳转回填

`BZ`/`BNZ`/`JMP` 的目标是 VM 指令地址，需要映射到 eBPF 指令下标。做法是：

- `pc_map[VM pc] = eBPF insn 下标`，边翻译边记录；
- 跳转指令的位置和目标 VM pc 记进 `fixup_at[]`/`fixup_to[]`；
- 全部翻译完后统一回填，`off = target - at - 1`（BPF 偏移相对**下一条**指令）。

> 只回填记录过的跳转。第一版遍历所有 `BPF_JMP` 类指令去 patch，把 5.5 里比较指令自己
> 已经算好的相对偏移也改坏了。

### 5.7 符号扩展

`BPF_LDX_MEM` 是**零扩展**。窄的有符号字段需要手工符号扩展，否则有符号比较行为和用户态
VM 不一致：

```c
EMIT(BPF_ALU64_IMM(BPF_LSH, BPF_A, bits));
EMIT(BPF_ALU64_IMM(BPF_ARSH, BPF_A, bits));
```

（`BPF_MEMSX` 一条即可，但那是 6.7+。）

### 5.8 不支持的构造

全部在**编译期**报错并给出具体原因，不会生成让 verifier 报晦涩错误的代码：

| 构造 | 原因 |
|------|------|
| 有符号 `/` `%` | 需要符号修正序列；`BPF_SDIV`/`BPF_SMOD` 是 6.7+ |
| `ksymbol()` | 依赖用户态 `/proc/kallsyms` 符号表 |
| `comm_get()` | 依赖用户态 pid→comm 缓存 |
| `printf()` / `system()` | 是输出/执行动作，不是过滤 |
| `strncmp()` / `~` / 字符串 `==` `!=` | 需要无界循环 |
| `syscall_name()` / `exit_reason_str()` | 返回字符串，内核侧无意义 |
| 数组下标（变量偏移） | verifier 要求显式 bounds masking |

字段名写错仍然走原有诊断，带 `^` 定位并列出可用字段：

```
$ perf-prof bpf:kvm_exit --filter 'nosuchfield == 1'
nosuchfield == 1
             ^ undefined variable
Available variables:
     int _cpu
     int _pid
     unsigned int tgid
     ...
```

### 5.9 赋值：为什么允许写事件

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
| `expr_to_bpf()` | `expr: cannot compile to BPF: ...` | 用了不支持的构造，见 5.8 |
| 内核 verifier | 加载失败，附带逐指令日志 | 日志会给出问题指令和寄存器状态；若怀疑是占位符本身的问题，见第六节的对照表 |

verifier 日志比看起来好用——它标出出错指令的下标和当时每个寄存器的类型，和 `-v` 打出的
eBPF 指令清单逐条对照即可定位。第六节那三条报错就都是这么找到的。

## 相关文档

- [expr.md](expr.md) — 表达式语法
- [Event_filtering.md](Event_filtering.md) — tracepoint（ftrace）过滤器语法