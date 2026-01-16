# Kprobe 动态探针

基于 Linux 内核文档 [kprobetrace.rst](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/trace/kprobetrace.rst) 整理。

## 概述

Kprobe 事件是基于 kprobe 和 kretprobe 的动态跟踪事件。与 tracepoint 不同，kprobe 可以动态添加和删除，无需重新编译内核。

**特点：**
- 可以探测几乎所有内核函数（除了带 `__kprobes/nokprobe_inline` 注解或标记 `NOKPROBE_SYMBOL` 的函数）
- 动态添加/删除，无需重启
- 每个探针最多支持 128 个参数

**内核配置：** 需要 `CONFIG_KPROBE_EVENTS=y`

**相关文件：**
- `/sys/kernel/debug/tracing/kprobe_events` - 添加/删除探针
- `/sys/kernel/debug/tracing/dynamic_events` - 统一动态事件接口
- `/sys/kernel/debug/tracing/events/kprobes/<EVENT>/` - 探针事件目录
- `/sys/kernel/debug/tracing/kprobe_profile` - 探针命中统计

## 语法

```
p[:[GRP/][EVENT]] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]    # kprobe - 函数入口探针
r[MAXACTIVE][:[GRP/][EVENT]] [MOD:]SYM[+0] [FETCHARGS]    # kretprobe - 函数返回探针
p[:[GRP/][EVENT]] [MOD:]SYM[+0]%return [FETCHARGS]        # kretprobe - 另一种语法
-:[GRP/][EVENT]                                            # 删除探针
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `GRP` | 组名，省略时默认为 "kprobes" |
| `EVENT` | 事件名，省略时根据 SYM+offs 或 MEMADDR 自动生成 |
| `MOD` | 符号所在的内核模块名 |
| `SYM[+offs]` | 符号名+偏移，探针插入位置 |
| `SYM%return` | 符号的返回地址（用于 kretprobe） |
| `MEMADDR` | 内存地址，探针插入位置 |
| `MAXACTIVE` | kretprobe 最大并发实例数，0 使用默认值 |

## FETCHARGS 参数获取

每个探针最多支持 128 个参数，格式为：`NAME=FETCHARG:TYPE`

### FETCHARG 类型

| 语法 | 说明 | 限制 |
|------|------|------|
| `%REG` | 获取寄存器值 | |
| `@ADDR` | 获取内核地址的内存值 | ADDR 必须是内核地址 |
| `@SYM[+\|-offs]` | 获取内核符号地址的内存值 | SYM 必须是数据符号 |
| `$stackN` | 获取栈上第 N 个值 | N >= 0 |
| `$stack` | 获取栈地址 | |
| `$argN` | 获取第 N 个函数参数 | N >= 1，仅函数入口(offs==0)，仅寄存器传参 |
| `$retval` | 获取返回值 | 仅 kretprobe |
| `$comm` | 获取当前进程名 | 默认类型为 string |
| `+\|-OFFS(FETCHARG)` | 内存解引用，获取结构体字段 | |
| `+\|-uOFFS(FETCHARG)` | 用户空间内存解引用 | |
| `\IMM` | 立即数 | |

### 数据类型 TYPE

| 类型 | 说明 |
|------|------|
| `u8/u16/u32/u64` | 无符号整数，十进制显示 |
| `s8/s16/s32/s64` | 有符号整数，十进制显示 |
| `x8/x16/x32/x64` | 无符号整数，十六进制显示 |
| `char` | 字符值 |
| `string` | 内核空间 null 结尾字符串 |
| `ustring` | 用户空间 null 结尾字符串 |
| `symbol` | 指针以 "symbol+offset" 格式显示 |
| `symstr` | 指针转为 "symbol+offset/size" 字符串存储 |
| `%pd` | 从 struct dentry 地址获取文件名 |
| `%pD` | 从 struct file 地址获取文件名 |
| `b<width>@<offset>/<size>` | 位域 |
| `<type>[N]` | 数组，N < 64 |

**数组说明：**
- 数组只能用于内存类型的 FETCHARG，不能用于寄存器/栈
- 错误示例：`$stack1:x8[8]`
- 正确示例：`+8($stack):x8[8]`
- `string[1]` 不等于 `string`，string 表示字符数组，`string[N]` 表示字符指针数组

## x86_64 寄存器与函数参数对应

| 参数顺序 | 寄存器 | FETCHARG |
|----------|--------|----------|
| 第 1 个参数 | RDI | `%di` |
| 第 2 个参数 | RSI | `%si` |
| 第 3 个参数 | RDX | `%dx` |
| 第 4 个参数 | RCX | `%cx` |
| 第 5 个参数 | R8 | `%r8` |
| 第 6 个参数 | R9 | `%r9` |
| 返回值 | RAX | `%ax` 或 `$retval` |

**注意：** 超过 6 个参数时，后续参数通过栈传递。

## 用户空间内存访问

Kprobe 支持访问用户空间内存，使用 `u` 前缀：

```bash
# 用户空间解引用
+u4(%si)              # 从 %si+4 地址读取用户空间内存

# 用户空间字符串
+u0(%si):string       # 从 %si 地址读取用户空间字符串
+0(%si):ustring       # 等价写法
```

**重要：** 必须明确区分内核空间和用户空间，使用错误的解引用方式可能导致失败。

## 使用示例

### 基本示例

```bash
# 在 do_sys_open 函数入口添加探针，记录参数
echo 'p:myprobe do_sys_open dfd=%ax filename=%dx flags=%cx mode=+4($stack)' > /sys/kernel/debug/tracing/kprobe_events

# 在 do_sys_open 返回点添加探针，记录返回值
echo 'r:myretprobe do_sys_open $retval' >> /sys/kernel/debug/tracing/kprobe_events

# 查看探针事件格式
cat /sys/kernel/debug/tracing/events/kprobes/myprobe/format

# 启用探针
echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
echo 1 > /sys/kernel/debug/tracing/events/kprobes/myretprobe/enable

# 开始跟踪
echo 1 > /sys/kernel/debug/tracing/tracing_on

# 查看跟踪结果
cat /sys/kernel/debug/tracing/trace

# 停止跟踪
echo 0 > /sys/kernel/debug/tracing/tracing_on

# 删除单个探针
echo '-:myprobe' >> /sys/kernel/debug/tracing/kprobe_events

# 清除所有探针
echo > /sys/kernel/debug/tracing/kprobe_events
```

### 获取结构体字段

```bash
# 跟踪 try_to_wake_up，获取 task_struct->pid
# 需要先确认 pid 在 task_struct 中的偏移（不同内核版本不同）
# 使用 pahole 或内核源码确认偏移

# 假设 pid 偏移为 2264
echo 'p:wakeup try_to_wake_up pid=+2264(%di):s32' > /sys/kernel/debug/tracing/kprobe_events
```

### 嵌套解引用

```bash
# 假设第一个参数是指针，获取其偏移+8处的指针，再获取该指针偏移+16处的值
echo 'p:nested myfunc val=+16(+8(%di)):u64' >> /sys/kernel/debug/tracing/kprobe_events
```

### 使用 $argN（需要 BTF 支持）

```bash
# 使用 $arg1, $arg2 获取参数（更直观，但需要内核支持）
echo 'p:myfunc some_function arg1=$arg1:u64 arg2=$arg2:u32' >> /sys/kernel/debug/tracing/kprobe_events
```

### 在 kretprobe 中访问函数参数

```bash
# kretprobe 也可以访问 $argN，用于同时记录参数和返回值
echo 'r:myret some_function arg1=$arg1:u64 ret=$retval:s32' >> /sys/kernel/debug/tracing/kprobe_events
```

### 使用符号类型

```bash
# 将地址显示为符号名
echo 'p:myprobe some_function caller=+0($stack):symbol' >> /sys/kernel/debug/tracing/kprobe_events

# symstr 类型可用于过滤器通配符匹配
echo 'p:myprobe some_function caller=+0($stack):symstr' >> /sys/kernel/debug/tracing/kprobe_events
```

### 内核模块中的函数

```bash
# 探测 ext4 模块中的函数
echo 'p:myprobe ext4:ext4_file_write_iter' > /sys/kernel/debug/tracing/kprobe_events
```

## 探针事件目录

添加探针后，在 `/sys/kernel/debug/tracing/events/kprobes/<EVENT>/` 目录下会有以下文件：

| 文件 | 说明 |
|------|------|
| `enable` | 写入 1/0 启用/禁用探针 |
| `format` | 探针事件格式 |
| `filter` | 事件过滤规则 |
| `id` | 事件 ID |
| `trigger` | 触发命令 |

## 内核启动参数

可以在内核启动时添加 kprobe 事件：

```bash
# 普通格式（空格分隔）
p:myprobe do_sys_open dfd=%ax filename=%dx flags=%cx mode=+4($stack)

# 内核启动参数格式（逗号分隔）
kprobe_event=p:myprobe,do_sys_open,dfd=%ax,filename=%dx,flags=%cx,mode=+4($stack)
```

## 在 perf-prof 中使用

添加 kprobe 探针后，可以在 perf-prof 中使用 `kprobes:EVENT` 格式引用：

```bash
# 先添加探针
echo 'p:wakeup try_to_wake_up pid=+2264(%di):s32' > /sys/kernel/debug/tracing/kprobe_events

# 在 perf-prof 中使用
perf-prof trace -e kprobes:wakeup
perf-prof top -e 'kprobes:wakeup//key=pid/'
perf-prof multi-trace -e kprobes:wakeup -e sched:sched_switch -i 1000
```

## 注意事项

1. **覆盖 vs 追加：** 使用 `>` 会清除所有已有探针，使用 `>>` 追加
2. **偏移量确认：** 结构体字段偏移因内核版本而异，需用 `pahole` 或源码确认
3. **探针名唯一性：** 同一组内探针名必须唯一
4. **删除顺序：** 删除探针前确保没有程序在使用
5. **$argN 限制：** 只支持寄存器传参，栈传参无法获取
6. **$retval 限制：** 返回值可能使用寄存器对传递，但只能访问一个寄存器
7. **用户空间访问：** 必须使用正确的用户空间解引用语法

## 相关资源
- [kprobetrace.rst](kprobetrace.rst)
