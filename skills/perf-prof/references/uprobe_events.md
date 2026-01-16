# Uprobe 动态探针

基于 Linux 内核文档 [uprobetracer.rst](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/trace/uprobetracer.rst) 整理。

## 概述

Uprobe 事件是基于 uprobe 的用户空间动态跟踪事件，与 kprobe 类似但用于跟踪用户空间程序。

**特点：**
- 跟踪用户空间程序和库函数
- 动态添加/删除，无需重新编译
- 需要用户手动计算探针在目标文件中的偏移

**内核配置：** 需要 `CONFIG_UPROBE_EVENTS=y`

**相关文件：**
- `/sys/kernel/debug/tracing/uprobe_events` - 添加/删除探针
- `/sys/kernel/debug/tracing/dynamic_events` - 统一动态事件接口
- `/sys/kernel/debug/tracing/events/uprobes/<EVENT>/` - 探针事件目录
- `/sys/kernel/debug/tracing/uprobe_profile` - 探针命中统计

## 语法

```
p[:[GRP/][EVENT]] PATH:OFFSET [FETCHARGS]           # uprobe - 函数入口探针
r[:[GRP/][EVENT]] PATH:OFFSET [FETCHARGS]           # uretprobe - 函数返回探针
p[:[GRP/][EVENT]] PATH:OFFSET%return [FETCHARGS]    # uretprobe - 另一种语法
-:[GRP/][EVENT]                                      # 删除探针
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `GRP` | 组名，省略时默认为 "uprobes" |
| `EVENT` | 事件名，省略时根据 PATH+OFFSET 自动生成 |
| `PATH` | 可执行文件或库的完整路径 |
| `OFFSET` | 探针在文件中的偏移（不是虚拟地址） |
| `OFFSET%return` | 返回探针的偏移 |

**重要：** OFFSET 是文件偏移，不是运行时虚拟地址！

## FETCHARGS 参数获取

每个探针最多支持 128 个参数，格式为：`NAME=FETCHARG:TYPE`

### FETCHARG 类型

| 语法 | 说明 | 限制 |
|------|------|------|
| `%REG` | 获取寄存器值 | |
| `@ADDR` | 获取用户空间地址的内存值 | ADDR 必须是用户空间地址 |
| `@+OFFSET` | 获取同一文件中指定偏移的内存值 | |
| `$stackN` | 获取栈上第 N 个值 | N >= 0 |
| `$stack` | 获取栈地址 | |
| `$retval` | 获取返回值 | 仅 uretprobe |
| `$comm` | 获取当前进程名 | 默认类型为 string |
| `+\|-OFFS(FETCHARG)` | 内存解引用，获取结构体字段 | |
| `+\|-uOFFS(FETCHARG)` | 用户空间解引用（u 前缀被忽略） | |
| `\IMM` | 立即数 | |

**注意：** 与 kprobe 不同，uprobe 中 `u` 前缀会被忽略，因为 uprobe 只能访问用户空间内存。

### 数据类型 TYPE

| 类型 | 说明 |
|------|------|
| `u8/u16/u32/u64` | 无符号整数，十进制显示 |
| `s8/s16/s32/s64` | 有符号整数，十进制显示 |
| `x8/x16/x32/x64` | 无符号整数，十六进制显示 |
| `string` | 用户空间 null 结尾字符串 |
| `b<width>@<offset>/<size>` | 位域 |

**默认类型：** 不指定类型时，根据架构使用 `x32`（32位）或 `x64`（64位）。

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

## 获取函数偏移的方法

**关键点：** uprobe 使用的是文件偏移，不是运行时虚拟地址。
**推荐：** 使用方法 1

### 方法 1：使用 perf-prof

```bash
# 直接输出文件偏移（OFFSET），不是运行时虚拟地址！
echo func_name | perf-prof --symbols /path/to/binary
```

### 方法 2：使用 nm

```bash
# 查看动态符号
nm -D /path/to/binary | grep " func_name"

# 查看所有符号
nm /path/to/binary | grep " func_name"
```

### 方法 3：使用 objdump

```bash
# 查看动态符号表
objdump -T /path/to/binary | grep func_name

# 查看所有符号
objdump -t /path/to/binary | grep func_name
```

### 方法 4：使用 readelf

```bash
# 查看符号表
readelf -s /path/to/binary | grep func_name

# 查看动态符号表
readelf --dyn-syms /path/to/binary | grep func_name
```

### 计算偏移示例（仅方法 2/3/4）

```bash
# 1. 查看进程映射
cat /proc/$(pgrep zsh)/maps | grep /bin/zsh | grep r-xp
# 输出: 00400000-0048a000 r-xp 00000000 08:03 130904 /bin/zsh

# 2. 查看函数符号地址
objdump -T /bin/zsh | grep -w zfree
# 输出: 0000000000446420 g    DF .text  0000000000000012  Base        zfree

# 3. 偏移计算
# 符号地址: 0x446420
# 加载基址: 0x400000
# 文件偏移 = 0x446420 - 0x400000 = 0x46420
# 或者对于 PIE 可执行文件，符号地址本身就是偏移
```

## 使用示例

### 基本示例

```bash
# 在 /bin/bash 的 0x4245c0 偏移处添加 uprobe
echo 'p /bin/bash:0x4245c0' > /sys/kernel/debug/tracing/uprobe_events

# 添加 uretprobe
echo 'r /bin/bash:0x4245c0' >> /sys/kernel/debug/tracing/uprobe_events

# 查看已注册的探针
cat /sys/kernel/debug/tracing/uprobe_events

# 删除探针
echo '-:p_bash_0x4245c0' >> /sys/kernel/debug/tracing/uprobe_events

# 清除所有探针
echo > /sys/kernel/debug/tracing/uprobe_events
```

### 带参数的探针

```bash
# 探测 zsh 的 zfree 函数，记录 IP 和 AX 寄存器
echo 'p:zfree_entry /bin/zsh:0x46420 %ip %ax' > /sys/kernel/debug/tracing/uprobe_events

# 返回探针
echo 'r:zfree_exit /bin/zsh:0x46420 %ip %ax' >> /sys/kernel/debug/tracing/uprobe_events

# 查看事件格式
cat /sys/kernel/debug/tracing/events/uprobes/zfree_entry/format

# 启用探针
echo 1 > /sys/kernel/debug/tracing/events/uprobes/enable

# 开始跟踪
echo 1 > /sys/kernel/debug/tracing/tracing_on

# 查看跟踪结果
cat /sys/kernel/debug/tracing/trace

# 停止跟踪
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 0 > /sys/kernel/debug/tracing/events/uprobes/enable
```

### 跟踪 libc 函数

```bash
# 获取 malloc 偏移
echo malloc | perf-prof --symbols /lib64/libc.so.6 # 输出: 0x9b1e0

# 添加 malloc 探针，记录分配大小
echo 'p:malloc /lib64/libc.so.6:0x9b1e0 size=%di:u64' > /sys/kernel/debug/tracing/uprobe_events

# 添加返回探针，记录返回的指针
echo 'r:malloc_ret /lib64/libc.so.6:0x9b1e0 ptr=$retval:x64' >> /sys/kernel/debug/tracing/uprobe_events

# 跟踪 free
echo free | perf-prof --symbols /lib64/libc.so.6 # 输出：0x9b870
echo 'p:free /lib64/libc.so.6:0x9b870 ptr=%di:x64' >> /sys/kernel/debug/tracing/uprobe_events
```

### 获取字符串参数

```bash
# 跟踪 open 系统调用包装函数，获取文件名
# 注意：对于系统调用包装，filename 是第一个参数
echo 'p:myopen /lib64/libc.so.6:0xXXXXX filename=+0(%di):string' > /sys/kernel/debug/tracing/uprobe_events
```

### 获取结构体字段

```bash
# 假设第一个参数是结构体指针，获取偏移+8处的字段
echo 'p:mystruct /path/to/app:0x1234 field1=+8(%di):u64 field2=+16(%di):u32' > /sys/kernel/debug/tracing/uprobe_events
```

### 命名参数

```bash
# 为参数指定名称
echo 'p:zfree_entry /bin/zsh:0x46420 ip=%ip ax=%ax' > /sys/kernel/debug/tracing/uprobe_events
```

## 探针事件目录

添加探针后，在 `/sys/kernel/debug/tracing/events/uprobes/<EVENT>/` 目录下会有以下文件：

| 文件 | 说明 |
|------|------|
| `enable` | 写入 1/0 启用/禁用探针 |
| `format` | 探针事件格式 |
| `filter` | 事件过滤规则 |
| `id` | 事件 ID |
| `trigger` | 触发命令 |

## 查看探针统计

```bash
# 查看探针命中次数
cat /sys/kernel/debug/tracing/uprobe_profile
# 输出格式: 文件名 事件名 命中次数
```

## 在 perf-prof 中使用

添加 uprobe 探针后，可以在 perf-prof 中使用 `uprobes:EVENT` 格式引用：

```bash
# 先添加探针
echo 'p:malloc /lib64/libc.so.6:0x9b1e0 size=%di:u64' > /sys/kernel/debug/tracing/uprobe_events
echo 'r:malloc_ret /lib64/libc.so.6:0x9b1e0 ptr=$retval:x64' >> /sys/kernel/debug/tracing/uprobe_events

# 在 perf-prof 中使用
perf-prof trace -e uprobes:malloc
perf-prof multi-trace -e uprobes:malloc -e uprobes:malloc_ret -i 1000

# 结合过滤器和属性
perf-prof trace -e 'uprobes:malloc/size>1024/'
perf-prof top -e 'uprobes:malloc//key=size/'
```

## 与 kprobe 的差异

| 特性 | kprobe | uprobe |
|------|--------|--------|
| 作用域 | 内核空间 | 用户空间 |
| 地址类型 | 符号名或内核地址 | 文件路径:偏移 |
| `$argN` | 支持 | 不支持 |
| `@SYM` | 内核符号 | 不支持 |
| `@ADDR` | 内核地址 | 用户空间地址 |
| `@+OFFSET` | 不支持 | 同一文件偏移 |
| `u` 前缀 | 区分用户/内核空间 | 被忽略（总是用户空间） |
| `symbol` 类型 | 支持 | 不支持 |
| `ustring` 类型 | 支持 | 不支持（使用 string） |

## 注意事项

1. **偏移是文件偏移：** 不是运行时虚拟地址，需要从符号表获取
2. **PIE 可执行文件：** 对于位置无关可执行文件，符号地址即为偏移
3. **共享库：** 共享库的偏移通常是相对于文件开头的
4. **覆盖 vs 追加：** 使用 `>` 会清除所有已有探针，使用 `>>` 追加
5. **探针名唯一性：** 同一组内探针名必须唯一
6. **删除顺序：** 删除探针前确保没有程序在使用
7. **符号 strip：** 如果二进制被 strip，可能无法找到符号，需要使用调试信息或手动计算偏移

## 常见库函数偏移获取

```bash
# libc 常用函数
nm -D /lib64/libc.so.6 | grep -E " (malloc|free|realloc|calloc|open|close|read|write|mmap|munmap)$"

# libpthread 函数
nm -D /lib64/libpthread.so.0 | grep -E " (pthread_create|pthread_join|pthread_mutex_lock|pthread_mutex_unlock)$"

# 自定义程序（未 strip）
nm /path/to/myapp | grep " my_function"

# 自定义程序（已 strip，需要调试符号）
nm /path/to/myapp.debug | grep " my_function"
```

## 相关资源
- [uprobetracer.rst](uprobetracer.rst)
