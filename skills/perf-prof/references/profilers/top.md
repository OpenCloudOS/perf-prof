# top - 键值统计分析
多维度键值统计工具，通过采样事件构建(key, [values], name)统计矩阵，按指定列排序显示。

## 概述
- **主要用途**: 通过采样事件进行多维度统计，支持自定义键值聚合和排序，用于分析系统事件分布和热点
- **适用场景**: 各种计数统计场景，如：进程调度统计、中断频率分析、内存分配统计、IO性能分析、网络协议统计等
- **功能分类**: 自定义事件类，聚合分析，采样分析
- **最低内核版本**: 3.10 (支持perf_event)
- **平台支持**: x86, ARM
- **特殊限制**:
  - 需要root权限或CAP_SYS_ADMIN权限
  - 依赖库: libtraceevent (trace事件解析), libperf (性能事件)
- **参与联合分析**: 不支持作为联合分析的事件源

## 基础用法
```bash
perf-prof top [OPTION...] -e "event[/filter/key=EXPR/top-by=EXPR/top-add=EXPR/comm=EXPR/alias=STR/printkey=EXPR/][,event2...]" [-k EXPR] [--only-comm]
```

### OPTION
- `--watermark <0-100>`: 默认50（不同于其他分析器）
- `-i, --interval <ms>`: 默认1000ms
- `-m, --mmap-pages <N>`: 默认4页

### FILTER OPTION
- `/filter/`: 内核态trace event过滤器，位于事件名之后的第一个//之间
- 用户态ftrace过滤器：当内核态过滤器失败时自动降级

### PROFILER OPTION
- `-e, --event <EVENT,...>`: 事件选择器，多个事件使用','分隔，不支持多个-e选项
- `-k, --key <EXPR>`: 设置键表达式，默认使用线程ID(tid)
- `--only-comm`: 仅显示进程名列，隐藏键列

### 事件属性
- `/key=EXPR/`: 指定键列表达式
- `/printkey=EXPR/`: 定制键列输出格式
- `/top-by=EXPR/`: 增加值列，优先排序
- `/top-add=EXPR/`: 增加值列，默认排序
- `/comm=EXPR/`: 键的对应名称
- `/alias=str/`: 事件的别名

## 核心原理

### 数据模型
```
事件 → (key, [value1, value2, ..., valuen], name) → 聚合 → 排序显示
```

### 事件源
- **自定义事件**: `-e` 选项指定多个事件，','分隔

### 过滤器层次
1. **内核态trace event过滤器**: `/filter/` 语法
2. **用户态ftrace过滤器**: 内核态失败时自动降级

### 事件处理

**三大核心组件**

1. **键(key) - 键列**
   - 作用：行标识，确定数据聚合的行
   - 提取规则：
     - 指定 key=EXPR 或 -k EXPR → 提取表达式值作为键（EXPR不能使用数组，只支持数值）
     - 未指定 → 默认使用线程ID(tid)
     - 不允许混合情况：部分事件指定key，部分未指定
   - `(key, name)` 组合作为行的唯一标识：
     - `(0, name)`: 启用--only-comm，隐藏键列，name作为唯一标识
     - `(key, NULL)`: 未启用--only-comm，key作为唯一标识
   - 显示标题：key=EXPR → 表达式大写字母；否则 → "PID"

2. **值(values) - 值列**
   - 作用：每列的累计统计值
   - 更新规则：
     - 指定 top-by=EXPR → 增加值列，优先排序
     - 指定 top-add=EXPR → 增加值列，默认排序
     - 未指定 → 对事件计数(每次+1)
   - 排序优先级：top-by列 > top-add列 + 默认值列
   - 显示标题：alias属性大写字母或EXPR表达式大写字母

3. **键名(name) - 名列**
   - 作用：键的可读名称，显示在行末
   - 更新规则：
     - 指定 comm=EXPR → 提取comm表达式值（必须返回`char *`类型）
     - 未指定 → common_pid获取进程名
   - 显示标题：首个comm属性大写字母或"COMM"字符串

### 统计与聚合
对每个采样的事件：
1. 提取事件对应的 `key`, `values`, `name`
2. 按(key, name)为索引在统计矩阵内查找对应的行（未找到则新建）
3. 把`values`累加到对应的值列

### 状态统计
- **信号处理**: SIGWINCH - 随终端窗口尺寸变化调整显示

## 输出

### 输出格式

```
perf-prof - HH:MM:SS  sample N events
键显示标题 value1标题   value2标题 ... 键名标题
key值     value1累计值 value2累计值 ... name值
```

### 关键指标

| 指标 | 计算方法 | 异常阈值 |
|------|----------|----------|
| 事件计数 | 默认值列累加 | 根据场景判断 |
| 字段累计值 | top-by/top-add表达式累加 | 根据场景判断 |
| 采样事件数 | 标题行sample N events | 过高可能导致丢事件 |

### 输出配置

**1. 键列显示**
- 默认显示：显示key的数值
- printkey定制：使用 `printkey=EXPR` 属性定制输出格式
- 隐藏键列：使用 `--only-comm` 选项

**2. 键名列显示**
- 有key属性但无comm属性：不显示该列
- 无key属性：自动显示对应的进程名
- comm属性：使用事件字段或表达式计算键名
  - ksymbol函数：将函数地址转换为符号名
  - comm_get函数：获取进程名

**3. 值列显示**
- 每列显示累计统计值
- 按排序优先级组织显示顺序

### 决策指南

**选择printkey还是键名列？**

1. **使用printkey的场景**:
   - key是复合键（如：`_cpu*1000+vector`）
   - 需要分解多个维度显示
   - 需要自定义格式化输出

2. **使用键名列的场景**:
   - key是单维度（如：PID、IRQ号）
   - 需要显示key的可读名称
   - key有明确的含义映射（如：PID→进程名）

## 应用示例

### 基础示例
```bash
# 1. 统计每个中断的次数和名称
perf-prof top -e irq:irq_handler_entry//key=irq/comm=name/

# 2. 统计每个pid的sched_wakeup次数
perf-prof top -e sched:sched_wakeup//key=pid/

# 3. 默认key为线程pid，累加runtime字段值
perf-prof top -e sched:sched_stat_runtime//top-by=runtime/

# 4. 按退出原因统计虚拟化退出次数
perf-prof top -e kvm:kvm_exit//key=exit_reason/ -i 1000

# 5. 统计可执行程序的执行次数
perf-prof top -e 'sched:sched_process_exec//key=pid/alias=num/comm=filename/' --only-comm

# 6. 按网络协议统计网络丢包的函数
perf-prof top -e 'skb:kfree_skb//key=protocol/comm=ksymbol(location)/' -m 32

# 7. 统计可执行程序的执行次数
perf-prof top -e 'sched:sched_process_exec//key=pid/alias=num/comm=filename/' --only-comm
```

### 高级技巧
```bash
# 使用printkey显示复合键
perf-prof top -e 'irq:softirq_entry//key=(_cpu<<32)|vec/printkey=printf("  %03d      %d",key>>32,(int)key)/'

# 使用用户态过滤器过滤Python进程
perf-prof top -e 'sched:sched_wakeup/comm_get(_pid) ~ "python*"/key=pid/' -i 1000

# 过滤特定CPU上的调度事件
perf-prof top -e 'sched:sched_switch/_cpu<4/key=prev_pid/comm=prev_comm/' -i 1000
```

### 性能优化
```bash
# 按comm统计进程唤醒次数（减少键数量）
perf-prof top -e sched:sched_wakeup//comm=comm/ --only-comm -m 64

# 按comm统计进程IO
perf-prof top -e block:block_rq_issue//top-by=nr_sector/comm=comm/ --only-comm -m 32

# 过滤写IO且是小IO
perf-prof top -e 'block:block_rq_issue/rwbs=="W"&&nr_sector<4/top-by=nr_sector/comm=comm/' --only-comm -i 1000
```

### 组合使用
```bash
# 统计进程的执行时间和进程切换次数
perf-prof top -e sched:sched_stat_runtime//key=pid/top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/

# 按进程名统计进程的执行时间和进程切换次数
perf-prof top -e sched:sched_stat_runtime//key=pid/comm=comm/top-by=runtime/,sched:sched_switch//key=prev_pid/comm=prev_comm/ --only-comm
```

## 真实案例

**目标**：分析每个进程的切换次数及运行时间，按运行时间排序显示。

### 选定待分析的事件
- `sched:sched_switch`事件：累计进程切换次数
- `sched:sched_stat_runtime`事件：累计进程运行时间

查看事件字段：
```bash
perf-prof top -e sched:sched_switch,sched:sched_stat_runtime help
```

### 选定键
选定2个事件都具有pid含义的字段作为key：
- `sched:sched_switch`事件：key=prev_pid
- `sched:sched_stat_runtime`事件：key=pid

### 选定值
- `sched:sched_switch`事件：默认值，对事件计数
- `sched:sched_stat_runtime`事件：top-by=runtime，累计运行时间并排序

### 选定键名
键值表示进程id，使用comm属性关联进程名：
- 加到任一事件：comm=prev_comm 或 comm=comm

### 最终命令
```bash
perf-prof top -e sched:sched_switch//key=prev_pid/comm=prev_comm/,sched:sched_stat_runtime//key=pid/top-by=runtime/ -i 1000

# 输出示例
2025-10-29 19:50:25.067825 perf-prof - 19:50:25  sample 9022 events
PREV_PID SCHED_SWITCH      RUNTIME PREV_COMM
    2831          933     12801931 sap1008
   32729          102      6203671 barad_agent
    6476          189      4759857 main
```

## 相关资源
- [perf-prof 表达式文档](expr.md)
- [trace event过滤器语法](Event_filtering.md)
