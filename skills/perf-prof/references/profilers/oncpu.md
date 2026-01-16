# oncpu - CPU运行进程监控
实时监控在CPU上运行的进程及其运行时间统计。

## 概述
- **主要用途**: 监控每个CPU上运行的进程及其运行时间，分析CPU资源在不同进程之间的分配情况。支持两种监控模式：按CPU监控进程（cpu-to-tidmap）和按进程监控CPU（tid-to-cpumap）。
- **适用场景**: CPU资源竞争分析、进程调度行为观察、实时任务监控、多线程负载均衡分析、CPU亲和性验证
- **功能分类**: 内建事件类，CPU性能分析，状态监控
- **最低内核版本**: 需要支持perf_event和sched tracepoint
- **平台支持**: 所有支持perf_event的Linux架构
- **特殊限制**:
  - 需要root权限
  - cpu-to-tidmap模式自动过滤swapper进程（tid=0）
- **参与联合分析**: 不参与

## 基础用法
```bash
perf-prof oncpu [OPTION...] [--detail] [--filter filter] [--only-comm] [--prio n]
```

### OPTION
- `-C, --cpus <cpu[-cpu],...>`: 监控指定的CPU列表，触发cpu-to-tidmap模式
- `-p, --pids <pid,...>`: Attach到指定进程，触发tid-to-cpumap模式
- `-t, --tids <tid,...>`: Attach到指定线程，触发tid-to-cpumap模式
- `-i, --interval <ms>`: 统计输出间隔，默认1000毫秒
- `-m, --mmap-pages <pages>`: mmap缓冲区页数，默认4页

### FILTER OPTION
- `--filter <filter>`: 事件过滤器，适用于tracepoint事件（与--prio互斥）
- `--prio <prio[-prio],...>`: 指定监控的优先级范围（仅cpu-to-tidmap模式）

### PROFILER OPTION
- `--detail`: 输出更详细的信息，包括切换次数(sws)和最大运行时间(max_ms)
- `--only-comm`: 只显示进程名（comm），不显示线程ID（tid）

## 核心原理

### 数据模型
```
tid-to-cpumap模式: sched_stat_runtime事件 → 红黑树聚合[thread][cpu] → 运行时间统计
cpu-to-tidmap模式: sched_switch事件 → 计算切换间隔 → 红黑树聚合[cpu][tid/comm] → 按运行时间排序
```

### 事件源
- **tid-to-cpumap模式（-p/-t参数）**: `sched:sched_stat_runtime`
  - 关键字段: `comm`, `pid`, `runtime`, `vruntime`
  - 触发时机: 进程运行时间片结束或被抢占时
- **cpu-to-tidmap模式（-C参数）**: `sched:sched_switch`
  - 关键字段: `prev_comm`, `prev_pid`, `prev_prio`, `next_comm`, `next_pid`, `next_prio`
  - 触发时机: 每次进程切换时

### 过滤器层次
1. **trace event过滤器（内核态）**: `--filter`手动指定或`--prio`自动生成
2. **优先级过滤器（仅cpu-to-tidmap）**: `--prio 1-99`生成`(prev_prio>=1 && prev_prio<=99) || (next_prio>=1 && next_prio<=99)`

### 事件处理
- **排序依赖**: 无排序依赖
- **丢事件处理**: cpu-to-tidmap模式下，丢事件后重置switch_time状态，从下次切换重新开始统计

## 输出

### 输出格式

**tid-to-cpumap模式（-p/-t参数）**:
```
[时间戳]

THREAD COMM             SUM(ms) CPUS(ms)
------ ---------------- ------- ---------
2347   my_process       1234    0(123ms) 2(234ms) 4(567ms) 8(310ms)
```

**cpu-to-tidmap模式（-C参数，不带--detail）**:
```
[时间戳]

CPU SUM(ms) COMM:TID(ms)
--- ------- --------------------------------------------
000 956     systemd:1(12.3) kworker/0:1(45.6) sshd:1234(898.1)
001 1024    nginx:5678(512.4) nginx:5679(511.6)
```

**cpu-to-tidmap模式（-C参数，带--detail）**:
```
[时间戳]

CPU SUM(ms/sws) COMM:TID(ms/sws/max_ms)
--- ----------- ---------------------------------------------------------
000 956ms/142   systemd:1(12.3ms/23/1.2ms) kworker/0:1(45.6ms/67/5.3ms)
001 1024ms/98   nginx:5678(512.4ms/49/35.2ms) nginx:5679(511.6ms/49/34.8ms)
```

### 输出字段
| 字段 | 说明 |
|------|------|
| THREAD | 线程ID |
| COMM | 进程/线程名称 |
| SUM(ms) | 在所有CPU上的总运行时间（毫秒） |
| CPUS(ms) | 在每个CPU上的运行时间，格式为`cpu(ms)` |
| CPU | CPU编号 |
| COMM:TID(ms) | 进程名:线程ID(运行时间)，按运行时间降序排列 |
| sws | 切换次数（仅--detail） |
| max_ms | 最大连续运行时间（仅--detail） |

### 关键指标

| 指标 | 计算方法 | 异常阈值 |
|------|----------|----------|
| SUM(ms) | 所有进程/CPU的runtime之和 | 远小于interval：CPU利用率低；远大于interval：多核正常 |
| COMM:TID(ms) | sched_stat_runtime.runtime或sched_switch时间差累加 | 某进程长期占用>80% CPU时间 |
| sws | 进程被调度到CPU的次数 | >1000/秒：可能有锁竞争；<1/秒：可能长时间运行 |
| max_ms | 单次运行的最大时间片 | 普通进程>100ms：可能禁用了抢占 |

## 应用示例

### 基础示例
```bash
# 1. 监控指定进程的CPU使用情况（tid-to-cpumap模式）
perf-prof oncpu -p 2347                         # 分析进程在各CPU上的分布
perf-prof oncpu -p $(pidof nginx)               # 监控nginx进程

# 2. 监控指定CPU上运行的进程（cpu-to-tidmap模式）
perf-prof oncpu -C 0-3                          # 监控CPU 0-3
perf-prof oncpu -C 0-3 --detail                 # 包含切换次数和最大运行时间

# 3. 监控实时优先级进程
perf-prof oncpu --prio 1-99                     # 只监控实时优先级（1-99）
perf-prof oncpu --prio 100-139                  # 只监控普通优先级
```

### 高级技巧
```bash
# CPU亲和性验证：检查进程是否按预期绑定到CPU
perf-prof oncpu -p 2347 -i 1000
# 预期输出：只在绑定的CPU上有运行时间

# 负载均衡分析：查看多个CPU的负载分布
perf-prof oncpu -C 0-15 --only-comm -i 1000 | grep -E "CPU|nginx"

# 调度延迟分析：结合--detail查看最大连续运行时间
perf-prof oncpu -C 0-3 --detail -i 1000
# max_ms > 50ms 表示可能有调度延迟问题
```

### 性能优化
```bash
# 高负载系统增加缓冲区
perf-prof oncpu -C 0-3 -m 16 -i 1000

# 长期监控减少输出量
perf-prof oncpu -C 0-7 --only-comm -i 5000

# 精确监控特定进程减少开销
perf-prof oncpu -p <pid> -i 1000
```

### 组合使用
```bash
# 与 profile 配合：先找CPU占用高的进程，再分析热点函数
perf-prof oncpu -C 0-3 -i 1000 --only-comm      # 找出CPU占用高的进程
perf-prof profile -p <pid> -F 997 -g --flame-graph cpu.folded

# 与 task-state 配合：判断进程是CPU密集型还是IO密集型
perf-prof oncpu -p 2347 -i 1000 --detail        # 运行时间统计
perf-prof task-state -p 2347 -i 1000            # 状态分布（R/S/D）

# 多阶段分析
mpstat -P ALL 1 10                              # 阶段1：找出CPU利用率高的CPU
perf-prof oncpu -C <cpu> -i 1000 --only-comm    # 阶段2：找出该CPU上占用最多的进程
perf-prof profile -p <pid> -F 997 -g            # 阶段3：分析热点函数
```

## 相关资源
- [profile分析器文档](profile.md)
- [task-state分析器文档](task-state.md)
- [top分析器文档](top.md)
