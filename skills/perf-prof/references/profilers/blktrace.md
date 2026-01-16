# blktrace - 块设备IO延迟跟踪
跟踪块设备上的IO延迟，分析从IO请求创建到完成的整个生命周期。

## 概述
- **主要用途**: 跟踪和统计块设备上的IO延迟，精确测量IO请求在不同阶段的耗时。通过四个关键tracepoint（block_getrq、block_rq_insert、block_rq_issue、block_rq_complete）追踪IO请求的完整生命周期。
- **适用场景**: 磁盘IO性能分析、存储子系统瓶颈定位、IO延迟排查、异常慢IO诊断
- **功能分类**: 内建事件类，I/O性能分析，延迟分析
- **最低内核版本**: 需要支持perf_event和trace event
- **平台支持**: 所有支持perf_event的Linux架构
- **特殊限制**:
  - 需要root权限
  - 只能监控实际物理设备或分区
- **参与联合分析**: 不参与

## 基础用法
```bash
perf-prof blktrace -d device [--than ns] [-i ms]
```

### OPTION
- `-m, --mmap-pages`: 默认为8页，高IOPS设备建议增加到64-128页
- `-i, --interval`: 默认为1000毫秒
- `--order`: 默认已启用，按时间戳排序事件

### FILTER OPTION
- 内建过滤器：自动根据设备和分区范围生成过滤器（`dev==N [&& sector>=start && sector<=end]`）

### PROFILER OPTION
- `-d, --device <device>`: **必需**。指定要监控的块设备，格式为`/dev/sdx`或`/dev/nvmeXnYpZ`
- `--than <n>`: 设置延迟阈值，统计并高亮显示超过该值的请求。单位：s/ms/us/*ns（默认ns）

## 核心原理

### 数据模型
```
IO请求创建 → [跟踪] → 插入队列 → [排队延迟] → 下发硬件 → [设备延迟] → 完成
   ↓           ↓        ↓          ↓          ↓           ↓        ↓
getrq  →  红黑树索引 → insert  →  统计延迟  →  issue  →  统计延迟 → complete
```

事件 → 设备过滤器 → 排序 → 红黑树跟踪 → 延迟统计 → 间隔输出

### 事件源
- **内建事件**:
  - `block:block_getrq`: IO请求创建，字段：dev, sector, nr_sector
  - `block:block_rq_insert`: IO请求插入队列，字段：dev, sector, nr_sector
  - `block:block_rq_issue`: IO请求下发硬件，字段：dev, sector, nr_sector
  - `block:block_rq_complete`: IO请求完成，字段：dev, sector, nr_sector, bytes

### 过滤器层次
1. **设备过滤器（内核态）**: 自动生成
   - 整盘设备：`dev==N`
   - 分区设备：`dev==N && sector>=start && sector<=end`

2. **特殊请求过滤**: flush请求（sector == -1）自动跳过

### 事件处理
- **排序依赖**: 默认启用排序（`order = true`），保证多CPU采样时事件按时间戳顺序处理
- **丢事件处理**:
  1. 检测LOST事件，记录丢失时间范围
  2. 清空红黑树中的所有请求跟踪状态
  3. 等待时间超过丢失范围后重新开始正常跟踪

- **请求跟踪机制**:
  - 使用`(dev, sector, nr_sector)`作为键在红黑树中跟踪IO请求
  - 状态转换：getrq → insert → issue → complete
  - 异常状态标记：EXIST（重复getrq）、BYPASS_INSERT（跳过insert）、LOST（状态丢失）、GREATER_THAN（延迟超阈值）

## 输出

### 输出格式

**周期统计输出（默认）**:
```
[时间戳]

       start => end              reqs       total(us)      min(us)      avg(us)      max(us)  than(reqs)
-------------- -------------- -------- ---------------- ------------ ------------ ------------ ------------
  block_getrq => block_rq_insert     142          512.345        0.123        3.608       45.234    5 ( 3%)
block_rq_insert => block_rq_issue     142         2145.678        1.234       15.112      234.567   12 ( 8%)
 block_rq_issue => block_rq_complete  142        45678.901       45.678      321.683    12345.678   45 (31%)
```

**详细输出（`-v`参数）**:
```
实时打印每个事件的详细信息，包括异常状态标记和超阈值请求（红色高亮）
```

### 输出字段
| 字段 | 说明 |
|------|------|
| start => end | IO请求的起始状态和结束状态 |
| reqs | 统计周期内完成该阶段的请求数量 |
| total(us) | 该阶段所有请求的总耗时（微秒，`--tsc`时为kcyc） |
| min(us) | 最小延迟 |
| avg(us) | 平均延迟 |
| max(us) | 最大延迟 |
| than(reqs) | 超过阈值的请求数及百分比（仅`--than`时显示） |

### 关键指标

| 指标 | 计算方法 | 异常阈值 |
|------|----------|----------|
| getrq→insert延迟 | insert时间戳 - getrq时间戳 | > 100us（锁竞争或内存分配延迟） |
| insert→issue延迟 | issue时间戳 - insert时间戳 | > 10ms（队列过长或调度策略不当） |
| issue→complete延迟 | complete时间戳 - issue时间戳 | SSD: > 10ms，HDD: > 100ms |
| than百分比 | (超阈值请求数 / 总请求数) × 100% | > 5%（持续性能问题） |

**正常范围参考**:
- getrq→insert: < 10us（软件操作）
- insert→issue: < 1ms（SSD）或 < 5ms（HDD）
- issue→complete: < 1ms（SSD）或 < 15ms（HDD）
- than百分比: < 1%

## 应用示例

### 基础示例
```bash
# 1. 基础监控：每秒输出设备的IO延迟统计
perf-prof blktrace -d /dev/sda -i 1000

# 2. 慢IO检测：监控超过10ms的IO请求
perf-prof blktrace -d /dev/sda -i 1000 --than 10ms

# 3. 分区监控：只监控特定分区的IO
perf-prof blktrace -d /dev/sda1 -i 500 --than 5ms

# 4. NVMe设备监控：使用更严格的阈值
perf-prof blktrace -d /dev/nvme0n1 -i 1000 --than 1ms

# 5. 详细调试：实时查看所有慢IO事件
perf-prof blktrace -d /dev/sda -i 1000 --than 10ms -v
```

### 高级技巧
```bash
# 高频监控：捕捉瞬时波动，增大缓冲区防丢事件
perf-prof blktrace -d /dev/sda -i 100 -m 128

# 捕捉特定时间段的慢IO（运行10秒后退出）
timeout 10s perf-prof blktrace -d /dev/sda -i 1000 --than 20ms -v > slow_io.log
```

### 性能优化
```bash
# 高IOPS设备：使用更大缓冲区防止事件丢失
perf-prof blktrace -d /dev/nvme0n1 -i 1000 -m 128

# 长期监控：增大间隔减少输出量
perf-prof blktrace -d /dev/sda -i 5000 --than 50ms
```

### 组合使用
```bash
# 与 iostat 配合：宏观+微观视角
iostat -x 1 &                                          # 宏观：IOPS、带宽、%util
perf-prof blktrace -d /dev/sda -i 1000 --than 10ms     # 微观：每阶段精确延迟

# 与 top 配合：定位产生慢IO的进程
perf-prof blktrace -d /dev/sda -i 1000 --than 10ms     # 阶段1：确认有慢IO
perf-prof top -e block:block_getrq//key=_pid/ -i 1000  # 阶段2：定位进程
```

## 相关资源
- [trace分析器文档](trace.md)
- [top分析器文档](top.md)
