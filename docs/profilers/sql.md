# sql - SQL聚合分析

将采样事件存储为SQL表并执行聚合查询分析。

## 概述
- **主要用途**: 将采样的事件存储到SQLite数据库表中，通过SQL查询语句对事件数据进行聚合分析、统计计算、多维度数据透视等复杂分析操作。
- **适用场景**: 需要对大量事件进行复杂的统计分析（如分组计数、聚合计算、多表关联）、需要灵活的数据查询和分析、需要持久化事件数据以供后续分析等场景。
- **功能分类**:
  - 按事件依赖程度：**自定义事件类** - 需要用户通过 `-e` 指定事件
  - 按功能领域：**数据分析与工具** - 通用事件数据分析工具
  - 按分析技术：**聚合分析** - 支持事件统计和数据挖掘
- **最低内核版本**: 需要内核支持 perf_event 子系统 (Linux 2.6.31+)
- **依赖库**:
  - libsqlite3 (SQLite数据库引擎，支持3.3.9+版本，推荐3.20.0+)
  - libtraceevent (事件解析)
  - libelf (符号解析)
- **平台支持**: x86, ARM, ARM64, RISC-V, PowerPC 等主流架构
- **特殊限制**:
  - 需要 root 权限或 CAP_PERFMON 能力
  - 必须指定 `--query` 或 `--output2` 之一（或同时指定）
  - 使用 `--query` 时如无 `--output2`，必须指定 `-i` 周期间隔
- **参与联合分析**: 不参与联合分析，作为独立的数据分析工具使用
- **核心技术**:
  - SQLite嵌入式数据库
  - 事件字段自动映射为SQL列
  - 事务批处理优化
  - 内存数据库与文件数据库双模式
  - 预编译SQL语句复用

## 基础用法
```bash
perf-prof sql -e EVENT [--query 'SQL_STATEMENT'] [--output2 DB_FILE] [-i INT]
```

OPTION:
- `-i, --interval <ms>` - 间隔输出，周期性执行SQL查询并清理数据 (默认：无间隔，仅在退出时执行一次)
- `--order` - 按时间戳排序事件后再插入数据库（通常不需要）
- `-m, --mmap-pages <pages>` - 环形缓冲区大小，默认8页，高频事件可增大

PROFILER OPTION:
- `-e, --event <EVENT,...>` - 事件选择器，事件名称作为SQL表名（必需）
  - 支持 `alias=` 属性指定表别名：`-e 'event//alias=table_name/'`
  - 有多个相同事件时必须使用别名区分
  - 示例：`-e 'sched:sched_wakeup//alias=wakeup1/',sched:sched_wakeup//alias=wakeup2/'`

- `--query <SQL>` - 执行的SQL查询语句，支持多条语句用 `;` 分隔
  - 查询语句将在周期间隔（`-i`）或程序退出时执行
  - 查询完成后会清空表数据（内存模式）或重建表（文件模式）
  - 支持标准SQL语法：SELECT, GROUP BY, ORDER BY, JOIN等

- `--output2 <file>` - 指定SQLite数据库文件路径
  - 未指定时使用内存数据库（`:memory:`）
  - 文件数据库可持久化数据，供后续分析
  - 文件数据库性能优化更激进（128MB缓存，512MB内存映射）

### 使用场景矩阵

| `-i` | `--query` | `--output2` | 行为说明 |
|------|-----------|-------------|---------|
| ✗ | ✗ | ✗ | **禁止** - 事件存储在内存中但从不使用 |
| ✗ | ✗ | ✓ | 事件持续保存到数据库文件（无查询） |
| ✗ | ✓ | ✗ | **禁止** - 内存累积直到程序退出 |
| ✗ | ✓ | ✓ | 程序退出时执行查询（数据持久化） |
| ✓ | ✗ | ✗ | **禁止** - 周期性无操作 |
| ✓ | ✗ | ✓ | 周期性保存事件到数据库文件 |
| ✓ | ✓ | ✗ | **推荐** - 周期性查询，内存清空 |
| ✓ | ✓ | ✓ | 周期性查询，表重建（适合长期监控） |

### 示例
```bash
# 统计每个进程的唤醒次数，按次数降序排列
perf-prof sql -e sched:sched_wakeup -i 1000 \
  --query 'SELECT comm, COUNT(*) as count FROM sched_wakeup GROUP BY comm ORDER BY count DESC'

# 多事件联合查询
perf-prof sql -e sched:sched_wakeup,sched:sched_switch -i 1000 \
  --query 'SELECT * FROM sched_wakeup WHERE pid > 1000'

# 保存事件到文件供后续分析
perf-prof sql -e sched:sched_wakeup --output2 events.db -i 10000

# 多条查询语句（用分号分隔）
perf-prof sql -e sched:sched_wakeup -i 1000 \
  --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm; SELECT AVG(prio) FROM sched_wakeup'

# 使用过滤器和事件字段
perf-prof sql -e 'sched:sched_wakeup/prio<10/' -i 1000 \
  --query 'SELECT target_cpu, COUNT(*) FROM sched_wakeup GROUP BY target_cpu'

# 使用别名区分多个相同事件（不同过滤条件）
perf-prof sql -e 'sched:sched_wakeup/prio<10/alias=high_prio/,sched:sched_wakeup/prio>=10/alias=low_prio/' -i 1000 \
  --query 'SELECT "high_prio" as type, COUNT(*) FROM high_prio UNION SELECT "low_prio", COUNT(*) FROM low_prio'
```

## 核心原理

**基本定义**

- **事件映射**: 每个事件自动映射为一张SQL表，表名为事件名（如 `sched_wakeup`）
  - 支持通过 `alias=` 属性指定表别名
  - 有别名时使用别名作为表名，否则使用事件名
  - 多个相同事件必须使用不同别名区分
- **字段映射**: 事件的所有字段自动映射为表的列
  - 数值字段 → INTEGER 类型
  - 字符串字段 → TEXT 类型
  - 数组字段 → BLOB 类型
- **系统列**: 每张表包含固定的系统列
  - `_pid`: 进程ID
  - `_tid`: 线程ID
  - `_time`: 事件时间戳
  - `_cpu`: CPU编号
  - `_period`: 采样周期
  - `common_flags`, `common_preempt_count`, `common_pid`: trace event通用字段
- **元数据表**: 自动创建 `event_metadata` 表存储事件元信息
  - `table_name`: 事件表名（主键）
  - `event_system`: 事件系统（如 sched）
  - `event_name`: 事件名称（如 sched_wakeup）
  - `event_id`: 事件ID（对应事件 common_type 字段）
  - `filter_expression`: 过滤器表达式
  - `has_stack`: 是否启用堆栈
  - `max_stack`: 最大堆栈深度
  - `field_count`: 字段总数
  - `created_time`: 表创建时间（Unix时间戳，秒）
  - `sample_count`: 采样总数
  - `first_sample_time`: 首次采样时间（perf时间戳，纳秒，非Unix时间）
  - `last_sample_time`: 最后采样时间（perf时间戳，纳秒，非Unix时间）
  - `function_list`: 该事件可用的SQL内置函数列表（逗号分隔），例如: `"symbolic('softirq_entry.vec', vec)"`

**数据模型**
```
事件采样 → [过滤器] → 批量插入SQL表 → [周期间隔] → 执行SQL查询 → 清空表
```

### 事件源

- **sample_type**:
  - `PERF_SAMPLE_TID`: 采集进程和线程ID
  - `PERF_SAMPLE_TIME`: 采集事件时间戳
  - `PERF_SAMPLE_ID`: 事件ID用于区分不同事件
  - `PERF_SAMPLE_CPU`: 采集CPU编号
  - `PERF_SAMPLE_PERIOD`: 采集周期
  - `PERF_SAMPLE_RAW`: 采集原始trace事件数据

- **自定义事件**: 通过 `-e` 选项指定
  - 支持所有tracepoint事件: `sys:name`
  - 支持通配符: `sched:*`, `irq:irq_*`
  - 支持kprobe/uprobe: `kprobe:function`, `uprobe:func@"file"`
  - **过滤器**: 支持trace event过滤器语法，在内核态过滤事件
    - 示例: `-e 'sched:sched_wakeup/pid>1000 && prio<10/'`
    - trace event过滤器失败时在用户态执行过滤
  - **属性**:
    - `alias=name`: 设置表别名（默认使用事件名）

### 事件处理

**表结构创建**
1. 程序启动时自动分析事件结构
2. 通过 `tep_event_fields()` 获取所有字段定义
3. 根据字段类型（数值/字符串/数组）生成CREATE TABLE语句
4. 预编译INSERT语句并持久化复用

**数据插入流程**
1. 接收到perf事件样本
2. 解析样本数据，提取系统字段和事件字段
3. 绑定参数到预编译语句（零拷贝绑定）
4. 执行INSERT语句
5. 批量提交优化（见性能优化章节）

**查询执行与清理**
1. 到达周期间隔或程序退出时触发
2. 提交未完成的事务
3. 执行用户指定的SQL查询语句
4. 输出查询结果（表格格式，自适应列宽）
5. 清理数据:
   - 内存数据库：DROP TABLE + CREATE TABLE
   - 文件数据库：DROP TABLE + CREATE TABLE（保留在文件中）

**性能优化策略**
- **事务批处理**:
  - 内存数据库：5000条插入/事务
  - 文件数据库：2000条插入/事务
- **预编译语句**: INSERT语句预编译并标记为PERSISTENT复用
- **零拷贝绑定**: 字符串和BLOB使用SQLITE_STATIC标志，避免数据拷贝
- **无排序依赖**: 事件按到达顺序直接插入，无需排序

### 参数调优

**SQLite PRAGMA优化**:
- `page_size = 65536`: 64KB大页面，减少页面切换
- `journal_mode = OFF`: 关闭日志，最大化写入速度
- `synchronous = OFF`: 关闭同步写入，不等待fsync
- `locking_mode = EXCLUSIVE`: 独占锁，避免锁竞争
- `cache_size`: 内存数据库64MB，文件数据库128MB
- `mmap_size = 512MB`: 文件数据库启用内存映射I/O

### 状态统计
- **信号处理**
  - SIGUSR1: 无特殊处理
  - SIGUSR2: 无特殊处理
- **统计信息**
  - Total Inserts: 总插入事件数
  - Total Commits: 总事务提交次数

## SQL 内置函数

### symbolic() - 符号转换函数

**功能**: 将事件字段的数值转换为对应的符号字符串，基于内核 `__print_symbolic()` 宏定义。

**语法**:
```sql
symbolic('field_name', field_value)
symbolic('table_name.field_name', field_value)
```

**参数**:
- `field_name`: 字段名称（支持所有表）
- `table_name.field_name`: 完整字段名（指定特定表）
- `field_value`: 需要转换的数值

**返回值**:
- 成功：返回对应的符号字符串
- 失败：返回 `"UNKNOWN"`

**工作原理**:
1. 启动时自动解析事件的 `print_fmt` 格式定义
2. 提取 `__print_symbolic()` 宏中的值到字符串映射
3. 构建内存查找表（红黑树）：`(event_id, field_offset, value) -> string`
4. SQL 查询时实时转换数值为符号字符串

**支持的事件类型**:
- ✅ 简单字段引用：`__print_symbolic(REC->vec, {0, "HI"}, {1, "TIMER"}, ...)`
- ✅ 条件表达式（KVM）：`(REC->isa == 1) ? __print_symbolic(...) : __print_symbolic(...)`
- ❌ 复杂表达式：`__print_symbolic((REC->dm >> 8 & 0x7), ...)` （不支持）
- ⚠️  每个事件的每个字段只能有一个 `__print_symbolic` 定义

**使用示例**:

```bash
# 将软中断向量号转换为名称
perf-prof sql -e irq:softirq_entry -i 1000 \
  --query "SELECT symbolic('vec', vec) as irq_name, COUNT(*) as count
           FROM softirq_entry
           GROUP BY vec
           ORDER BY count DESC"

# 输出示例:
# irq_name  | count
# ----------|-------
# NET_RX    | 15234
# TIMER     | 8901

# 将 KVM 退出原因转换为字符串（自动检测 Intel/AMD）
perf-prof sql -e kvm:kvm_exit -i 1000 \
  --query "SELECT symbolic('exit_reason', exit_reason) as reason,
                  COUNT(*) as exits
           FROM kvm_exit
           GROUP BY exit_reason
           ORDER BY exits DESC
           LIMIT 10"

# 输出示例（Intel VMX）:
# reason              | exits
# --------------------|--------
# EXTERNAL_INTERRUPT  | 45623
# IO_INSTRUCTION      | 8934
# CPUID               | 5432

# 使用表名前缀（多表场景）
perf-prof sql -e irq:softirq_entry,irq:softirq_exit -i 1000 \
  --query "SELECT symbolic('softirq_entry.vec', e.vec) as irq_name,
                  COUNT(*) as enter_count
           FROM softirq_entry e
           GROUP BY e.vec"
```

**注意事项**:
1. **自动注册**：只有包含 `__print_symbolic` 的事件才会注册该函数
2. **性能**：查找使用红黑树，时间复杂度 O(log n)，适合高频查询
3. **内存**：符号字符串不复制，直接引用内核 TEP 数据结构
4. **平台差异**：KVM 事件会根据 CPU vendor（Intel/AMD/Hygon）自动选择正确的符号表

**错误处理**:
```sql
-- 字段不存在或没有符号定义
SELECT symbolic("non_existent_field", 123)  -- 返回 "UNKNOWN"

-- 值没有对应的符号
SELECT symbolic("vec", 999)  -- 返回 "UNKNOWN"

-- 参数错误
SELECT symbolic("vec")  -- 错误：需要2个参数
SELECT symbolic(123, 456)  -- 错误：第一个参数必须是字符串
```


## SQLite版本兼容性

perf-prof sql支持新旧两个版本的SQLite库，自动适配不同的系统环境。

### 版本差异

**新版本 (sqlite3_prepare_v3)**:
- 支持 `SQLITE_PREPARE_PERSISTENT` 标志
- 预编译语句可复用，性能更好
- 查询语句自动解析多条SQL（通过pzTail参数）
- 推荐使用：SQLite 3.20.0+ (2017年8月发布)

**旧版本 (sqlite3_prepare_v2)**:
- 不支持 `SQLITE_PREPARE_PERSISTENT` 标志
- 预编译语句仍然可复用，但优化较少
- 同样支持多条SQL解析（通过pzTail参数）
- 兼容：SQLite 3.3.9+ (2006年8月发布)

### 自动检测机制

perf-prof在编译时自动检测SQLite版本：

```c
#if defined(SQLITE_PREPARE_PERSISTENT) && !defined(SQLITE_COMPAT)
#define USE_SQLITE_PREPARE_V3 1
#endif
```

**检测逻辑**:
1. 如果定义了 `SQLITE_PREPARE_PERSISTENT` 宏 → 使用 v3
2. 如果同时定义了 `SQLITE_COMPAT` 环境变量 → 强制使用 v2
3. 否则使用 v2 兼容模式

### 强制兼容模式

如果需要在新版本SQLite上强制使用v2接口（用于测试或兼容性验证）：

```bash
export CFLAGS=-DSQLITE_COMPAT
make
```

### 性能影响

**v3模式性能优势**:
- 预编译语句标记为PERSISTENT，SQLite可以进行更激进的内部优化
- 减少语句重新准备的开销


## 输出

### 输出格式

**查询结果表格**:
```
=== SQL查询语句 ===
column1  | column2  | column3
---------|----------|----------
value1   | value2   | value3
value1   | value2   | value3
```

- **表头**: 显示查询返回的列名
- **分隔符**: `|` 分隔各列，`-` 分隔表头和数据
- **列宽**: 自动调整，初始为列名长度，动态扩展以适应数据
- **数据格式**:
  - INTEGER: 左对齐十进制数
  - FLOAT: 左对齐，6位小数
  - TEXT: 左对齐字符串
  - BLOB: 显示为 `[BLOB:size]`
  - NULL: 显示为 `NULL`

**多查询输出**: 使用 `;` 分隔多条SQL语句时，每条查询单独输出一个表格

### 关键指标

SQL查询返回的指标完全由用户定义，常见的聚合函数包括：

- **COUNT(*)**: 事件总数
- **COUNT(DISTINCT field)**: 去重计数
- **SUM(field)**: 字段求和
- **AVG(field)**: 字段平均值
- **MIN(field)/MAX(field)**: 最小/最大值
- **GROUP BY**: 分组聚合

### 查询示例

```sql
-- 统计每个CPU上的事件数
SELECT _cpu, COUNT(*) FROM sched_wakeup GROUP BY _cpu

-- 计算平均优先级
SELECT AVG(prio) as avg_prio FROM sched_wakeup

-- 多维度分组统计
SELECT comm, target_cpu, COUNT(*) as count
FROM sched_wakeup
GROUP BY comm, target_cpu
ORDER BY count DESC

-- 时间范围查询（纳秒时间戳）
SELECT * FROM sched_wakeup
WHERE _time > 1000000000 AND _time < 2000000000

-- 多表关联（多事件）
SELECT w.comm, w.pid, COUNT(*)
FROM sched_wakeup w
JOIN sched_switch s ON w.pid = s.next_pid
GROUP BY w.comm, w.pid

-- 查询事件元数据信息
SELECT * FROM event_metadata

-- 关联元数据表查询事件ID和统计信息
SELECT m.event_system, m.event_name, m.event_id, m.sample_count
FROM event_metadata m
WHERE m.table_name = 'sched_wakeup'

-- 查询所有事件的采样统计
SELECT table_name, event_id, sample_count,
       (last_sample_time - first_sample_time) / 1000000000.0 as duration_sec
FROM event_metadata
ORDER BY sample_count DESC

-- 查询哪些事件支持内置函数
SELECT table_name, event_name, function_list
FROM event_metadata
WHERE function_list IS NOT NULL
```

## 分析方法

### 基础分析流程

1. **确定分析目标**: 明确需要统计什么指标（计数、平均值、分布等）
2. **选择事件**: 通过 `-e` 选择相关的事件
3. **设置过滤器**: 使用trace event过滤器减少数据量
4. **编写SQL查询**: 根据分析目标编写GROUP BY、聚合函数等
5. **设置间隔**: 使用 `-i` 设置合适的查询周期
6. **观察结果**: 分析输出的统计数据

### 数据驱动分析

**探索性分析**:
1. 查看事件元数据，了解可用函数
   ```sql
   SELECT table_name, function_list FROM event_metadata WHERE function_list IS NOT NULL
   ```
2. 用简单查询了解数据分布
   ```sql
   SELECT * FROM event_name LIMIT 10
   ```
3. 统计基本信息
   ```sql
   SELECT COUNT(*), MIN(field), MAX(field), AVG(field) FROM event_name
   ```
4. 识别热点
   ```sql
   SELECT field, COUNT(*) FROM event_name GROUP BY field ORDER BY COUNT(*) DESC
   ```

**渐进式过滤**:
1. 初步运行不加过滤器，观察整体情况
2. 根据查询结果识别关注点
3. 添加WHERE条件或trace event过滤器精确定位
4. 迭代优化查询语句

## 应用示例

### 基础统计分析

```bash
# 统计各进程的唤醒次数
perf-prof sql -e sched:sched_wakeup -i 1000 \
  --query 'SELECT comm, COUNT(*) as wakeups FROM sched_wakeup GROUP BY comm ORDER BY wakeups DESC LIMIT 10'

# 统计各CPU的事件分布
perf-prof sql -e sched:sched_switch -i 1000 \
  --query 'SELECT _cpu, COUNT(*) as switches FROM sched_switch GROUP BY _cpu'

# 计算平均运行时间
perf-prof sql -e sched:sched_stat_runtime -i 1000 \
  --query 'SELECT comm, AVG(runtime)/1000 as avg_us FROM sched_stat_runtime GROUP BY comm'
```

### 高级技巧

**多维度分组**:
```bash
# 按进程和优先级统计
perf-prof sql -e sched:sched_wakeup -i 1000 \
  --query 'SELECT comm, prio, COUNT(*) FROM sched_wakeup GROUP BY comm, prio ORDER BY COUNT(*) DESC'
```

**时间窗口分析**:
```bash
# 按时间窗口统计（需要计算时间窗口边界）
perf-prof sql -e sched:sched_wakeup -i 10000 \
  --query 'SELECT (_time/1000000000) as time_sec, COUNT(*) FROM sched_wakeup GROUP BY time_sec'
```

**多表关联**:
```bash
# 关联wakeup和switch事件
perf-prof sql -e sched:sched_wakeup,sched:sched_switch -i 1000 \
  --query 'SELECT w.comm, COUNT(DISTINCT w.pid) as processes
           FROM sched_wakeup w, sched_switch s
           WHERE w.pid = s.next_pid
           GROUP BY w.comm'
```

**使用别名对比不同条件**:
```bash
# 对比实时进程和普通进程的唤醒频率
perf-prof sql -e 'sched:sched_wakeup/prio<100/alias=rt_prio/,sched:sched_wakeup/prio>=100/alias=normal_prio/' -i 1000 \
  --query '
    SELECT "RT" as schedule_class, COUNT(*) as count
    FROM rt_prio
    GROUP BY schedule_class
    UNION ALL
    SELECT "NORMAL" as schedule_class, COUNT(*) as count
    FROM normal_prio
    GROUP BY schedule_class
    ORDER BY count DESC
    LIMIT 20'

# 对比不同CPU的事件分布
perf-prof sql -e 'sched:sched_switch/common_pid>0/cpus=0-3/alias=cpu_0_3/,sched:sched_switch/common_pid>0/cpus=4-7/alias=cpu_4_7/' -i 1000 \
  --query '
    SELECT "CPU 0-3" as cpu_group, COUNT(*) as switches FROM cpu_0_3
    UNION ALL
    SELECT "CPU 4-7" as cpu_group, COUNT(*) as switches FROM cpu_4_7'
```

**持久化数据供后续分析**:
```bash
# 先收集数据到文件
perf-prof sql -e sched:sched_wakeup --output2 wakeup.db -i 60000

# 后续使用sqlite3命令行工具分析
sqlite3 wakeup.db "SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm"
```

**使用元数据表分析**:
```bash
# 查询事件元数据信息
perf-prof sql -e sched:sched_wakeup,sched:sched_switch -i 1000 \
  --query 'SELECT table_name, event_id, sample_count FROM event_metadata'

# 关联元数据表查询事件详情
perf-prof sql -e sched:sched_wakeup -i 1000 \
  --query '
    SELECT m.event_system, m.event_name, m.event_id,
           w.comm, COUNT(*) as count
    FROM sched_wakeup w, event_metadata m
    WHERE m.table_name = "sched_wakeup"
    GROUP BY w.comm
    ORDER BY count DESC
    LIMIT 10'

# 查询事件采样时间跨度（perf时间，单位纳秒）
perf-prof sql -e sched:sched_wakeup --output2 wakeup.db -i 10000 \
  --query '
    SELECT table_name,
           first_sample_time,
           last_sample_time,
           (last_sample_time - first_sample_time) / 1000000000.0 as duration_sec,
           sample_count,
           sample_count / ((last_sample_time - first_sample_time) / 1000000000.0) as rate_per_sec
    FROM event_metadata'

# 查询事件可用的SQL内置函数
perf-prof sql -e irq:softirq_entry,sched:sched_wakeup -i 1000 \
  --query 'SELECT table_name, function_list FROM event_metadata WHERE function_list IS NOT NULL'

# 输出示例:
# table_name     | function_list
# ---------------|----------------------------------
# softirq_entry  | symbolic('softirq_entry.vec', vec)
```

**使用内置函数**:
```bash
# 查看事件的 print_fmt 定义（确认是否有 __print_symbolic）
perf-prof trace -e irq:softirq_entry help

# 验证 symbolic 函数是否可用
perf-prof sql -e irq:softirq_entry -i 1000 \
  --query 'SELECT vec, symbolic("vec", vec) FROM softirq_entry LIMIT 5'
```

### 性能优化

**缓冲区调优**:
- `-m` 参数: 高频事件（>100k/s）建议使用 `-m 64` 或更大
- 默认8页（32KB）适合中低频事件
- 避免事件丢失导致数据不完整

**事件过滤器优化**:
```bash
# 在内核态过滤，减少用户态处理开销
perf-prof sql -e 'sched:sched_wakeup/prio<10/' \
  --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm'

# 使用多个过滤条件
perf-prof sql -e 'sched:sched_wakeup/pid>1000 && target_cpu<4/' \
  --query 'SELECT comm, target_cpu, COUNT(*) FROM sched_wakeup GROUP BY comm, target_cpu'
```

**查询间隔调优**:
- 短间隔（`-i 1000`）: 实时监控，但查询开销较大
- 长间隔（`-i 10000`）: 减少查询开销，适合长期趋势分析
- 无间隔: 仅在程序结束时查询一次，适合一次性分析

**数据库模式选择**:
- 内存数据库（无`--output2`）:
  - 优点: 最快性能（5000条/批次）
  - 缺点: 数据不持久化，占用内存
  - 适用: 实时监控，周期性清空数据

- 文件数据库（有`--output2`）:
  - 优点: 数据持久化，可后续分析
  - 缺点: 稍慢（2000条/批次），占用磁盘
  - 适用: 需要保存原始数据，离线分析

### 组合使用

**与trace组合**:
```bash
# 先用trace探索事件字段
perf-prof trace -e sched:sched_wakeup -C 0 | head -20

# 再用sql进行统计分析
perf-prof sql -e sched:sched_wakeup -i 1000 \
  --query 'SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm'
```

**与list组合**:
```bash
# 先列出可用事件
perf-prof list | grep sched

# 选择合适的事件进行SQL分析
perf-prof sql -e sched:sched_wakeup,sched:sched_switch -i 1000 \
  --query 'SELECT * FROM sched_wakeup LIMIT 10'
```

**分阶段分析**:
1. 第一阶段：收集全量数据到文件
   ```bash
   perf-prof sql -e sched:* --output2 all_sched.db
   ```
2. 第二阶段：离线多角度查询分析
   ```bash
   sqlite3 all_sched.db
   sqlite> SELECT name FROM sqlite_master WHERE type='table';
   sqlite> SELECT * FROM sched_wakeup LIMIT 5;
   sqlite> SELECT comm, COUNT(*) FROM sched_wakeup GROUP BY comm;
   ```

## 相关资源
- [事件基础文档](../events/)
- [sample_type采样类型说明](../sample_type.md)
- [选项参数完整参考](../main_options.md)
- [trace事件过滤器语法](../Event_filtering.md)
- [表达式系统文档](../expr.md)
