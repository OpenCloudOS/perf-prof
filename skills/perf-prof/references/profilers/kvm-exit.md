# kvm-exit - KVM虚拟化退出延迟分析
KVM虚拟机退出(VM-Exit)到重新进入(VM-Entry)之间的延迟统计与分析。

## 概述
- **主要用途**: 监控并分析KVM虚拟机退出到重新进入之间的延迟，统计不同退出原因的延迟分布，识别虚拟化性能瓶颈
- **适用场景**: 虚拟机性能问题排查、虚拟化开销分析、特定VM-Exit事件的延迟监控、Guest性能优化
- **功能分类**: 内建事件类，虚拟化分析，延迟分析
- **最低内核版本**: 3.10+ (支持 kvm tracepoints)
- **平台支持**: x86 (Intel VMX/AMD SVM), ARM64
- **特殊限制**:
  - 需要root权限
  - 必须在Host端运行，不能在Guest内运行
  - 需要KVM模块加载
- **参与联合分析**: 不参与联合分析，独立分析器

## 基础用法
```bash
perf-prof kvm-exit -p <qemu-pid> -i 1000
```

### OPTION
- `-m, --mmap-pages`: 默认64页，高退出率场景可增大
- `-i, --interval`: 默认1000ms

### FILTER OPTION
- `--filter <filter>`: 事件过滤器，仅应用于kvm:kvm_exit事件（内核态执行）

### PROFILER OPTION
- `--perins`: 按实例统计，每个vcpu线程独立显示统计信息
- `--than <n>`: 输出大于指定阈值的事件，单位：s/ms/us/ns (默认ns)
- `--heatmap <file>`: 输出延迟热图数据到指定文件(自动添加.lat后缀)

## 核心原理

### 数据模型
```
kvm:kvm_exit → 线程配对 → kvm:kvm_entry → 延迟计算 → 按退出原因聚合 → 统计输出
```

### 事件源
- **内建事件**: `kvm:kvm_exit`（VM退出）和`kvm:kvm_entry`（VM进入）

### 过滤器层次
1. **trace event过滤器（内核态）**: `--filter` 选项，仅应用于kvm:kvm_exit

### 事件处理
- **配对机制**: 基于线程(vcpu)的exit/entry事件配对
- **排序依赖**: 无需`--order`，per-instance状态管理保证顺序
- **丢事件处理**: 标记instance缓存无效，等待下一个完整配对

### 关键概念
- **VM-Exit**: Guest执行特殊指令或遇到特定事件时，CPU控制权转移到Host
- **VM-Entry**: Host处理完退出原因后，恢复Guest执行
- **exit_reason**: 导致VM-Exit的具体原因编码
- **ISA类型**: VMX(Intel)、SVM(AMD)、ARM

## 输出

### 输出格式

**标准模式**:
```
exit_reason       calls   total(us)     min(us)     avg(us)     p99(us)     max(us)  %gsys
```

**按实例模式（`--perins`）**:
```
[CPU/THREAD] exit_reason       calls   total(us)     min(us)     avg(us)     p99(us)     max(us)  %gsys
```

**详细模式（`--than`触发）**:
```
<timestamp> kvm_exit: vcpu=X exit_reason=xxx guest_rip=0xXXXXXXXX
<timestamp> kvm_entry: vcpu=X
```

### 输出字段
| 字段 | 说明 |
|------|------|
| exit_reason | 退出原因字符串（Intel 20字符，其他32字符） |
| calls | 该退出原因发生的总次数 |
| total(us) | 总延迟时间（微秒） |
| min(us) | 最小延迟 |
| avg(us) | 平均延迟 = total / calls |
| p99(us) | 99分位延迟 |
| max(us) | 最大延迟 |
| %gsys | Guest内核态占比 |

### 关键指标

| 指标 | 计算方法 | 异常阈值 |
|------|----------|----------|
| calls | 退出次数累计 | 高频退出影响性能 |
| total | 各退出原因总延迟之和 | 衡量Host侧整体损耗 |
| p99延迟 | t-digest算法计算 | >1ms需关注 |
| max延迟 | 最大退出延迟 | >10ms严重影响Guest |

## 应用示例

### 基础示例
```bash
# 1. 监控虚拟机KVM退出延迟
perf-prof kvm-exit -p $(pidof qemu-system-x86_64) -i 1000

# 2. 按vcpu实例分别统计
perf-prof kvm-exit -p <qemu-pid> --perins -i 1000

# 3. 监控延迟超过1ms的退出事件
perf-prof kvm-exit -p <qemu-pid> --than 1ms -i 1000
```

### 高级技巧
```bash
# 过滤特定退出原因(EPT_VIOLATION = 48)
perf-prof kvm-exit -p <qemu-pid> --filter 'exit_reason==48' -i 1000

# 排除HLT指令退出(HLT = 12)
perf-prof kvm-exit -p <qemu-pid> --filter 'exit_reason!=12' -i 1000

# 生成延迟热图数据
perf-prof kvm-exit -p <qemu-pid> --heatmap kvm_lat -i 1000
```

### 性能优化
```bash
# 高退出率场景增大缓冲区
perf-prof kvm-exit -p <qemu-pid> -m 256 -i 1000

# 监控特定CPU上的vcpu
perf-prof kvm-exit -C 1-4 --perins -i 1000
```

### 组合使用
```bash
# 多阶段分析
perf-prof kvm-exit -p <qemu-pid> -i 1000              # 阶段1: 整体监控
perf-prof kvm-exit -p <qemu-pid> --perins -i 1000     # 阶段2: 按vcpu分析
perf-prof kvm-exit -p <qemu-pid> --than 1ms -i 1000   # 阶段3: 延迟事件捕获

# 与profile配合分析Host侧开销
perf-prof profile -p <qemu-pid> -g --exclude-user     # 分析内核态CPU使用
perf-prof kvm-exit -p <qemu-pid> -i 1000              # 分析VM-Exit延迟
```

## 退出原因参考

### x86 (Intel VMX)
| exit_reason | 名称 | 描述 |
|-------------|------|------|
| 0 | EXCEPTION_NMI | 异常或NMI |
| 1 | EXTERNAL_INTERRUPT | 外部中断 |
| 10 | CPUID | CPUID指令 |
| 12 | HLT | HLT指令（Guest空闲） |
| 28 | CR_ACCESS | 控制寄存器访问 |
| 30 | IO_INSTRUCTION | IO指令 |
| 31 | MSR_READ | 读MSR |
| 32 | MSR_WRITE | 写MSR |
| 48 | EPT_VIOLATION | EPT页错误 |
| 54 | WBINVD | WBINVD指令 |
| 55 | XSETBV | XSETBV指令 |

### x86 (AMD SVM)
| exit_code | 名称 | 描述 |
|-----------|------|------|
| 0x78 | SVM_EXIT_HLT | HLT指令 |
| 0x7B | SVM_EXIT_IOIO | IO指令 |
| 0x7C | SVM_EXIT_MSR | MSR访问 |
| 0x400 | SVM_EXIT_NPF | 嵌套页错误 |

### ARM64
| esr_ec | 名称 | 描述 |
|--------|------|------|
| 1 | WFI_WFE | WFI/WFE指令 |
| 24 | DABT_LOW | 数据中止(低异常级别) |
| 32 | IABT_LOW | 指令中止(低异常级别) |
| 36 | DABT_CURRENT | 数据中止(当前异常级别) |

## 相关资源
- [multi-trace分析器](multi-trace.md) - 延迟分析
- [profile分析器](profile.md) - CPU性能分析
- [KVM虚拟化架构](https://www.linux-kvm.org/page/Documents)
- [Intel VT-x规范](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
