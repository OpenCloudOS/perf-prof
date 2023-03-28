# perf time converted to guest tsc

在虚拟化场景，经常需要同时跟踪，host发生的事件和guest发生的事件。但由于kvm模块存在tsc-offset，host事件和guest事件的时间戳是不对应的。

时间戳对齐，就是把host事件的时间戳转换为guest时间戳。时间戳在同一尺度上，就可以跟guest事件的时间戳做比较。

时间戳对齐后，能够带来更多可能性：

- 可以观察，host注入中断到guest处理中断的延迟。
- 可以观察，vcpu发生一次调度，guest内在执行哪个进程。
- 可以观察，guest发送IO到host处理完IO的延迟。



时间戳对齐，分为多步转换工作。又细分为2种情况：

- guest内关闭kvmclock。
  1. host事件时间戳转换为tsc。
  2. tsc 再转换为 guest tsc。
  3. guest事件时间戳转换为tsc。

- guest内启用kvmclock。
  1. host事件时间戳转换为tsc。
  2. tsc 再转换为 guest tsc。
  3. guest tsc 转换为 kvmclock，再转换为 sched_clock。



目前针对guest内禁用kvmclock时，可以标准化支持。只介绍这种对齐方式。



# 1 host事件时间戳转换为tsc

利用`--tsc`参数，可以把host事件的时间戳直接转换为tsc。

```
$ ./perf-prof trace -e sched:sched_wakeup --tsc -N 1
TSC conversion is not supported.
2023-03-28 18:45:07.098609           <idle>      0 dNh. [002] 18085684.369061: sched:sched_wakeup: sap1014:11492 [120] success=1 CPU:002
```

先使用`perf-prof trace`做个测试，如果不支持tsc转换，会提示`TSC conversion is not supported.`



# 2 tsc转换为guest tsc

利用`--tsc-offset`参数，可以把tsc时间戳转换为guest tsc。

先要利用kvm模块的信息，找到`vcpu->arch.tsc_offset`的值。不同的guest值不一样，需要找到指定guest的。

## 2.1 得到tsc_offset

```
$ echo 'p:kvm_vcpu_kick kvm_vcpu_kick tsc_offset=+0x2eb8(%di):u64' >> /sys/kernel/debug/tracing/kprobe_events
# 0x2eb8 是 vcpu->arch.tsc_offset 的偏移量。不同的内核版本不同，需要具体利用crash工具分析下实际的偏移量。

$ ./perf-prof trace -e  kprobes:kvm_vcpu_kick -N 1 -p qemu_pid
2023-03-28 18:49:24.554854       CPU 68/KVM 183456 d... [049] 86344.182710: kprobes:kvm_vcpu_kick: (ffffffffc045ace0) tsc_offset=0xffee6aba03eccaac
```

通过`kvm_vcpu_kick()`函数找到 vcpu->arch.tsc_offset 的偏移量，进而找到 tsc_offset 的值。

## 2.2 转换为guest tsc

```
$ ./perf-prof trace -e sched:sched_wakeup --tsc --tsc-offset 0xffee6aba03eccaac -N 1
2023-03-28 18:53:53.757492           <idle>      0 dNh. [024] 5696917.795461: sched:sched_wakeup: pal_session:57886 [100] success=1 CPU:024
```

可以正常转换。

此时，host事件的时间戳已经转换为guest tsc时间。



# 3 guest配置

## 3.1 guest关闭kvmclock

加上内核启动参数 "no-kvmclock"。需要配置grub，并重启guest生效。

## 3.2 stable tsc(可选项)

host 需要配置xml文件：

```
<feature policy='require' name="invtsc"/>
```



# 4 guest事件时间戳转换为tsc

利用`--tsc`参数做个测试，判断是否支持转换为tsc。如果不支持，配置#3.2 stable tsc。



host事件和guest事件，时间戳全部都转换为tsc，**时间戳对齐**。