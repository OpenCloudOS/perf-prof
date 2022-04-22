# kvm-exit

统计kvm退出延迟。

在虚拟化场景，大部分指令都不需要退出到kvm模块，但少量特权指令需要退出，由kvm模块拦截并模拟执行指令。在kvm模块内会因为很多原因导致指令执行的延迟。

对于虚拟机来说，指令延迟会导致子机内业务抖动，cpu利用率增加等等。

该工具可以监控指令执行的耗时分布。

类似`perf trace -s`可以统计系统调用耗时分布一样，`perf-prof kvm-exit`可以统计特权指令的耗时分布。

共监控2个tracepoint点：

- kvm:kvm_exit，特权指令退出到kvm模块。
- kvm:kvm_entry，特权指令执行完成，进入guest。

```
用法:
	perf-prof kvm-exit [--perins] [--than ns] [--heatmap file]
例子:
	perf-prof kvm-exit -C 5-20,53-68 -i 1000 --than 1ms #统计CPU上的特权指令耗时,每1000ms输出一次,并打印耗时超过1ms的日志

 OPTION:
  -C, --cpu=CPU[-CPU],...    Monitor the specified CPU, Dflt: all cpu
  -i, --interval=ms          Interval, Unit: ms
  -m, --mmap-pages=pages     Number of mmap data pages and AUX area tracing mmap pages
      --order                Order events by timestamp.
      --order-mem=Bytes      Maximum memory used by ordering events. Unit: GB/MB/KB/*B.
  -p, --pids=PID,...         Attach to processes
  -t, --tids=TID,...         Attach to thread
  -v, --verbose              Verbose debug output

      --perins               Print per instance stat
      --than=ge              Greater than specified time, Unit: s/ms/us/*ns/percent
      --heatmap=file         Specify the output latency file.
```



## 1 量化虚拟化耗时

业务压测从开始到结束，可以统计出指令模拟的总耗时。以此可以量化虚拟化优化带来的性能提升。

业务压测前启动命令，业务压测结束后结束命令。

```bash
[root@kvm ~]# ./perf-prof kvm-exit -p 124604
^C2022-04-22 17:34:13.858975 
kvm-exit latency
exit_reason             calls        total(us)   min(us)   avg(us)      max(us)  %gsys
-------------------- -------- ---------------- --------- --------- ------------ ------
HLT                     20747     53004499.016     0.734  2554.803   199989.423 100.00
MSR_WRITE               28853        24009.550     0.446     0.832       15.074 100.00
IO_INSTRUCTION            222         1309.834     1.663     5.900       42.239 100.00
CPUID                     962         1071.299     0.610     1.113       13.196   0.00
EXTERNAL_INTERRUPT        845          834.426     0.437     0.987        8.658  60.43
PAUSE_INSTRUCTION         310          280.187     0.474     0.903       15.534 100.00
EPT_MISCONFIG              13          141.703     1.822    10.900      108.401 100.00
```

把`total(us)`列累加起来，就可以得到指令模拟的总耗时。

同时还能看到指令模拟次数，在子机内消除不必要的指令调用，也可以减少vmexit次数，提升性能。



## 2 监控虚拟化的抖动

每秒粒度输出指令延迟统计信息，并打印超过5ms的指令延迟。hlt指令超过5ms默认不会打印，hlt退出之后会让出cpu，指令延迟不可控。

```bash
[root@kvm ~]# ./perf-prof kvm-exit -p 126934 -i 1000 --than 5ms
2022-04-22 17:39:25.894653 
kvm-exit latency
exit_reason             calls        total(us)   min(us)   avg(us)      max(us)  %gsys
-------------------- -------- ---------------- --------- --------- ------------ ------
HLT                      1113       806253.057     0.816   724.396     4025.007 100.00
IO_INSTRUCTION           4188        21933.700     0.429     5.237      235.951 100.00
EXTERNAL_INTERRUPT       2060        10427.611     0.318     5.061     1091.176  22.23
APIC_WRITE               1706         4412.272     0.549     2.586      302.672 100.00
EOI_INDUCED              1023         1018.154     0.621     0.995        9.742 100.00
VMCALL                    408          492.190     0.823     1.206        6.376 100.00
EPT_MISCONFIG               6          103.010     1.938    17.168       89.159 100.00
PAUSE_INSTRUCTION          34           23.826     0.384     0.700        1.676 100.00
2022-04-22 17:39:26.535148            <...> 126953 .... [078] 96822671.255015: kvm:kvm_exit: reason APIC_WRITE rip 0xfffff801b782acff info 300 0
2022-04-22 17:39:26.535253            <...> 126953 d... [074] 96822671.266643: kvm:kvm_entry: vcpu 0
2022-04-22 17:39:26.894654 
kvm-exit latency
exit_reason             calls        total(us)   min(us)   avg(us)      max(us)  %gsys
-------------------- -------- ---------------- --------- --------- ------------ ------
HLT                      1208       903477.145     1.061   747.911     4621.338 100.00
APIC_WRITE               1481        22191.956     0.620    14.984    11628.216 100.00
IO_INSTRUCTION           4328        22057.770     0.430     5.096      225.165 100.00
EXTERNAL_INTERRUPT       1920         7065.979     0.323     3.680      203.007  34.68
EOI_INDUCED              1008         1159.526     0.607     1.150      100.200 100.00
EPT_MISCONFIG               8           57.767     4.255     7.220       15.644 100.00
PAUSE_INSTRUCTION          48           43.217     0.373     0.900        2.174 100.00
VMCALL                      1            5.370     5.370     5.370        5.370 100.00
```

可以看到有个`APIC_WRITE`超过11ms被打印出来。



```bash
[root@kvm ~]# ./perf-prof kvm-exit -p 126934 -i 1000 --perins
2022-04-22 17:47:05.729691 
kvm-exit latency THREAD 126953
exit_reason             calls        total(us)   min(us)   avg(us)      max(us)  %gsys
-------------------- -------- ---------------- --------- --------- ------------ ------
HLT                        74        38394.469     7.253   518.844     1075.099 100.00
IO_INSTRUCTION           4258        20494.856     0.427     4.813      272.158 100.00
EXTERNAL_INTERRUPT       1030         3133.794     0.330     3.042      565.862  43.99
APIC_WRITE               1195         2994.299     0.614     2.505       41.645 100.00
EOI_INDUCED              1024          948.862     0.583     0.926        8.067 100.00
PAUSE_INSTRUCTION           1            1.254     1.254     1.254        1.254 100.00
kvm-exit latency THREAD 126954
exit_reason             calls        total(us)   min(us)   avg(us)      max(us)  %gsys
-------------------- -------- ---------------- --------- --------- ------------ ------
HLT                       888       776830.290     7.454   874.808     3914.254 100.00
EXTERNAL_INTERRUPT        724        11867.819     0.324    16.392     1964.989  68.64
APIC_WRITE                264          451.068     0.656     1.708        9.231 100.00
IO_INSTRUCTION             14           95.456     1.351     6.818       12.901 100.00
EPT_MISCONFIG               6           29.160     3.205     4.860        7.510 100.00
PAUSE_INSTRUCTION           6            4.366     0.533     0.727        0.865 100.00
```

通过`--perins` 可以打印每个线程的统计。

