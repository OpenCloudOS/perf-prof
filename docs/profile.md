# profile

分析采样栈，可以分析内核态CPU利用率超过一定百分比抓取内核态栈。

统计cpu利用率，利用pmu可以过滤用户态和内核态的功能，统计1秒内内核态的cycle数，除以tsc频率，就能计算出%sys占比。

共监控1个事件。

- **pmu:ref-cycles**，参数时钟默认以固定频率运行，以tsc的频率运行。会先从内核获取tsc_khz的频率，然后固定间隔采样。

```
用法:
	perf-prof profile [-F freq] [-C cpu] [-g [--flame-graph file [-i INT]]] [-m pages] [--exclude-*] [-G] [--than PCT]
例子:
	perf-prof profile -F 100 -C 0 -g --exclude-user --than 30  #对cpu0采样，在内核态利用率超过30%打印内核栈。

  -F, --freq=n               以固定频率采样。
  -i, --interval=INT         以固定间隔输出火焰图。单位ms
  -C, --cpu=CPU              指定在哪些cpu上采样栈。
  -g, --call-graph           抓取采样点的栈。
      --exclude-user         过滤掉用户态的采样，只采样内核态，可以减少采样点。降低cpu压力。
      --exclude-kernel       过滤掉内核态采样，只采样用户态。
      --exclude-guest        过滤掉guest，保留host。
      --flame-graph=file     指定folded stack file.
  -G, --guest                过滤掉host，保留guest。
      --than=PCT             百分比，指定采样的用户态或者内核态超过一定百分比才输出信息，包括栈信息。可以抓取偶发内核态占比高的问题。
```

