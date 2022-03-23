# kmemleak

分析内存泄露，一般内存分配至少需要alloc和free两个接口。内存泄露，alloc之后永远不释放。

工具原理：

- 在alloc点抓到对应的内存分配信息，进程id、comm、内核栈、分配时间。并存到alloc链表里。
- 在free点，从alloc链表查找alloc信息。能找到，说明正确的分配和释放，删除alloc链表的记录。找不到说明在工具启动前分配的，直接丢弃。
- alloc和free之间通过`ptr`指针关联起来。动态增加的alloc/free tracepoint点需要ptr指针。
- 在工具结束时，打印所有alloc链表的信息。即为，*最可能的内存泄露点*。工具执行时间越久，越能得到最准确的信息。

可以解决内核[kmemleak](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/dev-tools/kmemleak.rst)工具不支持percpu内存泄露问题。

可以分析**内核态内存泄露**、**用户态内存泄露**。

共监控2个事件：

- **alloc**，需要自己指定，可以是`kmem:kmalloc、pcpu_alloc`等分配内存点。alloc点需要获取内核栈。可以指定多个alloc点。
- **free**，需要自己指定，与alloc相对应。可以是`kmem:kfree、free_percpu`等释放内存点。free点不需要栈信息。可以指定多个free点。

```
用法:
    perf-prof kmemleak --alloc EVENT[...] --free EVENT[...] [-p PID] [--order] [--order-mem=B] [-m pages] [-g [--flame-graph file]] [-v]

      --alloc=EVENT,...      Memory alloc tracepoint/kprobe
      --free=EVENT,...       memory free tracepoint/kprobe
  -p, --pids=PID,PID         Attach to processes
      --order                Order events by timestamp.
      --order-mem=B          Maximum memory used by ordering events. Unit: GB/MB/KB/*B.
      --flame-graph=file     Specify the folded stack file.
  -g, --call-graph           Enable call-graph recording
  -m, --mmap-pages=pages     number of mmap data pages and AUX area tracing mmap pages
  -v, --verbose              Verbose debug output
```

## 1 内核态内存泄露

## 1.1 kmalloc

```
perf-prof kmemleak --alloc "kmem:kmalloc,kmem:kmalloc_node" --free kmem:kfree -m 64 -g --order --order-mem 4M
```

--alloc，监控`kmem:kmalloc, kmem:kmalloc_node`2个分配入口。

--free，监控`kmem:kfree`1个释放点。

启用order，按时间排序所有cpu上的采样事件，可以减少内核唤醒perf-prof的次数，减少cpu消耗。并启用4M的排序内存。

## 1.2 kmem_cache_alloc

```
perf-prof kmemleak --alloc "kmem:kmem_cache_alloc/bytes_alloc>256/,kmem:kmem_cache_alloc_node/bytes_alloc>256/" --free "kmem:kmem_cache_free" -m 64 -g --order --order-mem 8M
```

--alloc，监控`kmem:kmem_cache_alloc, kmem:kmem_cache_alloc_node`2个分配入口。并过滤`bytes_alloc>256`的内存分配请求。

--free，监控`kmem:kmem_cache_free`1个释放点。

## 1.3  percpu

```
echo 'r:alloc_percpu pcpu_alloc ptr=$retval' >> /sys/kernel/debug/tracing/kprobe_events #ptr指向分配的内存地址
echo 'p:free_percpu free_percpu ptr=%di' >> /sys/kernel/debug/tracing/kprobe_events
perf-prof kmemleak --alloc kprobes:alloc_percpu --free kprobes:free_percpu -m 8 -g --order --order-mem 8M
```

alloc_percpu，增加pcpu_alloc return kprobe点，使用ptr参数接收返回的指针。

free_percpu，增加free_percpu kprobe点，使用ptr参数接收释放的指针。

--alloc，监控`kprobes:alloc_percpu`分配入口。

--free，监控`kprobes:free_percpu`释放点。



## 2 用户态内存泄露

可以借助tcmalloc的MallocHook功能，来把多个分配和释放接口，统一成2个：NewHook，DeleteHook。然后增加对应的uprobe点，来跟踪用户态内存泄露。

1. 编译libtcmalloc

   ```
   git clone https://github.com/gperftools/gperftools.git
   cd gperftools
   ./autogen.sh
   CPPFLAGS=-fno-omit-frame-pointer ./configure
   CPPFLAGS=-fno-omit-frame-pointer make
   make install
   把 libtcmalloc.so.4.5.9 移动到 /tmp/trace 目录
   tcmalloc库需要启用frame pointer, 才可以穿透tcmalloc库来获取应用程序的栈
   ```

2. 编译[malloc_hook](malloc_hook.c)

   ```
   gcc -shared -fPIC malloc_hook.c -o malloc_hook.so
   把 malloc_hook.so 移动到 /tmp/trace 目录
   ```

3. 添加uprobe点

   ```
   # 0x7d5为NewHook函数的偏移量，0x7e3为DeleteHook函数的偏移量。
   echo "p:NewHook /tmp/trace/malloc_hook.so:0x7d5 ptr=%di len=%si" >> /sys/kernel/debug/tracing/uprobe_events
   echo "p:DeleteHook /tmp/trace/malloc_hook.so:0x7e3 ptr=%di" >> /sys/kernel/debug/tracing/uprobe_events
   ```

4. 复现内存泄露

   ```
   LD_PRELOAD="/tmp/trace/libtcmalloc.so.4.5.9 /tmp/trace/malloc_hook.so" ./leak
   ```

5. 启动perf-prof

   ```
   perf-prof kmemleak --alloc uprobes:NewHook --free uprobes:DeleteHook -p 213597 -g # 213597为leak进程PID。
   ```



**内部原理**

```
leak       libtcmalloc    malloc_hook                        perf-prof
malloc ->  tc_malloc   -> NewHook(触发int3)                读取ring buffer中的栈，获取分配的内存指针ptr
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
                            |                                 |
kernel                  命中uprobe:NewHook tracepoint点        |
                            |                                 |
                        采样用户态栈传到到perf ringbuffer        |
                            `----------------------------------


leak       libtcmalloc    malloc_hook                     perf-prof
free   ->  tc_free     -> DeleteHook(触发int3)         读取内存释放ptr指针(DeleteHook)
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
                            |                                 |
kernel                  命中uprobe:DeleteHook tracepoint点     |
                            |                                 |
                        内存释放信息传到到perf ringbuffer        |
                            `----------------------------------
```

