# 程序原理与架构

## 1. 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        用户态 (Go)                           │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │ 内核版本检测    │───→│ runModern()     │                │
│  │ (>= 5.8 ?)      │    │  ringbuf reader │                │
│  └─────────────────┘    └─────────────────┘                │
│           │                                            ▲    │
│           └────────────────────────────────────────────┤    │
│           No (< 5.8)                                   │    │
│           ↓                                            │    │
│    ┌─────────────────┐                                 │    │
│    │ runLegacy()     │─────────────────────────────────┤    │
│    │ perf reader     │                                 │    │
│    └─────────────────┘                                 │    │
│                              BPF_MAP_TYPE_RINGBUF      │    │
│                              or PERF_EVENT_ARRAY       │    │
│                              ↓                         │    │
│                    ┌─────────────────────┐             │    │
│                    │ struct event        │─────────────┘    │
│                    └─────────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
                              ↑
                              │
┌─────────────────────────────────────────────────────────────┐
│                        内核态 (eBPF C)                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │ tp/sys_enter_   │  │ tp/sys_enter_   │  │ tp/sys_     │  │
│  │   execve        │  │   connect       │  │ enter/exit  │  │
│  │                 │  │                 │  │ _accept4    │  │
│  └────────┬────────┘  └────────┬────────┘  └──────┬──────┘  │
│           │                    │                  │         │
│           └────────────────────┴──────────────────┘         │
│                              │                              │
│                              ↓                              │
│           ┌──────────────────────────────────┐              │
│           │  trace.bpf.c (现代, >=5.8)       │              │
│           │  BPF_MAP_TYPE_RINGBUF            │              │
│           └──────────────────────────────────┘              │
│           ┌──────────────────────────────────┐              │
│           │  trace_legacy.bpf.c (兼容, <5.8) │              │
│           │  BPF_MAP_TYPE_PERF_EVENT_ARRAY   │              │
│           └──────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

## 2. 为什么选择 tracepoint

- **稳定性**：tracepoint 是内核官方维护的静态插桩点，API 不会随内核版本变化而破坏。相比 kprobe/kretprobe 动态挂钩具体函数实现，tracepoint 不会因为内核函数名变更或签名调整而失效。
- **性能开销低**：tracepoint 仅在有注册程序时产生极少量的上下文切换。
- **标准化**：所有 Linux 发行版对同一版本内核的 `sys_enter_*` / `sys_exit_*` tracepoint 定义完全一致。

## 3. 双模式设计

### 现代模式（内核 ≥ 5.8）
- **传输层**：`BPF_MAP_TYPE_RINGBUF`，支持多生产者单消费者、自动内存管理，性能优于 perf buffer。
- **可移植性**：CO-RE（Compile Once – Run Everywhere），依赖 BTF 自动修正结构体偏移。
- **Helpers**：使用 `bpf_probe_read_user` / `bpf_probe_read_user_str`。

### 兼容模式（内核 < 5.8）
- **传输层**：`BPF_MAP_TYPE_PERF_EVENT_ARRAY`，4.x / CentOS 7 广泛支持。
- **可移植性**：不使用 BTF/CO-RE，依赖 `vmlinux.h` 中的结构体定义。由于 tracepoint 的 `args[]` ABI 在 3.10 ~ 6.x 之间基本稳定，同一套编译产物在 4.x 内核上直接加载成功率很高。
- **Helpers**：使用 `bpf_probe_read` / `bpf_probe_read_str`，兼容 5.5 之前的内核。

## 4. 事件流转详解

### execve 监控
- `sys_enter_execve`：进入 execve 时触发。通过 `ctx->args[0]` 读取用户态 filename 字符串，连同 pid、comm 写入事件通道。
- `sys_exit_execve`：execve 返回时触发。记录返回值（0 表示成功，负数为错误码），用于确认命令是否真正执行成功。

### connect 监控
- `sys_enter_connect`：进入 connect 时触发。`ctx->args[1]` 为用户态传入的 `struct sockaddr *`。
- 内核态直接拷贝 128 字节 sockaddr 原始数据，**不在内核态做字符串解析**（减少 verifier 复杂度和指令数）。
- 用户态 Go 程序根据 `sa_family`（AF_INET/AF_INET6/AF_UNIX...）解析出可读的 IP:Port 或路径。

### accept4 监控
- accept4 的对端地址在 `sys_enter_accept4` 时**尚未填充**，内核只在返回前写入用户提供的缓冲区。
- 因此采用 **enter/exit 配对**模式：
  1. `sys_enter_accept4`：将 `pid → sockaddr 用户态指针` 存入一个临时 `BPF_MAP_TYPE_HASH`。
  2. `sys_exit_accept4`：以 pid 为 key 取出指针，读取已填充的 sockaddr，连同返回 fd（新的 socket fd）一起上报。最后删除 hash 中的临时记录。

## 5. 数据结构

```c
struct event {
    u32  pid;       // 进程 PID
    u32  type;      // 1=execve_enter, 2=execve_exit, 3=connect, 4=accept4_exit
    char comm[16];  // 进程名 (bpf_get_current_comm)
    char data[256]; // execve: filename; connect/accept4: sockaddr 原始字节
    s64  ret;       // 系统调用返回值 (exit 事件有效)
};
```
