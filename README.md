# eBPF Tracepoint 网络与进程行为追踪器

基于 eBPF tracepoint + Go 的轻量级系统调用追踪工具，可实时监控 `execve`、`connect`、`accept4` 三类核心系统调用。

**核心特性**：运行时自动检测内核版本，≥ 5.8 使用高性能 **ringbuf + BTF/CO-RE** 现代模式，< 5.8 自动降级到 **perf buffer** 兼容模式。一套静态二进制同时覆盖 RHEL/CentOS/Oracle 7.6+ 回移植内核 (3.10) ~ 最新 6.x 内核。

---

## 1. 程序原理

### 1.1 整体架构

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

### 1.2 为什么选择 tracepoint

- **稳定性**：tracepoint 是内核官方维护的静态插桩点，API 不会随内核版本变化而破坏。相比 kprobe/kretprobe 动态挂钩具体函数实现，tracepoint 不会因为内核函数名变更或签名调整而失效。
- **性能开销低**：tracepoint 仅在有注册程序时产生极少量的上下文切换。
- **标准化**：所有 Linux 发行版对同一版本内核的 `sys_enter_*` / `sys_exit_*` tracepoint 定义完全一致。

### 1.3 双模式设计

#### 现代模式（内核 ≥ 5.8）
- **传输层**：`BPF_MAP_TYPE_RINGBUF`，支持多生产者单消费者、自动内存管理，性能优于 perf buffer。
- **可移植性**：CO-RE（Compile Once – Run Everywhere），依赖 BTF 自动修正结构体偏移。
- **Helpers**：使用 `bpf_probe_read_user` / `bpf_probe_read_user_str`。

#### 兼容模式（内核 < 5.8）
- **传输层**：`BPF_MAP_TYPE_PERF_EVENT_ARRAY`，4.x / CentOS 7 广泛支持。
- **可移植性**：不使用 BTF/CO-RE，依赖 `vmlinux.h` 中的结构体定义。由于 tracepoint 的 `args[]` ABI 在 3.10 ~ 6.x 之间基本稳定，同一套编译产物在 4.x 内核上直接加载成功率很高。
- **Helpers**：使用 `bpf_probe_read` / `bpf_probe_read_str`，兼容 5.5 之前的内核。

### 1.4 事件流转详解

#### execve 监控
- `sys_enter_execve`：进入 execve 时触发。通过 `ctx->args[0]` 读取用户态 filename 字符串，连同 pid、comm 写入事件通道。
- `sys_exit_execve`：execve 返回时触发。记录返回值（0 表示成功，负数为错误码），用于确认命令是否真正执行成功。

#### connect 监控
- `sys_enter_connect`：进入 connect 时触发。`ctx->args[1]` 为用户态传入的 `struct sockaddr *`。
- 内核态直接拷贝 128 字节 sockaddr 原始数据，**不在内核态做字符串解析**（减少 verifier 复杂度和指令数）。
- 用户态 Go 程序根据 `sa_family`（AF_INET/AF_INET6/AF_UNIX...）解析出可读的 IP:Port 或路径。

#### accept4 监控
- accept4 的对端地址在 `sys_enter_accept4` 时**尚未填充**，内核只在返回前写入用户提供的缓冲区。
- 因此采用 **enter/exit 配对**模式：
  1. `sys_enter_accept4`：将 `pid → sockaddr 用户态指针` 存入一个临时 `BPF_MAP_TYPE_HASH`。
  2. `sys_exit_accept4`：以 pid 为 key 取出指针，读取已填充的 sockaddr，连同返回 fd（新的 socket fd）一起上报。最后删除 hash 中的临时记录。

### 1.5 数据结构

```c
struct event {
    u32  pid;       // 进程 PID
    u32  type;      // 1=execve_enter, 2=execve_exit, 3=connect, 4=accept4_exit
    char comm[16];  // 进程名 (bpf_get_current_comm)
    char data[256]; // execve: filename; connect/accept4: sockaddr 原始字节
    s64  ret;       // 系统调用返回值 (exit 事件有效)
};
```

---

## 2. 开发编译环境配置

### 2.1 系统要求（编译机）

> 编译机仍然建议 5.8+，因为生成现代版 eBPF 对象时需要本机 BTF。兼容版对象无需 BTF，但为了方便一次性生成两套对象，推荐在 5.8+ 环境编译。

| 组件 | 最低版本 | 说明 |
|------|---------|------|
| Linux 内核 | 5.8+ | 推荐，用于本地编译和测试现代模式 |
| Go | 1.24+ | 本项目使用 `github.com/cilium/ebpf v0.21.0` |
| Clang/LLVM | 14+ | 编译 eBPF C 代码到 ELF |
| bpftool | 任意 | 用于生成 `vmlinux.h` |
| libbpf-dev | 1.0+ | 提供 `<bpf/bpf_helpers.h>` 等头文件 |

### 2.2 Ubuntu/Debian 环境安装示例

```bash
# 基础工具链
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool

# Go（如系统版本过低，建议从官网下载）
# https://go.dev/dl/
```

### 2.3 项目初始化

```bash
# 1. 初始化 Go module
go mod init ebpf-tracepoint

# 2. 安装 cilium/ebpf 库及 bpf2go 工具
go get github.com/cilium/ebpf@latest
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# 3. 生成 vmlinux.h（从当前内核 BTF 导出）
mkdir -p bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

> **注意**：`vmlinux.h` 并非必须与编译机内核一致。只要目标机的内核字段是编译机内核字段的**子集**，CO-RE 即可兼容。若需支持更老内核，建议从**老内核**导出 `vmlinux.h`，因为新内核的字段只会多不会少。

---

## 3. 运行环境检测

### 3.1 内核版本适配矩阵

| 发行版 | 版本 | 典型内核 | 运行模式 | BTF | Ringbuf | 兼容性 |
|--------|------|---------|---------|-----|---------|--------|
| **CentOS / RHEL** | 7.5 及以下 | 3.10.0-862 等 | — | — | — | ❌ **不支持** (无 eBPF) |
| **CentOS / RHEL / Oracle** | 7.6+ | 3.10.0-957+ (RHEL 回移植) | 兼容模式 | ❌ | ❌ | ✅ **支持** |
| 其他发行版 | 任意 3.10 | 上游 3.10 | — | — | — | ❌ **不支持** |
| **CentOS / RHEL** | 8.x | 4.18 | 兼容模式 | ❌ | ❌ | ✅ **支持** |
| **CentOS Stream / RHEL** | 9.x | 5.14+ | 现代模式 | ✅ | ✅ | ✅ **支持** |
| **Rocky Linux** | 8.x | 4.18 | 兼容模式 | ❌ | ❌ | ✅ **支持** |
| **Rocky Linux** | 9.x | 5.14+ | 现代模式 | ✅ | ✅ | ✅ **支持** |
| **AlmaLinux** | 8.x | 4.18 | 兼容模式 | ❌ | ❌ | ✅ **支持** |
| **AlmaLinux** | 9.x | 5.14+ | 现代模式 | ✅ | ✅ | ✅ **支持** |
| **Oracle Linux** | 7.6+ (UEK) | 3.10.0-957+ / 4.14+ (UEK5) | 兼容模式 | ❌ | ❌ | ✅ **支持** |
| **Oracle Linux** | 8.x (UEK6) | 5.4+ | 现代模式 | ✅ | ✅ | ✅ **支持** |
| **Ubuntu** | 18.04 LTS | 4.15 | 兼容模式 | ❌ | ❌ | ✅ **支持** |
| **Ubuntu** | 20.04 LTS | 5.4 | 兼容模式 | ⚠️ 可选 | ❌ | ✅ **支持** |
| **Ubuntu** | 22.04+ LTS | 5.15+ | 现代模式 | ✅ | ✅ | ✅ **支持** |
| **Debian** | 9 (Stretch) | 4.9 | 兼容模式 | ❌ | ❌ | ✅ **支持** |
| **Debian** | 10 (Buster) | 4.19 | 兼容模式 | ❌ | ❌ | ✅ **支持** |
| **Debian** | 11 (Bullseye) | 5.10 | 现代模式 | ✅ | ✅ | ✅ **支持** |
| **Debian** | 12 (Bookworm) | 6.1 | 现代模式 | ✅ | ✅ | ✅ **支持** |
| **云厂商定制内核** | — | 5.8 ~ 6.x | 现代模式 | 视厂商 | 视厂商 | ✅ **支持** |

### 3.2 运行前自检脚本

在目标机器上执行以下检查：

```bash
#!/bin/bash
set -e

echo "=== eBPF 运行环境自检 ==="

# 1. 内核版本
KVER=$(uname -r | cut -d- -f1)
echo "内核版本: $KVER"

MAJOR=$(echo $KVER | cut -d. -f1)
MINOR=$(echo $KVER | cut -d. -f2)

if [ "$MAJOR" -gt 5 ] || ([ "$MAJOR" -eq 5 ] && [ "$MINOR" -ge 8 ]); then
    echo "[OK] 内核 >= 5.8，将使用现代模式 (ringbuf + BTF)"
    if [ -f /sys/kernel/btf/vmlinux ]; then
        echo "[OK] BTF 已开启"
    else
        echo "[WARN] BTF 未开启，现代模式可能加载失败"
    fi
else
    echo "[OK] 内核 < 5.8，将使用兼容模式 (perf buffer)"
fi

# 2. 检查 CAP_BPF / root
capsh --print 2>/dev/null | grep -q "cap_bpf\|cap_sys_admin" || true
if [ "$EUID" -ne 0 ]; then
    echo "[WARN] 当前非 root 用户。加载 eBPF 通常需要 root 或 CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN。"
else
    echo "[OK] 当前为 root 用户"
fi

echo "=== 自检通过，可以运行 ==="
```

### 3.3 常见失败场景

| 现象 | 根因 | 解决方案 |
|------|------|---------|
| `loadTraceObjects: ... BTF not found` | 目标内核未开启 BTF | 程序会自动降级到兼容模式，无需手动处理 |
| `failed to attach sys_enter_accept4: tracepoint not found` | 内核裁剪了该 tracepoint | 程序会跳过并打印 Warning，不影响其他事件 |
| `Failed to open ring buffer: invalid argument` | 内核 < 5.8 | 程序会自动使用 perf buffer 兼容模式 |
| `operation not permitted` | 权限不足 / SELinux/AppArmor 限制 | 使用 root，或检查安全策略 |

---

## 4. 缓冲区配置

程序通过 `-buffer-level` 参数提供三级缓冲区大小，用于平衡内存占用与事件丢失风险。

### 4.1 两种模式的缓冲机制差异

| 模式 | 缓冲类型 | 数量 | 配置影响 | 当前配置显示 |
|------|---------|------|---------|-------------|
| **现代模式** (≥ 5.8) | `BPF_MAP_TYPE_RINGBUF` | **全局 1 个** | 直接设定总大小 | `ringbuf 大小: X MB` |
| **兼容模式** (< 5.8) | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | **每 CPU 1 个** | 设定单 CPU 大小，总量 = 单 CPU × 核数 | `perf buffer 大小: X KB/CPU` |

### 4.2 等级换算表

| `-buffer-level` | 现代模式 (ringbuf) | 兼容模式 (perf buffer / CPU) | 适用场景 |
|----------------|-------------------|---------------------------|---------|
| **1** | 256 KB | 16 KB | 开发测试、低负载、内存敏感环境 |
| **2** (默认) | **1 MB** | **64 KB** | 通用生产环境，大多数场景够用 |
| **3** | 4 MB | 256 KB | 高频网络追踪、高并发服务器、防止 burst 丢事件 |

### 4.3 如何选择

- **事件频率低**（如仅追踪 `execve`）：level 1 即可，`execve` 触发频率通常远低于网络连接。
- **普通生产环境**：level 2 默认，1 MB ringbuf 可缓冲约 3400 个事件，64 KB/CPU perf buffer 可缓冲约 200 个事件/CPU。
- **高并发网络服务**（如 API 网关、数据库代理）：建议使用 **level 3**，或至少使用 `-net -buffer-level=3` 专门加大网络追踪的缓冲。

> **注意**：缓冲区占用的是**锁定的内核内存**（计入 memlock），但等级 3 的 4 MB ringbuf 或 `256 KB × CPU核数` 的 perf buffer 对现代服务器来说仍然非常小。

### 4.4 流量预警

程序支持对单条网络连接的流量进行内核态累加，并在超过阈值时实时预警。

```bash
# 当任意连接的收发流量超过 10MB 时输出预警
sudo ./ebpf-tracepoint -net -flow-threshold-mb 10
```

**预警输出示例**：

```
FLOW     845804 curl             ALERT=RX RX=1.00MB TX=0.09KB 90.130.70.73:80
FLOW     1135   AliYunDunMonito  ALERT=TX RX=3.46KB TX=1.00MB 100.100.188.188:443
```

**实现原理**：
- `connect` / `accept4` 建立连接时，在 eBPF map 中创建连接统计条目（key = pid+fd）。
- 通过 `write` / `read` / `sendto` / `recvfrom` 的 enter/exit 配对，累加实际收发字节数。
- `close` 时自动清理 map 条目，防止内存泄漏。
- 超过阈值时发送一次 `FLOW` 事件（带 `warned` 标志避免重复上报）。

**限制**：
- `sendfile` / `splice` 等零拷贝路径不会被计入。

---

## 5. 开发过程

### 5.1 文件结构

```
.
├── bpf/
│   ├── vmlinux.h              # BTF 导出的内核结构体定义
│   ├── trace.bpf.c            # eBPF 现代程序 (ringbuf, >=5.8)
│   └── trace_legacy.bpf.c     # eBPF 兼容程序 (perf buffer, <5.8)
├── main.go                    # Go 入口：环境检测、模式分发、公共解析
├── modern.go                  # 现代模式：加载 trace.o，ringbuf 消费
├── legacy.go                  # 兼容模式：加载 trace_legacy.o，perf 消费
├── Makefile                   # 一键构建
├── go.mod / go.sum            # Go 依赖
├── CHANGELOG.md               # 版本变更记录
└── ebpf-tracepoint            # 最终独立二进制（静态链接）
```

### 5.2 eBPF C 代码开发要点

#### 现代版 (`trace.bpf.c`)

使用 ringbuf 进行事件传输：
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
// ... 填充事件 ...
bpf_ringbuf_submit(e, 0);
```

使用 `bpf_probe_read_user()` / `bpf_probe_read_user_str()` 读取用户态内存（5.5+）。

#### 兼容版 (`trace_legacy.bpf.c`)

使用 perf event array 进行事件传输：
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} pb SEC(".maps");

struct event e = {};
// ... 填充事件 ...
bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));
```

使用 `bpf_probe_read()` / `bpf_probe_read_str()` 兼容老内核（无 `_user` 区分）。

### 5.3 Go 加载器开发要点

#### 4.3.1 go:generate 与 bpf2go

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//  -cc clang \
//  -cflags "-O2 -g -Wall -Werror -I/usr/include -I./bpf" \
//  -target bpfel,bpfeb \
//  trace bpf/trace.bpf.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//  -cc clang \
//  -cflags "-O2 -g -Wall -Werror -I/usr/include -I./bpf" \
//  -target bpfel,bpfeb \
//  trace_legacy bpf/trace_legacy.bpf.c
```

两套 `go:generate` 指令会在 `go generate ./...` 时同时编译现代版和兼容版 eBPF 对象。

#### 4.3.2 运行时自动分发

```go
func main() {
    kver, kverOK := checkKernelVersion()
    if kverOK {
        runModern(attachExecve, attachNet)
    } else {
        runLegacy(attachExecve, attachNet)
    }
}
```

`Event` 结构体、解析逻辑、`parseSockaddr` 两边完全一致，无需维护两份用户态代码。

#### 4.3.3 优雅降级：单点 attach 失败不退出

```go
attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSysEnterConnect, nil)
// ...
if attachments[i].err != nil {
    fmt.Fprintf(os.Stderr, "Warning: failed to attach %s: %v\n", attachments[i].name, attachments[i].err)
} else {
    attached++; defer attachments[i].l.Close()
}
```

某些精简内核可能缺少个别 tracepoint，程序不会直接崩溃，而是继续挂载其他可用的事件源。

### 5.4 构建流程

```bash
# 1. 生成两套 eBPF → Go（由 go:generate 自动调用 bpf2go）
go generate ./...

# 2. 编译最终静态二进制
CGO_ENABLED=0 go build -ldflags '-s -w' -o ebpf-tracepoint .

# 或使用 Makefile
make build
```

构建产物验证：
```bash
file ebpf-tracepoint
# 输出: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

---

## 6. 适配规则

### 6.1 CPU 架构适配规则

当前二进制为 **编译时确定架构**，规则如下：

| 编译机架构 | 目标架构 | 是否可直接运行 | 说明 |
|-----------|---------|--------------|------|
| x86_64 | x86_64 | ✅ | 直接复制运行 |
| x86_64 | arm64 | ❌ | eBPF ELF 对象和结构体对齐不同 |
| x86_64 | s390x | ❌ | 字节序不同（大端 vs 小端） |

**交叉编译方法**：

```bash
# 编译 ARM64 版本
GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '-s -w' -o ebpf-tracepoint-arm64 .

# 编译 s390x 大端版本
GOARCH=s390x CGO_ENABLED=0 go build -ldflags '-s -w' -o ebpf-tracepoint-s390x .
```

> bpf2go 已通过 `-target bpfel,bpfeb` 预生成了大小端两份 eBPF 对象（现代版和兼容版各两份），交叉编译时 Go 会根据 `GOARCH` 自动选择正确的那份。

### 6.2 添加新的 tracepoint 事件

如需扩展（如 `bind`、`listen`、`sendto`）：

1. 在 `trace.bpf.c` 和 `trace_legacy.bpf.c` 中同时增加新的 `SEC("tp/syscalls/sys_enter_xxx")` 函数。
2. 如需 enter/exit 配对，参照 `accept4` 使用临时 HASH map 保存中间态。
3. 定义新的 `EVENT_xxx` type。
4. 在 `main.go` 中增加对应的 `EventType` 常量，以及在 `modern.go` / `legacy.go` 中增加 `link.Tracepoint` attach 逻辑。
5. 在 `main.go` 的 `printEvent` 中增加解析分支。
6. 重新执行 `go generate ./... && go build`。

---

## 7. 快速开始

```bash
# 构建
make build

# 运行（自动检测内核版本选择模式）
sudo ./ebpf-tracepoint

# 仅追踪 execve
sudo ./ebpf-tracepoint -execve

# 仅追踪网络
sudo ./ebpf-tracepoint -net

# 使用小缓冲区（开发测试，低负载场景）
sudo ./ebpf-tracepoint -buffer-level=1

# 使用大缓冲区（高频网络连接，生产环境防丢事件）
sudo ./ebpf-tracepoint -net -buffer-level=3

# 开启流量预警：单连接收发超过 10MB 时报警
sudo ./ebpf-tracepoint -net -flow-threshold-mb 10
```

### 示例输出

```
=== eBPF Tracepoint 环境检测 ===
内核版本: 6.8.0-63-generic
[OK] 当前为 root 用户
[OK] memlock 限制已解除
===================================

追踪模式: 全部

[MODE] 内核 >= 5.8，启用现代模式 (ringbuf + BTF)
[OK] BTF 已开启
[OK] eBPF 对象加载成功
===================================

TYPE     PID    COMM             RET/FD       DATA
EXEC     1234   bash                          /usr/bin/curl
EXECRET  1234   curl             0
CONNECT  1234   curl                          127.0.0.1:8080
ACCEPT   5678   python3          fd=4         127.0.0.1:54320
```

### 7.1 GitHub Actions 自动发版

推送以 `v` 开头的 tag 即可触发 Release CI，自动编译 `linux/amd64` 与 `linux/arm64` 两个架构的静态二进制，并发布到 GitHub Release：

```bash
git tag v0.2.0
git push origin v0.2.0
```

也可在仓库的 **Actions → Release → Run workflow** 中手动触发。

---

## 8. 附录：核心参考

- [cilium/ebpf Documentation](https://pkg.go.dev/github.com/cilium/ebpf)
- [BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [Linux Kernel Tracepoint API](https://docs.kernel.org/trace/tracepoints.html)
- [BPF Ring Buffer](https://nakryiko.com/posts/bpf-ringbuf/)
