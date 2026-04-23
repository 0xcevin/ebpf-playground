# eBPF Tracepoint 网络与进程行为追踪器

基于 eBPF tracepoint + CO-RE + Go 的轻量级系统调用追踪工具，可实时监控 `execve`、`connect`、`accept4` 三类核心系统调用，编译为独立静态二进制，无需目标机安装任何开发环境。

---

## 1. 程序原理

### 1.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        用户态 (Go)                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │ 加载 eBPF   │───→│  Ringbuf    │───→│  解析/打印事件  │  │
│  │ 对象到内核  │    │  消费事件   │    │  (sockaddr...)  │  │
│  └─────────────┘    └─────────────┘    └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ↑
                              │ BPF_MAP_TYPE_RINGBUF
                              ↓
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
│                    ┌─────────────────────┐                  │
│                    │  BPF_MAP_TYPE_RINGBUF                  │
│                    │  (struct event)     │                  │
│                    └─────────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 为什么选择 tracepoint

- **稳定性**：tracepoint 是内核官方维护的静态插桩点，API 不会随内核版本变化而破坏。相比 kprobe/kretprobe 动态挂钩具体函数实现，tracepoint 不会因为内核函数名变更或签名调整而失效。
- **性能开销低**：tracepoint 仅在有注册程序时产生极少量的上下文切换。
- **标准化**：所有 Linux 发行版对同一版本内核的 `sys_enter_*` / `sys_exit_*` tracepoint 定义完全一致。

### 1.3 CO-RE（Compile Once – Run Everywhere）

传统 eBPF 开发需要在目标机器上使用对应版本的 kernel headers 进行编译，否则结构体字段偏移错误会导致加载失败。

本项目采用 **CO-RE** 方案：
1. 通过 `bpftool btf dump file /sys/kernel/btf/vmlinux format c` 从编译机（或参考机）导出 `vmlinux.h`。
2. C 代码中使用 `__attribute__((preserve_access_index))`（由 `#pragma clang attribute push` 在 `vmlinux.h` 中自动开启）。
3. `bpf2go` 编译时生成 BTF 重定位信息，嵌入到 ELF 对象中。
4. 目标机器加载时，libbpf（cilium/ebpf 内部逻辑）根据**目标内核当前 BTF** 自动修正结构体偏移。

**结果**：一个二进制文件可以直接分发到不同内核版本（同架构）的机器上运行，无需 kernel-headers、无需重新编译。

### 1.4 事件流转详解

#### execve 监控
- `sys_enter_execve`：进入 execve 时触发。通过 `ctx->args[0]` 读取用户态 filename 字符串，连同 pid、comm 写入 ringbuf。
- `sys_exit_execve`：execve 返回时触发。记录返回值（0 表示成功，负数为错误码），用于确认命令是否真正执行成功。

#### connect 监控
- `sys_enter_connect`：进入 connect 时触发。`ctx->args[1]` 为用户态传入的 `struct sockaddr *`。
- 使用 `bpf_probe_read_user()` 直接拷贝 128 字节 sockaddr 原始数据到 ringbuf，**不在内核态做字符串解析**（减少 verifier 复杂度和指令数）。
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

| 组件 | 最低版本 | 说明 |
|------|---------|------|
| Linux 内核 | 5.8+ | 需要支持 BTF 和 ringbuf，以便本地编译和测试加载 |
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

### 3.1 内核版本要求

| 特性 | 内核版本 | 本项目是否必须 |
|------|---------|--------------|
| eBPF 基础支持 | 4.1+ | 是 |
| BPF Map Type: HASH | 3.19+ | 是 |
| tracepoint raw syscalls | 4.17+ | 是 |
| BTF (BPF Type Format) | 5.2+ | **是（CO-RE 必需）** |
| Ringbuf | 5.8+ | **是（当前实现）** |
| `bpf_probe_read_user` | 5.5+ | 是 |

**结论**：
- **推荐运行环境**：内核 **5.8+** 且开启 BTF。
- **典型适配发行版**：
  - RHEL 9 / CentOS Stream 9 / Rocky Linux 9 / AlmaLinux 9（内核 5.14+）
  - Ubuntu 22.04+ / Debian 12+
  - 各类云服务器 5.8+ 定制内核

### 3.2 运行前自检脚本

在目标机器上执行以下检查：

```bash
#!/bin/bash
set -e

echo "=== eBPF 运行环境自检 ==="

# 1. 内核版本
KVER=$(uname -r | cut -d- -f1)
echo "内核版本: $KVER"

# 2. 检查 BTF
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "[OK] BTF 已开启 (/sys/kernel/btf/vmlinux 存在)"
else
    echo "[FAIL] BTF 未开启。当前二进制无法运行，需换用非 CO-RE 方案。"
    exit 1
fi

# 3. 检查 ringbuf 支持（通过 bpftool 查看 feature，或直接判断内核版本）
MAJOR=$(echo $KVER | cut -d. -f1)
MINOR=$(echo $KVER | cut -d. -f2)
if [ "$MAJOR" -gt 5 ] || ([ "$MAJOR" -eq 5 ] && [ "$MINOR" -ge 8 ]); then
    echo "[OK] 内核 >= 5.8，支持 ringbuf"
else
    echo "[FAIL] 内核 < 5.8，不支持 ringbuf。当前二进制无法运行。"
    exit 1
fi

# 4. 检查 CAP_BPF / root
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
| `loadTraceObjects: ... BTF not found` | 目标内核未开启 BTF | 换内核或改用非 CO-RE 方案 |
| `failed to attach sys_enter_accept4: tracepoint not found` | 内核裁剪了该 tracepoint | 程序会跳过并打印 Warning，不影响其他事件 |
| `Failed to open ring buffer: invalid argument` | 内核 < 5.8 | 改用 perf buffer 方案 |
| `operation not permitted` | 权限不足 / SELinux/AppArmor 限制 | 使用 root，或检查安全策略 |

---

## 4. 开发过程

### 4.1 文件结构

```
.
├── bpf/
│   ├── vmlinux.h          # BTF 导出的内核结构体定义（CO-RE 核心）
│   └── trace.bpf.c        # eBPF 内核程序
├── main.go                # Go 加载器：加载、附加、消费、解析
├── Makefile               # 一键构建
├── go.mod / go.sum        # Go 依赖
└── ebpf-tracepoint        # 最终独立二进制（静态链接）
```

### 4.2 eBPF C 代码开发要点 (`bpf/trace.bpf.c`)

#### 4.2.1 tracepoint 上下文

`sys_enter_*` 的上下文统一为：
```c
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;                    // 系统调用号
    long unsigned int args[6];      // 参数寄存器
    char __data[0];
};
```

`sys_exit_*` 的上下文为：
```c
struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    long int id;
    long int ret;                   // 返回值
    char __data[0];
};
```

通过 `ctx->args[N]` 即可访问 syscall 参数，无需处理 `pt_regs`，这是 tracepoint 比 kprobe 更简洁的地方。

#### 4.2.2 用户态内存读取

- `bpf_probe_read_user_str(dst, size, src)`：读取以 `\0` 结尾的字符串（如 filename）。
- `bpf_probe_read_user(dst, size, src)`：读取定长二进制（如 sockaddr）。
- 这两个 helper 在无效地址上**不会 panic 内核**，而是返回错误码，verifier 要求必须做好边界控制。

#### 4.2.3 Map 定义（BTF-style）

使用 `SEC(".maps")` + BTF 风格的 map 定义，cilium/ebpf 可以自动解析：
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```

### 4.3 Go 加载器开发要点 (`main.go`)

#### 4.3.1 go:generate 与 bpf2go

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//  -cc clang \
//  -cflags "-O2 -g -Wall -Werror -I/usr/include -I./bpf" \
//  -target bpfel,bpfeb \
//  trace bpf/trace.bpf.c
```

参数说明：
- `-cc clang`：指定 eBPF 编译器。
- `-cflags`：头文件搜索路径。`-I/usr/include` 用于 libbpf 头文件，`-I./bpf` 用于 `vmlinux.h`。
- `-target bpfel,bpfeb`：同时生成 **小端** 和 **大端** 两份 eBPF 对象。
- `trace`：生成文件前缀，最终产生 `trace_bpfel.go`、`trace_bpfeb.go` 等。

#### 4.3.2 多架构自动选择

bpf2go 生成的文件顶部包含 Go build tags：

```go
// trace_bpfel.go
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64 || wasm
```

```go
// trace_bpfeb.go
//go:build mips || mips64 || ppc64 || s390x
```

Go 编译器会根据 `GOARCH` 自动选择对应的文件，因此一份代码可以编译出适配多架构的二进制。

#### 4.3.3 优雅降级：单点 attach 失败不退出

```go
attachments[2].l, attachments[2].err = link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSysEnterConnect, nil)
// ...
if attachments[i].err != nil {
    fmt.Fprintf(os.Stderr, "Warning: failed to attach %s: %v\n", attachments[i].name, attachments[i].err)
} else {
    attached++; defer attachments[i].l.Close()
}
```

某些精简内核可能缺少个别 tracepoint，程序不会直接崩溃，而是继续挂载其他可用的事件源。

### 4.4 构建流程

```bash
# 1. 生成 eBPF → Go（由 go:generate 自动调用 bpf2go）
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

## 5. 适配规则

### 5.1 内核版本适配矩阵

| 目标系统 | 典型内核 | BTF | Ringbuf | 当前二进制兼容性 | 建议方案 |
|---------|---------|-----|---------|----------------|---------|
| CentOS 7 / RHEL 7 | 3.10 | ❌ | ❌ | **不兼容** | 使用 auditd / systemtap / bcc |
| CentOS 8 / RHEL 8 | 4.18 | ❌（默认关闭） | ❌ | **不兼容** | 改用 perf buffer + 传统 kernel-headers 编译 |
| CentOS Stream 9 / RHEL 9 / Rocky 9 / AlmaLinux 9 | 5.14 | ✅ | ✅ | **完全兼容** | 直接使用本二进制 |
| Ubuntu 20.04 | 5.4 | ⚠️ 可选 | ❌ | **不兼容** | 需升级内核至 5.8+ |
| Ubuntu 22.04+ | 5.15+ | ✅ | ✅ | **完全兼容** | 直接使用本二进制 |
| 云厂商容器安全加固内核 | 5.10~6.x | 视厂商 | 视厂商 | 需检测 BTF | 先运行自检脚本 |

### 5.2 CPU 架构适配规则

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

> bpf2go 已通过 `-target bpfel,bpfeb` 预生成了大小端两份 eBPF 对象，交叉编译时 Go 会根据 `GOARCH` 自动选择正确的那份。

### 5.3 从 CO-RE 降级到非 CO-RE（CentOS 8 兼容思路）

如果必须支持 CentOS 8（4.18），需要以下改造：

1. **替换 Ringbuf → Perf Buffer**
   - `BPF_MAP_TYPE_RINGBUF` 改为 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`。
   - Go 侧使用 `perf.NewReader` 替代 `ringbuf.NewReader`。

2. **移除 BTF/CO-RE 依赖**
   - 删除 `vmlinux.h`，改用 `<linux/ptrace.h>`、`<linux/socket.h>` 等标准内核头文件。
   - 移除 `#pragma clang attribute push`。
   - 直接在目标机上安装 `kernel-devel-$(uname -r)`，使用本地头文件编译。

3. **降级 bpf_probe_read_user**
   - 内核 4.18 没有 `bpf_probe_read_user`，统一替换为 `bpf_probe_read`。

4. **加载方式调整**
   - cilium/ebpf 在非 BTF 内核上加载时，需显式关闭某些 BTF 特性，或完全改用 libbpf C 加载器 + `skel` 方案。

**评估**： CentOS 8 的改造成本较高，且失去"独立二进制分发"的优势（必须在目标机有对应 headers）。建议优先推动业务升级到 RHEL 9 系列内核。

### 5.4 添加新的 tracepoint 事件

如需扩展（如 `bind`、`listen`、`sendto`）：

1. 在 `trace.bpf.c` 中增加新的 `SEC("tp/syscalls/sys_enter_xxx")` 函数。
2. 如需 enter/exit 配对，参照 `accept4` 使用临时 HASH map 保存中间态。
3. 定义新的 `EVENT_xxx` type。
4. 在 `main.go` 中增加对应的 `EventType` 常量、`link.Tracepoint` attach 逻辑、以及 `printEvent` 解析分支。
5. 重新执行 `go generate ./... && go build`。

---

## 6. 快速开始

```bash
# 构建
make build

# 运行环境自检
sudo ./check_env.sh

# 运行
sudo ./ebpf-tracepoint

# 示例输出
# TYPE     PID    COMM             RET/FD       DATA
# EXEC     1234   bash                          /usr/bin/curl
# EXECRET  1234   curl             0
# CONNECT  1234   curl                          127.0.0.1:8080
# ACCEPT   5678   python3          fd=4         127.0.0.1:54320
```

### 6.1 GitHub Actions 自动发版

推送以 `v` 开头的 tag 即可触发 Release CI，自动编译 `linux/amd64` 与 `linux/arm64` 两个架构的静态二进制，并发布到 GitHub Release：

```bash
git tag v0.1.0
git push origin v0.1.0
```

也可在仓库的 **Actions → Release → Run workflow** 中手动触发。

---

## 7. 附录：核心参考

- [cilium/ebpf Documentation](https://pkg.go.dev/github.com/cilium/ebpf)
- [BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [Linux Kernel Tracepoint API](https://docs.kernel.org/trace/tracepoints.html)
- [BPF Ring Buffer](https://nakryiko.com/posts/bpf-ringbuf/)
