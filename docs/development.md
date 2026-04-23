# 开发指南

## 1. 开发编译环境配置

### 1.1 系统要求（编译机）

> 编译机仍然建议 5.8+，因为生成现代版 eBPF 对象时需要本机 BTF。兼容版对象无需 BTF，但为了方便一次性生成两套对象，推荐在 5.8+ 环境编译。

| 组件 | 最低版本 | 说明 |
|------|---------|------|
| Linux 内核 | 5.8+ | 推荐，用于本地编译和测试现代模式 |
| Go | 1.24+ | 本项目使用 `github.com/cilium/ebpf v0.21.0` |
| Clang/LLVM | 14+ | 编译 eBPF C 代码到 ELF |
| bpftool | 任意 | 用于生成 `vmlinux.h` |
| libbpf-dev | 1.0+ | 提供 `<bpf/bpf_helpers.h>` 等头文件 |

### 1.2 Ubuntu/Debian 环境安装示例

```bash
# 基础工具链
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool

# Go（如系统版本过低，建议从官网下载）
# https://go.dev/dl/
```

### 1.3 项目初始化

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

## 2. 开发过程

### 2.1 文件结构

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

### 2.2 eBPF C 代码开发要点

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

### 2.3 Go 加载器开发要点

#### go:generate 与 bpf2go

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

#### 运行时自动分发

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

#### 优雅降级：单点 attach 失败不退出

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

### 2.4 构建流程

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

## 3. 适配规则

### 3.1 CPU 架构适配规则

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

### 3.2 添加新的 tracepoint 事件

如需扩展（如 `bind`、`listen`、`sendto`）：

1. 在 `trace.bpf.c` 和 `trace_legacy.bpf.c` 中同时增加新的 `SEC("tp/syscalls/sys_enter_xxx")` 函数。
2. 如需 enter/exit 配对，参照 `accept4` 使用临时 HASH map 保存中间态。
3. 定义新的 `EVENT_xxx` type。
4. 在 `main.go` 中增加对应的 `EventType` 常量，以及在 `modern.go` / `legacy.go` 中增加 `link.Tracepoint` attach 逻辑。
5. 在 `main.go` 的 `printEvent` 中增加解析分支。
6. 重新执行 `go generate ./... && go build`。
