# 流量统计扩展至兼容模式 — 实现步骤

> 状态：待实现  
> 目标：将现代模式的单连接流量统计与预警功能，完整移植到兼容模式（内核 < 5.8）。

---

## 背景

现代模式（≥ 5.8）已实现：
- 内核态累加单连接的 `rx_bytes` / `tx_bytes`
- `-flow-threshold-mb` 参数控制预警阈值
- 覆盖 `write/read/sendto/recvfrom/close` 五组 tracepoint
- 通过 ringbuf 实时上报 `FLOW` 预警事件

兼容模式（< 5.8）目前仅有 `execve/connect/accept4` 基础追踪，缺少流量统计能力。

---

## 实现步骤

### Step 1：同步 `struct event` 大小（必须先做）

现代模式已把 `struct event` 从 288 字节扩展到 **312 字节**。兼容模式的 C 代码和 Go 代码必须保持**完全一致**，否则 Go 端 `binary.Read` 解析会错位。

**文件**：`bpf/trace_legacy.bpf.c`

```c
struct event {
    u32 pid;
    u32 type;
    char comm[16];
    char data[256];
    s64 ret;
    // ===== 新增字段（与现代模式完全一致） =====
    u64 rx_bytes;
    u64 tx_bytes;
    u32 daddr;
    u16 dport;
    u16 family;
};
```

> ⚠️ 注意：不要调整字段顺序，否则内存布局对不齐。

---

### Step 2：在 `trace_legacy.bpf.c` 中新增 map 和结构体

**复制现代模式的以下定义**（放在 `pb` map 之后即可）：

1. `struct conn_key` / `struct conn_info`
2. `conn_stats_map`（BPF_MAP_TYPE_HASH, max_entries=4096）
3. `io_enter_args`（BPF_MAP_TYPE_HASH, max_entries=1024, key=u32 pid, value=u32 fd）
4. `config_map`（BPF_MAP_TYPE_ARRAY, max_entries=1, 存放 threshold）
5. `struct config`（tx_threshold / rx_threshold）

---

### Step 3：添加辅助函数

**复制现代模式的两个函数到 `trace_legacy.bpf.c`**，但把 `bpf_probe_read_user` 替换为 `bpf_probe_read`：

```c
static __always_inline void parse_sockaddr_to_conn(...)
static __always_inline void check_and_alert(...)
```

**替换点**：
- `bpf_probe_read_user` → `bpf_probe_read`
- `bpf_ringbuf_reserve` / `bpf_ringbuf_submit` → `bpf_perf_event_output`

---

### Step 4：改造 `check_and_alert` 中的事件发送逻辑

现代模式用 ringbuf：
```c
struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
// ... 填充 ...
bpf_ringbuf_submit(e, 0);
```

兼容模式改用 perf buffer，**需要 `ctx` 参数**：
```c
struct event e = {};
// ... 填充 ...
bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));
```

> 关键区别：`check_and_alert` 的签名需要增加 `struct trace_event_raw_sys_exit *ctx`（或 `struct trace_event_raw_sys_enter *ctx`），因为 `bpf_perf_event_output` 第一个参数必须是 `struct pt_regs *` 或 tracepoint 的 `ctx`。

---

### Step 5：添加 write/read/sendto/recvfrom/close tracepoint

**复制现代模式的 9 个 tracepoint 函数**，做以下替换：

| 现代模式 | 兼容模式替换 |
|---------|------------|
| `bpf_probe_read_user` | `bpf_probe_read` |
| `bpf_ringbuf_reserve` | 无需保留，直接用栈变量 + `bpf_perf_event_output` |
| `submit_event(e)` | `bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e))` |

**需要添加的 tracepoint**：
- `sys_enter_write` / `sys_exit_write`
- `sys_enter_read` / `sys_exit_read`
- `sys_enter_sendto` / `sys_exit_sendto`
- `sys_enter_recvfrom` / `sys_exit_recvfrom`
- `sys_enter_close`

---

### Step 6：修改现有的 `connect` 和 `accept4_exit`

在原有事件上报逻辑之后，**插入 `conn_stats_map` 记录逻辑**：

- `sys_enter_connect`：创建 `conn_key`，记录目标地址到 `conn_info`
- `sys_exit_accept4`：如果 `ret >= 0`，用返回的 fd 创建 `conn_key`，记录对端地址

> 注意：兼容模式的 `sys_exit_accept4` 已有 `cleanup` 标签，新增逻辑要放在 `bpf_map_delete_elem(&accept4_sockaddr, &pid)` 之前。

---

### Step 7：`go generate` 重新编译兼容版 eBPF 对象

```bash
cd /home/admin/ebpf-playground
go generate ./...
```

这会重新生成：
- `trace_legacy_bpfel.go` / `trace_legacy_bpfel.o`
- `trace_legacy_bpfeb.go` / `trace_legacy_bpfeb.o`

---

### Step 8：修改 `legacy.go`

#### 8.1 修改 `runLegacy` 签名
```go
func runLegacy(attachExecve, attachNet bool, perfPerCPUSize int, flowThresholdBytes uint64)
```

#### 8.2 加载前设置 `config_map` 阈值（参考 modern.go）
```go
if flowThresholdBytes > 0 {
    if cfgMap, ok := spec.Maps["config_map"]; ok {
        cfgMap.Contents = []ebpf.MapKV{
            {Key: uint32(0), Value: struct {
                TxThreshold uint64
                RxThreshold uint64
            }{TxThreshold: flowThresholdBytes, RxThreshold: flowThresholdBytes}},
        }
    }
}
```

#### 8.3 挂载 write/read/sendto/recvfrom/close tracepoint

在 `legacy.go` 的 attach 段中，**无条件追加**以下 5 组 tracepoint（流量统计的基础）：

```go
link.Tracepoint("syscalls", "sys_enter_write", objs.TracepointSysEnterWrite, nil)
link.Tracepoint("syscalls", "sys_exit_write", objs.TracepointSysExitWrite, nil)
link.Tracepoint("syscalls", "sys_enter_read", objs.TracepointSysEnterRead, nil)
link.Tracepoint("syscalls", "sys_exit_read", objs.TracepointSysExitRead, nil)
link.Tracepoint("syscalls", "sys_enter_sendto", objs.TracepointSysEnterSendto, nil)
link.Tracepoint("syscalls", "sys_exit_sendto", objs.TracepointSysExitSendto, nil)
link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TracepointSysEnterRecvfrom, nil)
link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.TracepointSysExitRecvfrom, nil)
link.Tracepoint("syscalls", "sys_enter_close", objs.TracepointSysEnterClose, nil)
```

> 注意：兼容模式生成的 `trace_legacyObjects` 中会自动包含这些 program 字段（因为 bpf2go 会扫描 C 代码中的 SEC）。

---

### Step 9：修改 `main.go` 的调用点

确保 `main.go` 中调用 `runLegacy` 时也传入 `flowThresholdBytes`：

```go
runLegacy(attachExecve, attachNet, perfPerCPUSize, flowThresholdBytes)
```

> 当前代码如果已按现代模式修改，此步通常只需确认参数顺序一致。

---

### Step 10：编译与验证

```bash
# 1. 编译 Go 端
go build -o ebpf-tracepoint .

# 2. 在现代内核上验证兼容模式强制加载（可选）
# 可通过环境变量或代码临时跳过内核版本检测，强制走 legacy 路径

# 3. 在目标老内核机器上验证
sudo ./ebpf-tracepoint -net -flow-threshold-mb 1
# 触发 curl 下载大文件，观察是否输出 FLOW 预警
```

---

## 潜在风险与应对

| 风险 | 应对方案 |
|------|---------|
| 老内核 verifier 指令超限 | `check_and_alert` 精简逻辑，必要时拆分为两个函数（`check_tx_alert` / `check_rx_alert`） |
| `bpf_perf_event_output` 事件大小受限 | 312 字节通常安全；如失败，尝试减小 `DATA_LEN` 从 256 → 128 |
| 精简内核缺少 `sys_enter_sendto` 等 tracepoint | attach 失败时打印 Warning，不影响其他 tracepoint 继续工作 |
| 高频 IO 导致性能下降 | 用户态默认 `-flow-threshold-mb 0`（关闭），显式开启时才挂载 |

---

## 完成后应更新的文档

- [ ] `CHANGELOG.md`：补充兼容模式流量统计说明
- [ ] `README.md`：「流量预警」章节去掉"仅现代模式"的限制描述
- [ ] 本计划文件：标记为已完成或归档
