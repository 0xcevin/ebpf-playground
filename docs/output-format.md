# 输出格式解析

程序启动后会先输出环境检测与配置信息，随后进入事件追踪并输出实时事件。以下对各类输出内容做详细字段解析。

## 启动信息

```
=== eBPF Tracepoint 环境检测 ===
版本: v0.3.1
编译时间: 2026-04-23T12:00:00Z
编译环境: linux/amd64
编译内核: 6.8.0-63-generic
Go 版本: go1.24.1
内核版本: 6.8.0-63-generic
系统版本: Ubuntu 22.04.5 LTS
[OK] 当前为 root 用户
[OK] memlock 限制已解除
===================================

追踪模式: 全部
[MODE] 内核 >= 5.8，启用现代模式 (ringbuf + BTF)
[CONFIG] ringbuf 大小: 1 MB (level=2)
```

| 输出项 | 含义 |
|--------|------|
| `版本` | 程序版本号，编译时通过 `-ldflags -X Version=...` 注入 |
| `编译时间` | 二进制构建时间戳 |
| `编译环境` | 构建时的 OS/Arch |
| `编译内核` | 构建机内核版本（仅参考） |
| `Go 版本` | 编译所用的 Go 版本 |
| `内核版本` | 当前运行机的内核版本 |
| `系统版本` | 读取 `/etc/os-release` 得到的发行版信息 |
| `[OK/WARN]` 权限检查 | root 或 CAP_BPF 等权限状态 |
| `[OK/WARN]` memlock | 内核内存锁定限制是否已解除 |
| `追踪模式` | 根据 `-execve` / `-net` 参数显示当前追踪范围 |
| `[MODE]` | 现代模式 (`>=5.8`, ringbuf + BTF) 或兼容模式 (`<5.8`, perf buffer) |
| `[CONFIG]` | 缓冲区大小及等级，流量预警阈值（若开启） |

## 事件表头

```
TYPE     PID    COMM             RET/FD       DATA
```

| 字段 | 宽度 | 说明 |
|------|------|------|
| `TYPE` | 8 | 事件类型标识 |
| `PID` | 6 | 触发事件的进程 PID |
| `COMM` | 16 | 进程名（`bpf_get_current_comm` 获取，最长 16 字节，含截断） |
| `RET/FD` | 12 | 系统调用返回值（exit 事件）或 socket fd（accept4） |
| `DATA` | 可变 | 事件附加数据：execve 文件名、IP:Port 地址等 |

## 事件类型详解

### EXEC — `sys_enter_execve`

```
EXEC     1234   bash                          /usr/bin/curl
```

- `PID`: 发起 `execve` 的进程 PID
- `COMM`: 进程名（执行新程序前的旧名字）
- `DATA`: 被执行文件的完整路径（从 `ctx->args[0]` 读取的 `filename`）
- `RET/FD`: 空（enter 事件无返回值）

### EXECRET — `sys_exit_execve`

```
EXECRET  1234   curl             0
```

- `PID`: 同上
- `COMM`: 新进程名（execve 成功后内核已更新 `comm`）
- `RET/FD`: 系统调用返回值。`0` 表示成功；负数为错误码（如 `-2` 表示 `ENOENT` 文件不存在）
- `DATA`: 空

### CONNECT — `sys_enter_connect`

```
CONNECT  1234   curl                          127.0.0.1:8080
```

- `PID`: 发起连接的进程 PID
- `COMM`: 进程名
- `DATA`: 对端地址。IPv4 显示为 `IP:Port`；IPv6 显示为 `[IP]:Port`；非 INET 族显示 `family=N`
- `RET/FD`: 空（enter 事件）

> 地址解析发生在用户态 Go 端：内核态仅原样拷贝 128 字节的 `sockaddr`，用户态根据 `sa_family` 解析，以减少 eBPF verifier 复杂度。

### ACCEPT — `sys_exit_accept4`

```
ACCEPT   5678   python3          fd=4         127.0.0.1:54320
```

- `PID`: 接受连接的进程 PID
- `COMM`: 进程名
- `RET/FD`: 新建立的 socket 文件描述符（`fd=N`）
- `DATA`: 客户端地址，格式同 CONNECT

### FLOW — 流量预警（需开启 `-flow-threshold-mb`）

```
FLOW     845804 curl             ALERT=RX RX=1.00MB TX=0.09KB 90.130.70.73:80
FLOW     1135   AliYunDunMonito  ALERT=TX RX=3.46KB TX=1.00MB 100.100.188.188:443
```

- `PID`: 持有该连接的进程 PID
- `COMM`: 进程名
- `RET/FD`: 空，以 `ALERT=RX` 或 `ALERT=TX` 表示触发方向
- `RX`: 该连接累计接收流量（自动切换 KB/MB 单位）
- `TX`: 该连接累计发送流量（自动切换 KB/MB 单位）
- `DATA` 末尾: 对端地址（IPv4 `IP:Port`，IPv6 仅显示 `[IPv6]:Port`）

> 每个连接在超过阈值时**仅上报一次**，避免重复刷屏；连接 `close` 后 map 条目自动清理。

### UNKNOWN — 未识别事件类型

```
UNKNOWN  1234   someapp          -1           0000000000000000
```

- 当内核上报了程序未定义的 `type` 时触发（通常不会遇到）
- `DATA` 显示原始 `e.Data` 前 16 字节的十六进制，供调试使用
