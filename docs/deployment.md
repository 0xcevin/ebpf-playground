# 运行环境与部署指南

## 1. 运行环境检测

### 1.1 内核版本适配矩阵

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

### 1.2 运行前自检脚本

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

### 1.3 常见失败场景

| 现象 | 根因 | 解决方案 |
|------|------|---------|
| `loadTraceObjects: ... BTF not found` | 目标内核未开启 BTF | 程序会自动降级到兼容模式，无需手动处理 |
| `failed to attach sys_enter_accept4: tracepoint not found` | 内核裁剪了该 tracepoint | 程序会跳过并打印 Warning，不影响其他事件 |
| `Failed to open ring buffer: invalid argument` | 内核 < 5.8 | 程序会自动使用 perf buffer 兼容模式 |
| `operation not permitted` | 权限不足 / SELinux/AppArmor 限制 | 使用 root，或检查安全策略 |

## 2. 缓冲区配置

程序通过 `-buffer-level` 参数提供三级缓冲区大小，用于平衡内存占用与事件丢失风险。

### 2.1 两种模式的缓冲机制差异

| 模式 | 缓冲类型 | 数量 | 配置影响 | 当前配置显示 |
|------|---------|------|---------|-------------|
| **现代模式** (≥ 5.8) | `BPF_MAP_TYPE_RINGBUF` | **全局 1 个** | 直接设定总大小 | `ringbuf 大小: X MB` |
| **兼容模式** (< 5.8) | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | **每 CPU 1 个** | 设定单 CPU 大小，总量 = 单 CPU × 核数 | `perf buffer 大小: X KB/CPU` |

### 2.2 等级换算表

| `-buffer-level` | 现代模式 (ringbuf) | 兼容模式 (perf buffer / CPU) | 适用场景 |
|----------------|-------------------|---------------------------|---------|
| **1** | 256 KB | 16 KB | 开发测试、低负载、内存敏感环境 |
| **2** (默认) | **1 MB** | **64 KB** | 通用生产环境，大多数场景够用 |
| **3** | 4 MB | 256 KB | 高频网络追踪、高并发服务器、防止 burst 丢事件 |

### 2.3 如何选择

- **事件频率低**（如仅追踪 `execve`）：level 1 即可，`execve` 触发频率通常远低于网络连接。
- **普通生产环境**：level 2 默认，1 MB ringbuf 可缓冲约 3400 个事件，64 KB/CPU perf buffer 可缓冲约 200 个事件/CPU。
- **高并发网络服务**（如 API 网关、数据库代理）：建议使用 **level 3**，或至少使用 `-net -buffer-level=3` 专门加大网络追踪的缓冲。

> **注意**：缓冲区占用的是**锁定的内核内存**（计入 memlock），但等级 3 的 4 MB ringbuf 或 `256 KB × CPU核数` 的 perf buffer 对现代服务器来说仍然非常小。

### 2.4 流量预警

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
