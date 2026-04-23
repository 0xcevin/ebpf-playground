# eBPF Tracepoint 网络与进程行为追踪器

基于 eBPF tracepoint + Go 的轻量级系统调用追踪工具，可实时监控 `execve`、`connect`、`accept4` 三类核心系统调用。

**核心特性**：运行时自动检测内核版本，≥ 5.8 使用高性能 **ringbuf + BTF/CO-RE** 现代模式，< 5.8 自动降级到 **perf buffer** 兼容模式。一套静态二进制同时覆盖 RHEL/CentOS/Oracle 7.6+ 回移植内核 (3.10) ~ 最新 6.x 内核。

---

## 文档索引

| 文档 | 内容 |
|------|------|
| [docs/architecture.md](docs/architecture.md) | 程序原理、整体架构、双模式设计、事件流转、数据结构 |
| [docs/deployment.md](docs/deployment.md) | 运行环境检测、内核适配矩阵、缓冲区配置、流量预警、故障排查 |
| [docs/development.md](docs/development.md) | 开发编译环境、文件结构、构建流程、添加新 tracepoint |
| [docs/output-format.md](docs/output-format.md) | 启动信息与事件输出的详细字段解析 |

---

## 快速开始

### 构建

```bash
make build
```

> 若修改了 `bpf/*.bpf.c`，需先执行 `go generate ./...` 重新生成 eBPF ELF 对象。详见 [docs/development.md](docs/development.md)。

### 运行

```bash
# 追踪所有事件（自动检测内核版本选择模式）
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

> 输出字段的详细解析请见 [docs/output-format.md](docs/output-format.md)。

---

## GitHub Actions 自动发版

推送以 `v` 开头的 tag 即可触发 Release CI，自动编译 `linux/amd64` 与 `linux/arm64` 两个架构的静态二进制，并发布到 GitHub Release：

```bash
git tag v0.2.0
git push origin v0.2.0
```

也可在仓库的 **Actions → Release → Run workflow** 中手动触发。

---

## 附录：核心参考

- [cilium/ebpf Documentation](https://pkg.go.dev/github.com/cilium/ebpf)
- [BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [Linux Kernel Tracepoint API](https://docs.kernel.org/trace/tracepoints.html)
- [BPF Ring Buffer](https://nakryiko.com/posts/bpf-ringbuf/)
