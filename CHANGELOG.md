# Changelog

## [0.2.3] - 2026-04-23

### 修复
- **CentOS 7 兼容模式 map BTF 加载失败**：在 CentOS 7 (3.10.0-862) 上，兼容模式报错 `load BTF: detect support for Map BTF (Var/Datasec): function not implemented`。
  - 根因：`cilium/ebpf` 在创建 map 时发现 `MapSpec.Key` / `MapSpec.Value` 不为 nil，尝试检测内核 Map BTF 支持性。CentOS 7 的 3.10 内核不支持 Map BTF，`bpf(BTF_LOAD)` 返回 `ENOSYS`。
  - 修复：在 `legacy.go` 加载兼容对象前，清空所有 map 的 `Key` 和 `Value` BTF 字段，使 `cilium/ebpf` 以传统方式创建 map。

---

## [0.2.2] - 2026-04-23

### 修复
- **CentOS 7 memlock 解除失败**：在 CentOS 7 (3.10.0-862) 上，`rlimit.RemoveMemlock()` 报错 `unexpected error detecting memory cgroup accounting: function not implemented`。
  - 根因：`cilium/ebpf` 的 `RemoveMemlock` 在内部检测 cgroup 内存会计时调用了老内核不支持的系统调用。
  - 修复：`RemoveMemlock` 失败时，降级到 `unix.Getrlimit` + `unix.Setrlimit` 手动解除 memlock 限制。

---

## [0.2.1] - 2026-04-23

### 修复
- **兼容模式加载失败**：在 Oracle Linux 8 (UEK 5.4.x)、CentOS 7/8 等无 BTF 内核上，兼容模式报错 `apply CO-RE relocations: no BTF found`。
  - 根因：`bpf2go` 编译 `trace_legacy.bpf.c` 时，`vmlinux.h` 中的 `#pragma clang attribute push (__attribute__((preserve_access_index)))` 导致 `.BTF.ext` 生成 CO-RE 重定位记录。
  - 修复：为兼容版编译添加 `-DBPF_NO_PRESERVE_ACCESS_INDEX`，禁用 `preserve_access_index` 属性。`.BTF.ext` 中不再包含 `core_reloc` 段，但保留 `.BTF` 段用于 `cilium/ebpf` 解析 BTF-style map 定义。

---

## [0.2.0] - 2026-04-23

### 重大变更
- **双模式内核自适应**：运行时自动检测内核版本，≥ 5.8 使用现代模式（ringbuf + BTF/CO-RE），< 5.8 自动降级到兼容模式（perf buffer + legacy helper）。一套二进制同时覆盖 4.x ~ 6.x 内核。

### 新增
- 新增 `bpf/trace_legacy.bpf.c`：面向 4.x / CentOS 7 / CentOS 8 老内核的 eBPF 兼容程序。
  - 使用 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 替代 ringbuf。
  - 使用 `bpf_probe_read` / `bpf_probe_read_str` 替代 5.5+ 才引入的 `_user` 变体。
  - 保留 `accept4` enter/exit 配对、sockaddr 透传等核心逻辑。
- 新增 `modern.go`：抽取原 `main.go` 中 5.8+ 的 ringbuf 加载与消费逻辑。
- 新增 `legacy.go`：4.x 兼容模式的 perf buffer 加载与消费逻辑。
- 自动生成 `trace_legacy_bpfel.go` / `trace_legacy_bpfeb.go` 及对应 ELF 对象。

### 变更
- `main.go` 重构为纯入口层：
  - 负责环境检测（内核版本、权限、memlock）。
  - 根据内核版本自动分发到 `runModern()` 或 `runLegacy()`。
  - `Event` 结构体、`printEvent`、`parseSockaddr` 等解析逻辑继续全局复用。
- 现代模式（≥ 5.8）的行为保持不变：BTF 检查、ringbuf 消费、CO-RE 加载。
- 兼容模式（< 5.8）不再检查 BTF 与 ringbuf，直接加载 legacy eBPF 对象。

### 兼容性
| 目标系统 | 典型内核 | 支持模式 |
|---------|---------|---------|
| CentOS 7 / RHEL 7 | 3.10 | 兼容模式 ✅ |
| CentOS 8 / RHEL 8 | 4.18 | 兼容模式 ✅ |
| Ubuntu 20.04 | 5.4 | 兼容模式 ✅ |
| Ubuntu 22.04+ / RHEL 9+ | 5.15+ / 5.14+ | 现代模式 ✅ |
| 云厂商定制内核 | 5.8 ~ 6.x | 现代模式 ✅ |

---

## [0.1.0] - 2026-04-23

### 新增
- **选择性追踪**：新增 `-execve` 和 `-net` 命令行参数，可单独追踪 execve 或网络相关系统调用。
- **环境自检**：启动时自动检测内核版本、BTF 可用性、root 权限、memlock 限制，并给出明确的中文提示。
- **GitHub Actions Release CI**：`.github/workflows/release.yml`，推送 `v*` tag 自动编译 `linux/amd64` 与 `linux/arm64` 静态二进制并发布 Release。
- **优雅降级**：单个 tracepoint attach 失败不再导致程序退出，而是打印 Warning 并继续挂载其他可用事件。

### 变更
- `main.go` 大幅重构：增加 CLI flag 解析、内核版本检查、BTF 检查、改进错误提示。
- README 增加 GitHub Actions 发版说明章节。

### 初始功能（继承自 initial commit）
- 基于 eBPF tracepoint 监控 `execve`（进入/退出）、`connect`、`accept4`。
- 内核态直接透传 `sockaddr` 原始字节，用户态 Go 程序解析 IPv4 / IPv6 地址。
- 使用 `BPF_MAP_TYPE_RINGBUF` 进行内核-用户态事件传输。
- 采用 CO-RE 方案，一个静态二进制可在同架构不同 5.8+ 内核间分发运行。
