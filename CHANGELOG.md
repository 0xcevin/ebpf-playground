# Changelog

## [0.3.4] - 2026-04-24

### 新增
- **RHEL 9 / AlmaLinux 9 环境检测与报错增强**：显著降低 `cannot create bpf perf link: permission denied` 的排查成本。
  - `main.go`：启动时自动检测 Kernel Lockdown（Secure Boot）、SELinux Enforcing、`perf_event_paranoid`，并在日志中直接列出修复命令。
  - `modern.go` / `legacy.go`：当 `link.Tracepoint` attach 返回 `permission denied` 时，自动追加三条根因分析与对应操作提示（关闭 Secure Boot / setenforce 0 / 调整 perf_event_paranoid）。

### 文档
- 新增 `docs/releases/v0.3.4.md`。
- CHANGELOG.md 追加 v0.3.4 条目。

---

## [0.3.3] - 2026-04-24

### 修复
- **兼容模式 execve 追踪失败**：CentOS 7 (3.10.0-957) 等老内核缺少 `syscalls:sys_enter_execve` tracepoint，导致 `-execve` 无输出。
  - 在 `bpf/trace_legacy.bpf.c` 中新增 `kprobe/sys_execve` 与 `kretprobe/sys_execve`。
  - `legacy.go` 在 tracepoint attach 失败后自动 fallback 到 `link.Kprobe` / `link.Kretprobe`。
- **CI arm64 编译失败**：v0.3.2 将 legacy 的 `go:generate` target 误改为 `amd64`，导致 `GOARCH=arm64` 构建缺失 `loadTrace_legacy`。
  - `main.go`：恢复为 `amd64,arm64` 双 target，bpf2go 同时生成双架构对象。
  - `bpf/trace_legacy.bpf.c`：使用架构内联寄存器访问宏（`KP_PARM1` / `KP_RET`）替代 `bpf_tracing.h` 的 `PT_REGS_*`，避免 arm64 缺少 `struct user_pt_regs` 定义。

---

## [0.3.2] - 2026-04-24

### 修复
- **兼容模式 execve 追踪失败**：CentOS 7 (3.10.0-957) 等老内核缺少 `syscalls:sys_enter_execve` tracepoint，导致 `-execve` 无输出。
  - 在 `bpf/trace_legacy.bpf.c` 中新增 `kprobe/sys_execve` 与 `kretprobe/sys_execve`，通过 `pt_regs` 读取参数和返回值。
  - `legacy.go` 在 tracepoint attach 失败后自动 fallback 到 `link.Kprobe` / `link.Kretprobe`。
  - 事件格式与 tracepoint 版完全一致，用户侧无感知。

---

## [0.3.1] - 2026-04-23

### 新增
- **兼容模式流量统计**：连接级流量统计与预警功能扩展至兼容模式（内核 < 5.8）。
  - `bpf/trace_legacy.bpf.c` 完整移植现代模式的流量累加与预警逻辑。
  - 覆盖 `write/read/sendto/recvfrom/close` 五组 tracepoint。
  - 使用 `bpf_perf_event_output` 替代 ringbuf 发送预警事件。
  - `legacy.go` 支持 `-flow-threshold-mb` 参数，与现代模式行为一致。

### 文档
- README.md 与 CHANGELOG.md 更新：流量预警不再限于现代模式。

---

## [0.3.0] - 2026-04-23

### 新增
- **动态缓冲区配置**：新增 `-buffer-level` 命令行参数，支持三级缓冲区大小（1=小, 2=中, 3=大）。
  - 现代模式（ringbuf）：level 1=256 KB, level 2=1 MB, level 3=4 MB。
  - 兼容模式（perf buffer）：level 1=16 KB/CPU, level 2=64 KB/CPU, level 3=256 KB/CPU。
  - 运行时根据内核模式自动应用对应配置，无需重新编译 eBPF 对象。
- **连接级流量统计与预警**：
  - 内核态实时累加每个 socket 连接的 `rx_bytes` / `tx_bytes`。
  - 新增 `-flow-threshold-mb` 参数，当单条连接的收发流量超过阈值时，实时发送 `FLOW` 预警事件。
  - 覆盖 `write`/`read`/`sendto`/`recvfrom` 四类 IO 系统调用，适配绝大多数网络程序。
  - 连接关闭（`close`）时自动清理统计 map，避免内存泄漏。
  - 预警事件包含：进程名、PID、对端 IP:Port、累计 RX/TX 大小、预警类型（TX/RX）。
  - **双模式支持**：现代模式（ringbuf）与兼容模式（perf buffer）均支持流量预警。

### 文档
- README.md 新增「缓冲区配置」章节，详细说明两种模式的缓冲机制差异、等级换算表及选型建议。

---

## [0.2.5] - 2026-04-23

### 新增
- **环境检测增强**：启动时同时打印内核版本与系统版本（读取 `/etc/os-release`）。
- **按需加载 eBPF 对象**：根据 `-execve` / `-net` 参数，在加载前从 CollectionSpec 中剔除不需要的 program 和 map，避免老内核因未使用对象而加载失败。
- **bpf syscall 可用性探测**：运行时探测 `bpf(2)` 系统调用是否实现，若返回 `ENOSYS` 则提前退出并给出友好提示。
- **最低内核版本拦截**：明确不支持低于 Linux 3.10 的内核；所有版本提示统一为 **4.7+**。

### 文档
- 更新 README.md 与 CHANGELOG.md 的发行版支持矩阵，覆盖 CentOS/RHEL、Rocky Linux、AlmaLinux、Oracle Linux、Ubuntu、Debian。
- 明确说明：3.10 内核仅限 **RHEL 系 7.6+ 回移植版本**支持，上游 3.10 不支持。

---

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
| 发行版 | 版本 | 典型内核 | 支持模式 |
|--------|------|---------|---------|
| CentOS / RHEL | 7.5 及以下 | 3.10.0-862 等 | ❌ 不支持 (无 eBPF) |
| CentOS / RHEL / Oracle | 7.6+ | 3.10.0-957+ (RHEL 回移植) | 兼容模式 ✅ |
| CentOS / RHEL | 8.x | 4.18 | 兼容模式 ✅ |
| CentOS Stream / RHEL | 9.x | 5.14+ | 现代模式 ✅ |
| Rocky Linux | 8.x / 9.x | 4.18 / 5.14+ | 兼容/现代 ✅ |
| AlmaLinux | 8.x / 9.x | 4.18 / 5.14+ | 兼容/现代 ✅ |
| Oracle Linux | 7.6+ / 8.x | 3.10.0-957+ / 5.4+ | 兼容/现代 ✅ |
| Ubuntu | 18.04 / 20.04 / 22.04+ | 4.15 / 5.4 / 5.15+ | 兼容/现代 ✅ |
| Debian | 9 / 10 / 11 / 12 | 4.9 / 4.19 / 5.10 / 6.1 | 兼容/现代 ✅ |
| 云厂商定制内核 | — | 5.8 ~ 6.x | 现代模式 ✅ |

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
