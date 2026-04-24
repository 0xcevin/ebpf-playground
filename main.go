package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type execveEnterInfo struct {
	comm     string
	filename string
}

var execveEnterCache = make(map[uint32]execveEnterInfo)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include -I./bpf" -target bpfel,bpfeb trace bpf/trace.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -cflags "-O2 -Wall -Werror -I/usr/include -I./bpf -DBPF_NO_PRESERVE_ACCESS_INDEX" -target amd64,arm64 trace_legacy bpf/trace_legacy.bpf.c

type EventType uint32

const (
	EventExecveEnter EventType = 1
	EventExecveExit  EventType = 2
	EventConnect     EventType = 3
	EventAccept4Exit EventType = 4
)

type Event struct {
	Pid     uint32
	Type    uint32
	Comm    [16]byte
	Data    [256]byte
	Ret     int64
	RxBytes uint64
	TxBytes uint64
	Daddr   uint32
	Dport   uint16
	Family  uint16
}

var (
	flagExecve        bool
	flagNet           bool
	flagBufferLevel   int
	flagFlowThreshold int

	// 编译时通过 -ldflags -X 注入
	Version     = "dev"
	BuildTime   = "unknown"
	BuildOS     = "unknown"
	BuildArch   = "unknown"
	BuildKernel = "unknown"
	GoVersion   = "unknown"
)

func init() {
	flag.BoolVar(&flagExecve, "execve", false, "仅追踪 execve 系统调用")
	flag.BoolVar(&flagNet, "net", false, "仅追踪网络相关系统调用 (connect, accept4)")
	flag.IntVar(&flagBufferLevel, "buffer-level", 2, "事件缓冲区大小等级: 1=小(低负载/开发), 2=中(默认/生产), 3=大(高频网络)")
	flag.IntVar(&flagFlowThreshold, "flow-threshold-mb", 0, "流量预警阈值(MB): 当单条连接的收发流量超过此值时触发预警, 0=关闭")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "基于 eBPF tracepoint 的轻量级系统调用追踪工具。\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  sudo %s           # 追踪所有事件\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  sudo %s -execve   # 仅追踪 execve\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  sudo %s -net      # 仅追踪网络\n", path.Base(os.Args[0]))
	}
}

func main() {
	flag.Parse()

	fmt.Println("=== eBPF Tracepoint 环境检测 ===")

	// 1. 检查内核版本
	kver, kverOK := checkKernelVersion()
	fmt.Printf("版本: %s\n", Version)
	fmt.Printf("编译时间: %s\n", BuildTime)
	fmt.Printf("编译环境: %s/%s\n", BuildOS, BuildArch)
	fmt.Printf("编译内核: %s\n", BuildKernel)
	fmt.Printf("Go 版本: %s\n", GoVersion)
	fmt.Printf("内核版本: %s\n", kver)
	fmt.Printf("系统版本: %s\n", getOSVersion())

	// 分水岭：低于 3.10 的内核直接不支持
	major, minor := getKernelMajorMinor()
	if major < 3 || (major == 3 && minor < 10) {
		printEnvFail(fmt.Sprintf("当前内核版本 %d.%d 过低，本工具不支持低于 Linux 3.10 的内核。需要 CentOS/RHEL 7.6+ 或内核 4.7+。", major, minor))
	}

	// 2. 检查权限
	if os.Geteuid() != 0 {
		fmt.Println("[WARN] 当前非 root 用户。加载 eBPF 通常需要 root 或 CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN。")
	} else {
		fmt.Println("[OK] 当前为 root 用户")
	}

	// 3. 检查可能影响 eBPF tracepoint 的安全限制
	checkSecurityConstraints()

	// 4. 解除 memlock
	if err := rlimit.RemoveMemlock(); err != nil {
		// 老内核（如 CentOS 7 的 3.10）可能不支持 RemoveMemlock 内部的 cgroup 检测，降级到手动设置
		fmt.Fprintf(os.Stderr, "[WARN] rlimit.RemoveMemlock 失败: %v，尝试手动设置...\n", err)
		var rlim unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
			fmt.Fprintf(os.Stderr, "[FAIL] 无法获取 memlock 限制: %v\n", err)
			printEnvFail("请确保有足够的权限（root 或 CAP_SYS_RESOURCE）。")
		}
		rlim.Cur = rlim.Max
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
			fmt.Fprintf(os.Stderr, "[FAIL] 无法设置 memlock 限制: %v\n", err)
			printEnvFail("请确保有足够的权限（root 或 CAP_SYS_RESOURCE）。")
		}
		fmt.Println("[OK] memlock 限制已手动解除")
	} else {
		fmt.Println("[OK] memlock 限制已解除")
	}

	fmt.Println("===================================")
	fmt.Println()

	// 探测 eBPF 系统调用是否可用（CentOS 7.5 等老内核不支持 bpf syscall）
	if !bpfSyscallAvailable() {
		printEnvFail("当前内核不支持 eBPF 系统调用（bpf syscall 未实现），需要 CentOS/RHEL 7.6+ 或内核 4.7+。")
	}

	// 确定要 attach 的事件
	attachExecve := true
	attachNet := true
	if flagExecve || flagNet {
		attachExecve = flagExecve
		attachNet = flagNet
	}

	modeStr := "全部"
	if flagExecve && !flagNet {
		modeStr = "仅 execve"
	} else if flagNet && !flagExecve {
		modeStr = "仅网络 (connect, accept4)"
	}
	fmt.Printf("追踪模式: %s\n", modeStr)
	fmt.Println()

	// 计算缓冲区大小
	ringbufSize, perfPerCPUSize := calcBufferSizes(flagBufferLevel)
	flowThresholdBytes := uint64(flagFlowThreshold) * 1024 * 1024
	if flagFlowThreshold > 0 {
		fmt.Printf("[CONFIG] 流量预警阈值: %d MB\n", flagFlowThreshold)
	}

	// 根据内核版本选择模式
	if kverOK {
		fmt.Println("[MODE] 内核 >= 5.8，启用现代模式 (ringbuf + BTF)")
		if ringbufSize >= 1024*1024 {
			fmt.Printf("[CONFIG] ringbuf 大小: %d MB (level=%d)\n", ringbufSize/1024/1024, flagBufferLevel)
		} else {
			fmt.Printf("[CONFIG] ringbuf 大小: %d KB (level=%d)\n", ringbufSize/1024, flagBufferLevel)
		}
		runModern(attachExecve, attachNet, ringbufSize, flowThresholdBytes)
	} else {
		fmt.Println("[MODE] 内核 < 5.8，启用兼容模式 (perf buffer)")
		fmt.Printf("[CONFIG] perf buffer 大小: %d KB/CPU (level=%d)\n", perfPerCPUSize/1024, flagBufferLevel)
		runLegacy(attachExecve, attachNet, perfPerCPUSize, flowThresholdBytes)
	}
}

func calcBufferSizes(level int) (ringbufSize uint32, perfPerCPUSize int) {
	switch level {
	case 1:
		ringbufSize = 256 * 1024       // 256 KB
		perfPerCPUSize = 16 * 1024     // 16 KB / CPU
	case 3:
		ringbufSize = 4 * 1024 * 1024  // 4 MB
		perfPerCPUSize = 256 * 1024    // 256 KB / CPU
	default:
		// level 2 或其他非法值均使用默认中等配置
		if level != 2 {
			fmt.Fprintf(os.Stderr, "[WARN] 未知的 buffer-level=%d，使用默认 level=2\n", level)
		}
		ringbufSize = 1024 * 1024      // 1 MB
		perfPerCPUSize = 64 * 1024     // 64 KB / CPU
	}
	return
}

func printEnvFail(hint string) {
	fmt.Println()
	fmt.Println("===================================")
	fmt.Println("抱歉，当前环境不满足运行条件。")
	if hint != "" {
		fmt.Printf("提示: %s\n", hint)
	}
	fmt.Println("===================================")
	os.Exit(1)
}

func getOSVersion() string {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	if data, err := os.ReadFile("/etc/redhat-release"); err == nil {
		return strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/etc/centos-release"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return "unknown"
}

func checkKernelVersion() (string, bool) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown", false
	}
	kver := strings.TrimSpace(string(data))
	parts := strings.Split(kver, ".")
	if len(parts) >= 2 {
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		if major > 5 || (major == 5 && minor >= 8) {
			return kver, true
		}
	}
	return kver, false
}

func getKernelMajorMinor() (major, minor int) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return 0, 0
	}
	kver := strings.TrimSpace(string(data))
	parts := strings.Split(kver, ".")
	if len(parts) >= 2 {
		major, _ = strconv.Atoi(parts[0])
		minor, _ = strconv.Atoi(parts[1])
	}
	return
}

func bpfSyscallAvailable() bool {
	// 尝试调用 bpf syscall，cmd=0 在支持的系统上会返回 EINVAL，
	// 在不支持的系统上返回 ENOSYS
	_, _, err := unix.Syscall(unix.SYS_BPF, 0, 0, 0)
	return err != syscall.ENOSYS
}

func checkSecurityConstraints() {
	var hints []string

	// Kernel Lockdown (通常由 Secure Boot 触发)
	if data, err := os.ReadFile("/sys/kernel/security/lockdown"); err == nil {
		s := strings.TrimSpace(string(data))
		// 格式示例: [none] integrity confidentiality
		if idx := strings.Index(s, "]"); idx > 1 && strings.HasPrefix(s, "[") {
			current := s[1:idx]
			if current == "integrity" || current == "confidentiality" {
				fmt.Println("[WARN] Kernel lockdown 已启用（通常由 Secure Boot 触发），可能阻止 eBPF tracepoint attach。")
				hints = append(hints, "  → 方案 A：进 BIOS 关闭 Secure Boot（根治）")
				hints = append(hints, "  → 方案 B：内核参数添加 lockdown=0（部分环境有效）")
			}
		}
	}

	// SELinux
	if path, err := exec.LookPath("getenforce"); err == nil {
		out, err := exec.Command(path).Output()
		if err == nil {
			mode := strings.TrimSpace(string(out))
			if mode == "Enforcing" {
				fmt.Println("[WARN] SELinux 处于 Enforcing 模式，可能限制 perf event / tracepoint attach。")
				hints = append(hints, "  → 方案 C：sudo setenforce 0（临时测试）")
			}
		}
	}

	// perf_event_paranoid
	if data, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid"); err == nil {
		v, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		if v >= 2 {
			fmt.Printf("[WARN] perf_event_paranoid=%d，可能限制 tracepoint 访问。\n", v)
			hints = append(hints, "  → 方案 D：echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid")
		}
	}

	if len(hints) > 0 {
		fmt.Println("[INFO] 如遇 attach permission denied，可尝试以下方案：")
		for _, h := range hints {
			fmt.Println(h)
		}
	}
}

func readProcExe(pid int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}

func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	data = bytes.TrimRight(data, "\x00")
	parts := strings.Split(string(data), "\x00")
	return strings.Join(parts, " ")
}

func printEvent(e Event) {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	switch EventType(e.Type) {
	case EventExecveEnter:
		fname := string(bytes.TrimRight(e.Data[:], "\x00"))
		execveEnterCache[e.Pid] = execveEnterInfo{comm: comm, filename: fname}
		fmt.Printf("%-8s %-6d %-16s %-12s %s\n", "EXEC", e.Pid, comm, "", fname)
	case EventExecveExit:
		info, ok := execveEnterCache[e.Pid]
		if !ok {
			info = execveEnterInfo{comm: comm, filename: ""}
		}
		delete(execveEnterCache, e.Pid)

		var exePath, cmdline string
		if e.Ret >= 0 {
			exePath = readProcExe(int(e.Pid))
			cmdline = readProcCmdline(int(e.Pid))
		}
		if exePath == "" {
			exePath = info.filename
		}
		if cmdline == "" {
			cmdline = info.filename
		}
		if len(cmdline) > 200 {
			cmdline = cmdline[:200] + "..."
		}
		fmt.Printf("%-8s %-6d %-16s ret=%-6d exe=%s cmd=%s\n", "EXEC", e.Pid, info.comm, e.Ret, exePath, cmdline)
	case EventConnect:
		addrStr := parseSockaddr(e.Data[:])
		fmt.Printf("%-8s %-6d %-16s %-12s %s\n", "CONNECT", e.Pid, comm, "", addrStr)
	case EventAccept4Exit:
		addrStr := parseSockaddr(e.Data[:])
		fmt.Printf("%-8s %-6d %-16s fd=%-7d %s\n", "ACCEPT", e.Pid, comm, e.Ret, addrStr)
	case 5:
		alertType := "TX"
		if e.Ret == 2 {
			alertType = "RX"
		}
		addrStr := ""
		if e.Family == syscall.AF_INET {
			ip := net.IP(make([]byte, 4))
			binary.LittleEndian.PutUint32(ip, e.Daddr)
			port := binary.BigEndian.Uint16([]byte{byte(e.Dport), byte(e.Dport >> 8)})
			addrStr = fmt.Sprintf("%s:%d", ip.String(), port)
		} else if e.Family == syscall.AF_INET6 {
			port := binary.BigEndian.Uint16([]byte{byte(e.Dport), byte(e.Dport >> 8)})
			addrStr = fmt.Sprintf("[IPv6]:%d", port)
		}
		rxStr := fmt.Sprintf("%.2fKB", float64(e.RxBytes)/1024)
		if e.RxBytes >= 1024*1024 {
			rxStr = fmt.Sprintf("%.2fMB", float64(e.RxBytes)/1024/1024)
		}
		txStr := fmt.Sprintf("%.2fKB", float64(e.TxBytes)/1024)
		if e.TxBytes >= 1024*1024 {
			txStr = fmt.Sprintf("%.2fMB", float64(e.TxBytes)/1024/1024)
		}
		fmt.Printf("%-8s %-6d %-16s %-12s ALERT=%s RX=%s TX=%s %s\n",
			"FLOW", e.Pid, comm, "", alertType, rxStr, txStr, addrStr)
	default:
		fmt.Printf("%-8s %-6d %-16s %-12d %x\n", "UNKNOWN", e.Pid, comm, e.Ret, e.Data[:16])
	}
}

func parseSockaddr(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	family := binary.LittleEndian.Uint16(data[:2])
	switch family {
	case syscall.AF_INET:
		if len(data) < 16 {
			return ""
		}
		ip := net.IP(data[4:8])
		port := binary.BigEndian.Uint16(data[2:4])
		return fmt.Sprintf("%s:%d", ip.String(), port)
	case syscall.AF_INET6:
		if len(data) < 28 {
			return ""
		}
		ip := net.IP(data[8:24])
		port := binary.BigEndian.Uint16(data[2:4])
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		return fmt.Sprintf("family=%d", family)
	}
}
