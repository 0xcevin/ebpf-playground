package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include -I./bpf" -target bpfel,bpfeb trace bpf/trace.bpf.c

type EventType uint32

const (
	EventExecveEnter EventType = 1
	EventExecveExit  EventType = 2
	EventConnect     EventType = 3
	EventAccept4Exit EventType = 4
)

type Event struct {
	Pid  uint32
	Type uint32
	Comm [16]byte
	Data [256]byte
	Ret  int64
}

var (
	flagExecve bool
	flagNet    bool
)

func init() {
	flag.BoolVar(&flagExecve, "execve", false, "仅追踪 execve 系统调用")
	flag.BoolVar(&flagNet, "net", false, "仅追踪网络相关系统调用 (connect, accept4)")

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
	fmt.Printf("内核版本: %s\n", kver)
	if !kverOK {
		fmt.Println("[FAIL] 内核版本 < 5.8，不支持 ringbuf。")
		printEnvFail("请升级至 Linux 5.8+ 内核。")
	} else {
		fmt.Println("[OK] 内核支持 ringbuf (>= 5.8)")
	}

	// 2. 检查 BTF
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		fmt.Println("[FAIL] BTF 未开启 (/sys/kernel/btf/vmlinux 不存在)。")
		printEnvFail("请使用开启 BTF 的内核（CONFIG_DEBUG_INFO_BTF=y）。")
	} else {
		fmt.Println("[OK] BTF 已开启")
	}

	// 3. 检查权限
	if os.Geteuid() != 0 {
		fmt.Println("[WARN] 当前非 root 用户。加载 eBPF 通常需要 root 或 CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN。")
		// 非 root 但具备 CAP_BPF 理论上也可以，继续尝试加载；若加载失败再退出。
	} else {
		fmt.Println("[OK] 当前为 root 用户")
	}

	// 4. 解除 memlock
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] 无法解除 memlock 限制: %v\n", err)
		printEnvFail("请确保有足够的权限（root 或 CAP_SYS_RESOURCE）。")
	}
	fmt.Println("[OK] memlock 限制已解除")

	// 5. 加载 eBPF 对象
	objs := traceObjects{}
	if err := loadTraceObjects(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] 加载 eBPF 对象失败: %v\n", err)
		printEnvFail("请检查内核配置是否支持 eBPF，以及是否具备足够权限。")
	}
	defer objs.Close()
	fmt.Println("[OK] eBPF 对象加载成功")

	fmt.Println("===================================")
	fmt.Println()

	modeStr := "全部"
	if flagExecve && !flagNet {
		modeStr = "仅 execve"
	} else if flagNet && !flagExecve {
		modeStr = "仅网络 (connect, accept4)"
	}
	fmt.Printf("追踪模式: %s\n", modeStr)
	fmt.Println()

	// 确定要 attach 的事件：默认全部；若指定 -execve / -net，则按指定来
	attachExecve := true
	attachNet := true
	if flagExecve || flagNet {
		attachExecve = flagExecve
		attachNet = flagNet
	}

	type attachDef struct {
		name string
		l    link.Link
		err  error
	}

	var attachments []attachDef
	if attachExecve {
		attachments = append(attachments,
			attachDef{name: "sys_enter_execve"},
			attachDef{name: "sys_exit_execve"},
		)
	}
	if attachNet {
		attachments = append(attachments,
			attachDef{name: "sys_enter_connect"},
			attachDef{name: "sys_enter_accept4"},
			attachDef{name: "sys_exit_accept4"},
		)
	}

	idx := 0
	if attachExecve {
		attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSysEnterExecve, nil)
		idx++
		attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_exit_execve", objs.TracepointSysExitExecve, nil)
		idx++
	}
	if attachNet {
		attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSysEnterConnect, nil)
		idx++
		attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_accept4", objs.TracepointSysEnterAccept4, nil)
		idx++
		attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_exit_accept4", objs.TracepointSysExitAccept4, nil)
		idx++
	}

	attached := 0
	for i := range attachments {
		if attachments[i].err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to attach %s: %v\n", attachments[i].name, attachments[i].err)
		} else {
			attached++
			defer attachments[i].l.Close()
		}
	}
	if attached == 0 {
		fmt.Fprintf(os.Stderr, "No tracepoints attached, exiting.\n")
		os.Exit(1)
	}

	// Open ring buffer
	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open ring buffer: %v\n", err)
		os.Exit(1)
	}
	defer rd.Close()

	// Handle Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		rd.Close()
	}()

	fmt.Printf("%-8s %-6s %-16s %-12s %s\n", "TYPE", "PID", "COMM", "RET/FD", "DATA")

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "Failed to read from ring buffer: %v\n", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse event: %v\n", err)
			continue
		}

		printEvent(event)
	}
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

func printEvent(e Event) {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	switch EventType(e.Type) {
	case EventExecveEnter:
		fname := string(bytes.TrimRight(e.Data[:], "\x00"))
		fmt.Printf("%-8s %-6d %-16s %-12s %s\n", "EXEC", e.Pid, comm, "", fname)
	case EventExecveExit:
		fmt.Printf("%-8s %-6d %-16s %-12d %s\n", "EXECRET", e.Pid, comm, e.Ret, "")
	case EventConnect:
		addrStr := parseSockaddr(e.Data[:])
		fmt.Printf("%-8s %-6d %-16s %-12s %s\n", "CONNECT", e.Pid, comm, "", addrStr)
	case EventAccept4Exit:
		addrStr := parseSockaddr(e.Data[:])
		fmt.Printf("%-8s %-6d %-16s fd=%-7d %s\n", "ACCEPT", e.Pid, comm, e.Ret, addrStr)
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
