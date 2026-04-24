package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

func runLegacy(attachExecve, attachNet bool, perfPerCPUSize int, flowThresholdBytes uint64) {
	// 加载 eBPF 兼容对象
	spec, err := loadTrace_legacy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] 加载 eBPF 兼容对象失败: %v\n", err)
		printEnvFail("请检查内核配置是否支持 eBPF，以及是否具备足够权限。")
	}

	// 应用流量预警阈值
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

	// 老内核（如 CentOS 7 的 3.10）不支持 Map BTF，清空 BTF 避免加载失败
	for _, m := range spec.Maps {
		m.Key = nil
		m.Value = nil
	}

	objs := trace_legacyObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] 加载 eBPF 兼容对象失败: %v\n", err)
		if errors.Is(err, syscall.ENOSYS) {
			printEnvFail("当前内核不支持 eBPF 基本功能（bpf 系统调用未实现），需要至少 Linux 4.7+（建议 5.8+）。")
		}
		printEnvFail("请检查内核配置是否支持 eBPF，以及是否具备足够权限。")
	}
	defer objs.Close()
	fmt.Println("[OK] eBPF 兼容对象加载成功")

	fmt.Println("===================================")
	fmt.Println()

	// Attach tracepoints
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
	// write/read/sendto/recvfrom/close 是流量统计的基础，始终挂载
	attachments = append(attachments,
		attachDef{name: "sys_enter_write"},
		attachDef{name: "sys_exit_write"},
		attachDef{name: "sys_enter_read"},
		attachDef{name: "sys_exit_read"},
		attachDef{name: "sys_enter_sendto"},
		attachDef{name: "sys_exit_sendto"},
		attachDef{name: "sys_enter_recvfrom"},
		attachDef{name: "sys_exit_recvfrom"},
		attachDef{name: "sys_enter_close"},
	)

	idx := 0
	if attachExecve {
		attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSysEnterExecve, nil)
		if attachments[idx].err != nil {
			attachments[idx].l, attachments[idx].err = link.Kprobe("sys_execve", objs.KprobeSysExecve, nil)
		}
		idx++
		attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_exit_execve", objs.TracepointSysExitExecve, nil)
		if attachments[idx].err != nil {
			attachments[idx].l, attachments[idx].err = link.Kretprobe("sys_execve", objs.KretprobeSysExecve, nil)
		}
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
	// write/read/sendto/recvfrom/close
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_write", objs.TracepointSysEnterWrite, nil)
	idx++
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_exit_write", objs.TracepointSysExitWrite, nil)
	idx++
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_read", objs.TracepointSysEnterRead, nil)
	idx++
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_exit_read", objs.TracepointSysExitRead, nil)
	idx++
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_sendto", objs.TracepointSysEnterSendto, nil)
	idx++
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_exit_sendto", objs.TracepointSysExitSendto, nil)
	idx++
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TracepointSysEnterRecvfrom, nil)
	idx++
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.TracepointSysExitRecvfrom, nil)
	idx++
	attachments[idx].l, attachments[idx].err = link.Tracepoint("syscalls", "sys_enter_close", objs.TracepointSysEnterClose, nil)
	idx++

	attached := 0
	for i := range attachments {
		if attachments[i].err != nil {
			msg := fmt.Sprintf("Warning: failed to attach %s: %v", attachments[i].name, attachments[i].err)
			if strings.Contains(attachments[i].err.Error(), "permission denied") {
				msg += "\n  Hint: 在 RHEL 9 / AlmaLinux 9 / Rocky 9 等系统上，这通常由以下原因导致："
				msg += "\n        1. Secure Boot 触发 Kernel Lockdown → 进 BIOS 关闭 Secure Boot"
				msg += "\n        2. SELinux Enforcing → sudo setenforce 0（临时测试）"
				msg += "\n        3. perf_event_paranoid 过高 → echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
			}
			fmt.Fprintln(os.Stderr, msg)
		} else {
			attached++
			defer attachments[i].l.Close()
		}
	}
	if attached == 0 {
		fmt.Fprintf(os.Stderr, "No tracepoints attached, exiting.\n")
		os.Exit(1)
	}

	// Open perf buffer
	rd, err := perf.NewReader(objs.Pb, perfPerCPUSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open perf buffer: %v\n", err)
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
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "Failed to read from perf buffer: %v\n", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse event: %v\n", err)
			continue
		}

		printEvent(event)
	}
}
