package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func runModern(attachExecve, attachNet bool) {
	// BTF 检查（仅现代模式需要）
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		fmt.Println("[FAIL] BTF 未开启 (/sys/kernel/btf/vmlinux 不存在)。")
		printEnvFail("请使用开启 BTF 的内核（CONFIG_DEBUG_INFO_BTF=y）。")
	} else {
		fmt.Println("[OK] BTF 已开启")
	}

	// 加载 eBPF 对象
	objs := traceObjects{}
	if err := loadTraceObjects(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] 加载 eBPF 对象失败: %v\n", err)
		printEnvFail("请检查内核配置是否支持 eBPF，以及是否具备足够权限。")
	}
	defer objs.Close()
	fmt.Println("[OK] eBPF 对象加载成功")

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
