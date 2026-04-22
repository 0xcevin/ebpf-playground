package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
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

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	objs := traceObjects{}
	if err := loadTraceObjects(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load eBPF objects: %v\n", err)
		os.Exit(1)
	}
	defer objs.Close()

	// Attach tracepoints. Failure of individual tracepoints is non-fatal.
	attachments := []struct {
		name   string
		l      link.Link
		err    error
	}{
		{"sys_enter_execve", nil, nil},
		{"sys_exit_execve", nil, nil},
		{"sys_enter_connect", nil, nil},
		{"sys_enter_accept4", nil, nil},
		{"sys_exit_accept4", nil, nil},
	}

	attachments[0].l, attachments[0].err = link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSysEnterExecve, nil)
	attachments[1].l, attachments[1].err = link.Tracepoint("syscalls", "sys_exit_execve", objs.TracepointSysExitExecve, nil)
	attachments[2].l, attachments[2].err = link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSysEnterConnect, nil)
	attachments[3].l, attachments[3].err = link.Tracepoint("syscalls", "sys_enter_accept4", objs.TracepointSysEnterAccept4, nil)
	attachments[4].l, attachments[4].err = link.Tracepoint("syscalls", "sys_exit_accept4", objs.TracepointSysExitAccept4, nil)

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
