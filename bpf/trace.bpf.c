//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET		2
#define AF_INET6	10

#define EVENT_EXECVE_ENTER	1
#define EVENT_EXECVE_EXIT	2
#define EVENT_CONNECT		3
#define EVENT_ACCEPT4_EXIT	4

/* Max data payload for sockaddr or filename */
#define DATA_LEN 256
#define MAX_SOCKADDR_LEN 128

struct event {
	u32 pid;
	u32 type;
	char comm[16];
	char data[DATA_LEN];
	s64 ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Temporary storage for accept4 arguments keyed by pid */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct sockaddr *);
} accept4_sockaddr SEC(".maps");

static __always_inline void *reserve_event(void)
{
	return bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
}

static __always_inline void submit_event(void *e)
{
	bpf_ringbuf_submit(e, 0);
}

SEC("tp/syscalls/sys_enter_execve")
int tracepoint__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = reserve_event();
	if (!e)
		return 0;

	e->type = EVENT_EXECVE_ENTER;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ret = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->data, sizeof(e->data), filename);

	submit_event(e);
	return 0;
}

SEC("tp/syscalls/sys_exit_execve")
int tracepoint__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
	struct event *e = reserve_event();
	if (!e)
		return 0;

	e->type = EVENT_EXECVE_EXIT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ret = ctx->ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->data[0] = '\0';

	submit_event(e);
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int tracepoint__sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = reserve_event();
	if (!e)
		return 0;

	e->type = EVENT_CONNECT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ret = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
	bpf_probe_read_user(&e->data, MAX_SOCKADDR_LEN, addr);

	submit_event(e);
	return 0;
}

SEC("tp/syscalls/sys_enter_accept4")
int tracepoint__sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

	bpf_map_update_elem(&accept4_sockaddr, &pid, &addr, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_accept4")
int tracepoint__sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct sockaddr **addrpp = bpf_map_lookup_elem(&accept4_sockaddr, &pid);
	if (!addrpp)
		return 0;

	struct event *e = reserve_event();
	if (!e)
		goto cleanup;

	e->type = EVENT_ACCEPT4_EXIT;
	e->pid = pid;
	e->ret = ctx->ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Dereference userspace pointer stored in enter */
	struct sockaddr *addr = *addrpp;
	if (addr) {
		bpf_probe_read_user(&e->data, MAX_SOCKADDR_LEN, addr);
	} else {
		e->data[0] = '\0';
	}

	submit_event(e);

cleanup:
	bpf_map_delete_elem(&accept4_sockaddr, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
