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
#define EVENT_FLOW_ALERT	5

/* Max data payload for sockaddr or filename */
#define DATA_LEN 256
#define MAX_SOCKADDR_LEN 128

struct event {
	u32 pid;
	u32 type;
	char comm[16];
	char data[DATA_LEN];
	s64 ret;
	u64 rx_bytes;
	u64 tx_bytes;
	u32 daddr;
	u16 dport;
	u16 family;
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

/* Connection stats keyed by pid+fd */
struct conn_key {
	u32 pid;
	u32 fd;
};

struct conn_info {
	u64 rx_bytes;
	u64 tx_bytes;
	u32 warned_rx;
	u32 warned_tx;
	u32 daddr;
	u16 dport;
	u16 family;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct conn_key);
	__type(value, struct conn_info);
} conn_stats_map SEC(".maps");

/* Temporary storage for write/read enter fd keyed by pid */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u32);
} io_enter_args SEC(".maps");

/* Configuration: thresholds */
struct config {
	u64 tx_threshold;
	u64 rx_threshold;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct config);
} config_map SEC(".maps");

static __always_inline void *reserve_event(void)
{
	return bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
}

static __always_inline void submit_event(void *e)
{
	bpf_ringbuf_submit(e, 0);
}

static __always_inline void parse_sockaddr_to_conn(struct sockaddr *addr, struct conn_info *info)
{
	u16 family;
	if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family))
		return;
	info->family = family;
	if (family == AF_INET) {
		struct sockaddr_in sin;
		if (bpf_probe_read_user(&sin, sizeof(sin), addr) == 0) {
			info->daddr = sin.sin_addr.s_addr;
			info->dport = sin.sin_port;
		}
	} else if (family == AF_INET6) {
		struct sockaddr_in6 sin6;
		if (bpf_probe_read_user(&sin6, sizeof(sin6), addr) == 0) {
			/* For IPv6 we only store port; address is too large for u32 */
			info->dport = sin6.sin6_port;
			info->daddr = 0;
		}
	}
}

static __always_inline void check_and_alert(struct conn_key *key, struct conn_info *info, int is_tx)
{
	u32 cfg_key = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
	if (!cfg)
		return;

	if (is_tx && cfg->tx_threshold > 0 && info->tx_bytes >= cfg->tx_threshold && !info->warned_tx) {
		info->warned_tx = 1;
		struct event *e = reserve_event();
		if (!e)
			return;
		e->type = EVENT_FLOW_ALERT;
		e->pid = key->pid;
		e->ret = 1; /* TX alert */
		e->rx_bytes = info->rx_bytes;
		e->tx_bytes = info->tx_bytes;
		e->daddr = info->daddr;
		e->dport = info->dport;
		e->family = info->family;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(&e->data, "TX_THRESHOLD", 13);
		submit_event(e);
	}

	if (!is_tx && cfg->rx_threshold > 0 && info->rx_bytes >= cfg->rx_threshold && !info->warned_rx) {
		info->warned_rx = 1;
		struct event *e = reserve_event();
		if (!e)
			return;
		e->type = EVENT_FLOW_ALERT;
		e->pid = key->pid;
		e->ret = 2; /* RX alert */
		e->rx_bytes = info->rx_bytes;
		e->tx_bytes = info->tx_bytes;
		e->daddr = info->daddr;
		e->dport = info->dport;
		e->family = info->family;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(&e->data, "RX_THRESHOLD", 13);
		submit_event(e);
	}
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

	/* Record connection stats */
	u32 pid = e->pid;
	u32 fd = (u32)ctx->args[0];
	struct conn_key key = { .pid = pid, .fd = fd };
	struct conn_info info = {};
	parse_sockaddr_to_conn(addr, &info);
	bpf_get_current_comm(&info.comm, sizeof(info.comm));
	bpf_map_update_elem(&conn_stats_map, &key, &info, BPF_ANY);

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

	/* Record connection stats for the new fd */
	if (ctx->ret >= 0) {
		u32 new_fd = (u32)ctx->ret;
		struct conn_key key = { .pid = pid, .fd = new_fd };
		struct conn_info info = {};
		parse_sockaddr_to_conn(addr, &info);
		bpf_get_current_comm(&info.comm, sizeof(info.comm));
		bpf_map_update_elem(&conn_stats_map, &key, &info, BPF_ANY);
	}

	submit_event(e);

cleanup:
	bpf_map_delete_elem(&accept4_sockaddr, &pid);
	return 0;
}

SEC("tp/syscalls/sys_enter_write")
int tracepoint__sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 fd = (u32)ctx->args[0];
	struct conn_key key = { .pid = pid, .fd = fd };
	struct conn_info *info = bpf_map_lookup_elem(&conn_stats_map, &key);
	if (info) {
		bpf_map_update_elem(&io_enter_args, &pid, &fd, BPF_ANY);
	}
	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int tracepoint__sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	s64 size = ctx->ret;
	if (size <= 0)
		return 0;

	u32 *fdp = bpf_map_lookup_elem(&io_enter_args, &pid);
	if (!fdp)
		return 0;

	struct conn_key key = { .pid = pid, .fd = *fdp };
	struct conn_info *info = bpf_map_lookup_elem(&conn_stats_map, &key);
	if (!info)
		goto cleanup;

	info->tx_bytes += size;
	check_and_alert(&key, info, 1);

cleanup:
	bpf_map_delete_elem(&io_enter_args, &pid);
	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int tracepoint__sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 fd = (u32)ctx->args[0];
	struct conn_key key = { .pid = pid, .fd = fd };
	struct conn_info *info = bpf_map_lookup_elem(&conn_stats_map, &key);
	if (info) {
		bpf_map_update_elem(&io_enter_args, &pid, &fd, BPF_ANY);
	}
	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int tracepoint__sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	s64 size = ctx->ret;
	if (size <= 0)
		return 0;

	u32 *fdp = bpf_map_lookup_elem(&io_enter_args, &pid);
	if (!fdp)
		return 0;

	struct conn_key key = { .pid = pid, .fd = *fdp };
	struct conn_info *info = bpf_map_lookup_elem(&conn_stats_map, &key);
	if (!info)
		goto cleanup;

	info->rx_bytes += size;
	check_and_alert(&key, info, 0);

cleanup:
	bpf_map_delete_elem(&io_enter_args, &pid);
	return 0;
}

SEC("tp/syscalls/sys_enter_sendto")
int tracepoint__sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 fd = (u32)ctx->args[0];
	struct conn_key key = { .pid = pid, .fd = fd };
	struct conn_info *info = bpf_map_lookup_elem(&conn_stats_map, &key);
	if (info) {
		bpf_map_update_elem(&io_enter_args, &pid, &fd, BPF_ANY);
	}
	return 0;
}

SEC("tp/syscalls/sys_exit_sendto")
int tracepoint__sys_exit_sendto(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	s64 size = ctx->ret;
	if (size <= 0)
		return 0;

	u32 *fdp = bpf_map_lookup_elem(&io_enter_args, &pid);
	if (!fdp)
		return 0;

	struct conn_key key = { .pid = pid, .fd = *fdp };
	struct conn_info *info = bpf_map_lookup_elem(&conn_stats_map, &key);
	if (!info)
		goto cleanup;

	info->tx_bytes += size;
	check_and_alert(&key, info, 1);

cleanup:
	bpf_map_delete_elem(&io_enter_args, &pid);
	return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int tracepoint__sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 fd = (u32)ctx->args[0];
	struct conn_key key = { .pid = pid, .fd = fd };
	struct conn_info *info = bpf_map_lookup_elem(&conn_stats_map, &key);
	if (info) {
		bpf_map_update_elem(&io_enter_args, &pid, &fd, BPF_ANY);
	}
	return 0;
}

SEC("tp/syscalls/sys_exit_recvfrom")
int tracepoint__sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	s64 size = ctx->ret;
	if (size <= 0)
		return 0;

	u32 *fdp = bpf_map_lookup_elem(&io_enter_args, &pid);
	if (!fdp)
		return 0;

	struct conn_key key = { .pid = pid, .fd = *fdp };
	struct conn_info *info = bpf_map_lookup_elem(&conn_stats_map, &key);
	if (!info)
		goto cleanup;

	info->rx_bytes += size;
	check_and_alert(&key, info, 0);

cleanup:
	bpf_map_delete_elem(&io_enter_args, &pid);
	return 0;
}

SEC("tp/syscalls/sys_enter_close")
int tracepoint__sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 fd = (u32)ctx->args[0];
	struct conn_key key = { .pid = pid, .fd = fd };
	bpf_map_delete_elem(&conn_stats_map, &key);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
