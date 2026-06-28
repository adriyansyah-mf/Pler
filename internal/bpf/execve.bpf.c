// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ARGSIZE      128
#define MAXARGS      20
#define TOTAL_ARGBUF (ARGSIZE * MAXARGS)

struct event_t {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __s32 retval;
    char  comm[16];
    char  filename[256];
    char  argv[TOTAL_ARGBUF];
    __u8  argv_truncated;
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct event_t);
} inflight SEC(".maps");

/* Per-CPU scratch map avoids the 512-byte BPF stack limit for large structs */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_t);
} scratch SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 zero = 0;

    struct event_t *ev = bpf_map_lookup_elem(&scratch, &zero);
    if (!ev)
        return 0;

    ev->ts_ns = bpf_ktime_get_ns();
    ev->pid   = pid;
    ev->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->gid   = bpf_get_current_uid_gid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), filename);

    const char *const *argv = (const char *const *)ctx->args[1];
    int pos = 0;
    __u8 truncated = 0;

    #pragma unroll
    for (int i = 0; i < MAXARGS; i++) {
        if (pos >= TOTAL_ARGBUF - ARGSIZE) {
            truncated = 1;
            break;
        }
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        int n = bpf_probe_read_user_str(&ev->argv[pos], ARGSIZE, argp);
        if (n <= 1)
            break;
        pos += n - 1;
        if (pos < TOTAL_ARGBUF - 1)
            ev->argv[pos++] = ' ';
    }
    if (pos > 0)
        ev->argv[pos - 1] = '\0';
    ev->argv_truncated = truncated;

    bpf_map_update_elem(&inflight, &pid, ev, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event_t *ev = bpf_map_lookup_elem(&inflight, &pid);
    if (!ev)
        return 0;

    ev->retval = (__s32)ctx->ret;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
    bpf_map_delete_elem(&inflight, &pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
