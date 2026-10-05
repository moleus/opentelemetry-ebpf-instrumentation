// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Reports the delivery of a signal that terminates the process with the default action:
// crashes (SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT) and kills (SIGKILL, also from the OOM killer).
// Signals that the process handles itself (for example SIGSEGV in a JVM or a Go runtime) are not reported.

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/pin_internal.h>

#include <pid/pid_helpers.h>

enum fatal_signal { k_sigill = 4, k_sigabrt = 6, k_sigbus = 7, k_sigfpe = 8, k_sigkill = 9, k_sigsegv = 11 };

enum { k_sig_dfl = 0, k_comm_len = 16 };

typedef struct fatal_signal_event {
    u64 timestamp;
    pid_info pid;
    s32 sig;
    s32 code;
    unsigned char comm[k_comm_len];
    u8 _pad[4];
} fatal_signal_event_t;

// keeps the type in the BTF for bpf2go -type
const fatal_signal_event_t *unused_fatal_signal_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 14);
    __uint(pinning, OBI_PIN_INTERNAL);
} fatal_signal_events SEC(".maps");

static __always_inline bool is_fatal(const int sig) {
    switch (sig) {
    case k_sigill:
    case k_sigabrt:
    case k_sigbus:
    case k_sigfpe:
    case k_sigkill:
    case k_sigsegv:
        return true;
    default:
        return false;
    }
}

// BTF tracepoint: attached with a BPF link, so it needs no tracefs or debugfs mount in the container.
// Runs in the context of the task that receives the signal. info is NULL (SEND_SIG_NOINFO) when a
// group exit forces SIGKILL, so it is read with BPF_CORE_READ.
SEC("tp_btf/signal_deliver")
int BPF_PROG(obi_tp_btf_signal_deliver, int sig, struct kernel_siginfo *info, struct k_sigaction *ka) {
    if (!is_fatal(sig) || (unsigned long)BPF_CORE_READ(ka, sa.sa_handler) != k_sig_dfl) {
        return 0;
    }

    fatal_signal_event_t *event = bpf_ringbuf_reserve(&fatal_signal_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    event->timestamp = bpf_ktime_get_ns();
    task_pid(&event->pid);
    event->sig = sig;
    event->code = BPF_CORE_READ(info, si_code);
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
