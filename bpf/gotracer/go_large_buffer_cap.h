// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/utils.h>

#include <common/large_buffers.h>

// Bytes of one Go HTTP write to send to user space. User space keeps at most max_bytes per
// request and per response, so BPF does not send the rest: the chunks of a large body
// fill the shared events ring buffer and the span events after them are lost.
// sent holds the bytes already sent for this message; it is updated here.
static __always_inline u32 go_large_buf_emit_len(u32 *sent, u32 len, u32 max_bytes) {
    const u32 done = *sent;
    if (done >= max_bytes) {
        return 0;
    }

    u32 emit = max_bytes - done;
    if (len < emit) {
        emit = len;
    }
    bpf_clamp_umax(emit, k_large_buf_max_http_captured_bytes);

    *sent = done + emit;
    return emit;
}
