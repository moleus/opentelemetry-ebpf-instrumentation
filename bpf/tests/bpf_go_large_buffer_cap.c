// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run me with: make && ./bpf_go_large_buffer_cap

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <bpfcore/vmlinux.h>

#include <gotracer/go_large_buffer_cap.h>

static int failures;

static void expect(bool ok, const char *msg) {
    printf("%s: %s\n", ok ? "PASS" : "FAIL", msg);
    if (!ok) {
        failures++;
    }
}

// A Go server writes a 90 MiB body in 4 KiB writes; with the cap of 8192 bytes only the
// first two writes go to the ring buffer.
static void test_large_body_stops_at_cap(void) {
    u32 sent = 0;
    u32 emitted = 0;
    u32 writes = 0;
    for (u32 i = 0; i < (90u << 20) / 4096; i++) {
        const u32 n = go_large_buf_emit_len(&sent, 4096, 8192);
        emitted += n;
        writes += n > 0;
    }
    expect(emitted == 8192, "a 90 MiB body sends 8192 bytes");
    expect(writes == 2, "a 90 MiB body sends 2 writes");
    expect(sent == 8192, "the counter stops at the cap");
}

// A write that crosses the cap is cut at the cap.
static void test_write_cut_at_cap(void) {
    u32 sent = 0;
    expect(go_large_buf_emit_len(&sent, 5000, 8192) == 5000, "first write is sent whole");
    expect(go_large_buf_emit_len(&sent, 5000, 8192) == 3192, "second write is cut at the cap");
    expect(go_large_buf_emit_len(&sent, 1, 8192) == 0, "nothing after the cap");
}

// A new message starts with a zero counter and gets the full cap again.
static void test_new_message_resets(void) {
    u32 sent = 8192;
    expect(go_large_buf_emit_len(&sent, 100, 8192) == 0, "full message sends nothing");
    sent = 0;
    expect(go_large_buf_emit_len(&sent, 100, 8192) == 100, "new message sends again");
}

// Capture off: max_bytes 0 sends nothing.
static void test_disabled(void) {
    u32 sent = 0;
    expect(go_large_buf_emit_len(&sent, 100, 0) == 0, "max 0 sends nothing");
}

int main(void) {
    test_large_body_stops_at_cap();
    test_write_cut_at_cap();
    test_new_message_resets();
    test_disabled();
    if (failures) {
        printf("%d failures\n", failures);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
