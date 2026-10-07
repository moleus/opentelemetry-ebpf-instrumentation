// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// The helper below is copied from bpf/generictracer/protocol_tcp.h (kafka_be32 and
// kafka_complete_produce_request) with the minimum of surrounding types, like the other
// tests in this directory. It decides when a Produce request without a response
// (acks=0) is final. The bytes are a Produce v8 request as written by a Go client library.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

enum {
    k_tcp_max_len = 256,
    k_kafka_hdr_message_size = 4,
    k_kafka_request_header_fields_without_message_size = 8,
    k_kafka_min_request_header_size = 12,
    k_kafka_api_key_produce = 0,
    k_kafka_max_produce_api_version = 13,
    k_kafka_max_payload_len = 20 * 1024 * 1024,
};

typedef struct tcp_req {
    u64 end_monotime_ns;
    u32 len;
    u32 req_len;
    unsigned char buf[k_tcp_max_len];
} tcp_req_t;

static u32 kafka_be32(const unsigned char *b) {
    return ((u32)b[0] << 24) | ((u32)b[1] << 16) | ((u32)b[2] << 8) | (u32)b[3];
}

static int kafka_complete_produce_request(const tcp_req_t *req) {
    if (req->end_monotime_ns != 0 || req->len < k_kafka_min_request_header_size) {
        return 0;
    }
    const u32 message_size = kafka_be32(&req->buf[0]);
    const u32 api_key = ((u32)req->buf[4] << 8) | (u32)req->buf[5];
    const u32 api_version = ((u32)req->buf[6] << 8) | (u32)req->buf[7];
    const u32 correlation_id = kafka_be32(&req->buf[8]);
    return api_key == k_kafka_api_key_produce && api_version <= k_kafka_max_produce_api_version &&
           correlation_id < 0x80000000 &&
           message_size >= k_kafka_request_header_fields_without_message_size + 2 &&
           message_size <= k_kafka_max_payload_len &&
           req->req_len == message_size + k_kafka_hdr_message_size;
}

// Produce v8, acks=0, one record, 150 bytes on the wire.
static const char *produce_v8_hex =
    "000000920000000800000007001d6769746875622e636f6d2f7365676d656e74696f2f6b61666b612d676f"
    "ffff" "0000" "00002710" "00000001"
    "000a67742d6b61666b61676f00000001000000000000004700000000000000000000003bffffffff"
    "025fd8dc7f000000000000000001a1176993d1000001a1176993d1ffffffffffffffffffffffffffff"
    "0000000112000000026b046d3100";

static int hex(const char *h, unsigned char *out) {
    int n = (int)(strlen(h) / 2);
    for (int i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    return n;
}

static void assert_equal(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s (expected %d, got %d)\n", message, expected, actual);
        exit(1);
    }
}

static tcp_req_t make_req(const unsigned char *data, int total, int captured) {
    tcp_req_t r;
    memset(&r, 0, sizeof(r));
    int n = captured < k_tcp_max_len ? captured : k_tcp_max_len;
    memcpy(r.buf, data, (size_t)n);
    r.len = (u32)captured;
    r.req_len = (u32)total;
    return r;
}

int main(void) {
    unsigned char data[512];
    const int total = hex(produce_v8_hex, data);
    assert_equal(150, total, "test vector length");

    tcp_req_t r = make_req(data, total, total);
    assert_equal(1, kafka_complete_produce_request(&r), "complete Produce request");

    // The Java broker reads the 4-byte size first, then the body: the pending request
    // is complete only when both reads were appended.
    r = make_req(data, 4, 4);
    assert_equal(0, kafka_complete_produce_request(&r), "only the size was read");
    // A large request is captured only in part (len is clamped), req_len keeps the real size.
    r = make_req(data, total, 100);
    assert_equal(1, kafka_complete_produce_request(&r), "complete request, capture clamped");
    r.req_len = 120;
    assert_equal(0, kafka_complete_produce_request(&r), "request not complete yet");

    r = make_req(data, total, total);
    r.end_monotime_ns = 1;
    assert_equal(0, kafka_complete_produce_request(&r), "request already answered");

    r = make_req(data, total, total);
    r.buf[5] = 1; // api key 1 = Fetch: it always has a response
    assert_equal(0, kafka_complete_produce_request(&r), "not a Produce request");

    r = make_req(data, total, total);
    r.buf[7] = 14; // version newer than the parser knows
    assert_equal(0, kafka_complete_produce_request(&r), "unknown Produce version");

    r = make_req(data, total, total);
    r.req_len = total + 150; // a second request was appended before the fix
    assert_equal(0, kafka_complete_produce_request(&r), "more than one request");

    printf("kafka produce complete: all tests passed\n");
    return 0;
}
