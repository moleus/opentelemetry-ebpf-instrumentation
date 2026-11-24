// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Tests the production helpers of bpf/generictracer/kafka_produce.h that decide when a Kafka
// Produce request without a response (acks=0) is final. The request bytes are built the way
// the Kafka protocol defines them (versions 0 to 13) and one is a request written by a Go
// client library.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <generictracer/kafka_produce.h>

static void assert_equal(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s (expected %d, got %d)\n", message, expected, actual);
        exit(1);
    }
}

static unsigned char *put16(unsigned char *p, int v) {
    *p++ = (unsigned char)(v >> 8);
    *p++ = (unsigned char)v;
    return p;
}

static unsigned char *put32(unsigned char *p, uint32_t v) {
    p = put16(p, (int)(v >> 16));
    return put16(p, (int)(v & 0xffff));
}

// Builds a Produce request. client_id/txn_id NULL = null string. The topic data is `pad` zero
// bytes, so the request size is a parameter too. Returns the length on the wire.
static int build(unsigned char *out,
                 int version,
                 const char *client_id,
                 const char *txn_id,
                 int acks,
                 int pad) {
    unsigned char *p = out + 4; // message_size is filled in at the end
    p = put16(p, 0);            // api key
    p = put16(p, version);
    p = put32(p, 7); // correlation id
    if (client_id) {
        p = put16(p, (int)strlen(client_id));
        memcpy(p, client_id, strlen(client_id));
        p += strlen(client_id);
    } else {
        p = put16(p, -1);
    }
    if (version >= 9) {
        *p++ = 0; // tagged fields
    }
    if (version >= 3) {
        if (version >= 9) {
            if (txn_id) {
                *p++ = (unsigned char)(strlen(txn_id) + 1);
                memcpy(p, txn_id, strlen(txn_id));
                p += strlen(txn_id);
            } else {
                *p++ = 0;
            }
        } else if (txn_id) {
            p = put16(p, (int)strlen(txn_id));
            memcpy(p, txn_id, strlen(txn_id));
            p += strlen(txn_id);
        } else {
            p = put16(p, -1);
        }
    }
    p = put16(p, acks);
    p = put32(p, 10000); // timeout
    memset(p, 0, (size_t)pad);
    p += pad;
    const int total = (int)(p - out);
    put32(out, (uint32_t)(total - 4));
    return total;
}

static int hex(const char *h, unsigned char *out) {
    int n = (int)(strlen(h) / 2);
    for (int i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    return n;
}

// Produce v8, acks=0, one record, 150 bytes on the wire, as written by a Go client library.
static const char *produce_v8_hex =
    "000000920000000800000007001d6769746875622e636f6d2f7365676d656e74696f2f6b61666b612d676f"
    "ffff"
    "0000"
    "00002710"
    "00000001"
    "000a67742d6b61666b61676f00000001000000000000004700000000000000000000003bffffffff"
    "025fd8dc7f000000000000000001a1176993d1000001a1176993d1ffffffffffffffffffffffffffff"
    "0000000112000000026b046d3100";

static int complete(const unsigned char *b, int captured, int req_len) {
    return kafka_is_complete_acks0_produce(b, (u32)captured, (u32)req_len);
}

int main(void) {
    unsigned char b[4096] = {0}; // the largest frame built below is 4096 bytes
    int n;

    assert_equal(k_kafka_acks_unknown, kafka_be16(b, 127, 128), "16-bit read cannot cross capture window");
    assert_equal(k_kafka_acks_unknown, kafka_be16(b, 12, 13), "16-bit read cannot cross captured prefix");
    assert_equal(k_kafka_acks_unknown, kafka_be16(b, UINT32_MAX, 128), "16-bit read rejects overflowing offset");
    b[12] = 0xff;
    b[13] = 0xff;
    assert_equal(0xffff, kafka_unsigned16(b, 12, 14), "unsigned length retains the null-string marker");
    assert_equal(k_kafka_acks_unknown, kafka_unsigned16(b, 12, 13), "unsigned length preserves a failed read");

    // The request written by a Go client library.
    n = hex(produce_v8_hex, b);
    assert_equal(150, n, "test vector length");
    assert_equal(0, kafka_produce_acks(b, n), "v8 vector acks");
    assert_equal(1, complete(b, n, n), "v8 vector is complete acks=0");

    // Every version, three acks values, null and non-null strings.
    for (int v = 0; v <= 13; v++) {
        const int acks_set[3] = {0, 1, -1};
        for (int i = 0; i < 3; i++) {
            for (int s = 0; s < 2; s++) {
                n = build(b, v, s ? "client-1" : NULL, s ? "txn-1" : NULL, acks_set[i], 40);
                char msg[80];
                snprintf(msg, sizeof(msg), "v%d acks=%d strings=%d: acks", v, acks_set[i], s);
                assert_equal(acks_set[i], kafka_produce_acks(b, n), msg);
                snprintf(msg, sizeof(msg), "v%d acks=%d strings=%d: complete", v, acks_set[i], s);
                assert_equal(acks_set[i] == 0, complete(b, n, n), msg);
            }
        }
    }

    // A pipelined acknowledged request is never taken as final, whatever follows it.
    n = build(b, 7, "client-1", NULL, 1, 40);
    assert_equal(0, complete(b, n, n), "acks=1 complete frame");
    assert_equal(0, complete(b, n, n + 100), "acks=1 and the next request already read");
    n = build(b, 7, "client-1", NULL, -1, 40);
    assert_equal(0, complete(b, n, n), "acks=-1 complete frame");

    // Capture is shorter than the request (the generic tracker keeps 256 bytes): req_len is the
    // real size, so a 4096-byte request that was read in parts is complete once req_len is.
    n = build(b, 8, "client-1", NULL, 0, 4096 - 30);
    assert_equal(4096, n, "large request length");
    assert_equal(1, complete(b, 256, 4096), "large request, capture clamped");
    assert_equal(0, complete(b, 256, 1024), "large request, first read only");
    assert_equal(0, complete(b, 256, 3328), "large request, bytes still missing");

    // The Java broker reads the 4-byte size first, then the body: not complete after the size.
    n = build(b, 8, "client-1", NULL, 0, 40);
    assert_equal(0, complete(b, 4, 4), "only the size was read");
    assert_equal(0, complete(b, 14, 14), "only the header prefix was read");
    // Not complete until all bytes were read, even when the acks field is already captured.
    assert_equal(0, complete(b, n, n - 1), "one byte missing");
    assert_equal(1, complete(b, n, n), "all bytes read");
    // Coalesced: two requests in one read are not one frame (they stay with the generic path).
    assert_equal(0, complete(b, n, 2 * n), "two frames in one read");

    // The acks field is beyond the captured prefix: unknown, never final.
    n = build(b, 8, "a-client-id-that-is-long-enough-to-push-acks-out", NULL, 0, 40);
    assert_equal(0, kafka_produce_acks(b, n), "long client id, acks inside the window");
    char long_id[200];
    memset(long_id, 'x', sizeof(long_id) - 1);
    long_id[sizeof(long_id) - 1] = 0;
    unsigned char big[512];
    n = build(big, 8, long_id, NULL, 0, 40);
    assert_equal(k_kafka_acks_unknown, kafka_produce_acks(big, n), "client id beyond the window");
    assert_equal(0, complete(big, n, n), "client id beyond the window is not final");
    // A captured prefix cut inside the acks field.
    n = build(b, 8, "client-1", NULL, 0, 40);
    const int acks_end = 12 + 2 + 8 + 2 + 2; // up to and including acks
    assert_equal(k_kafka_acks_unknown, kafka_produce_acks(b, acks_end - 1), "cut inside acks");
    assert_equal(0, kafka_produce_acks(b, acks_end), "cut right after acks");

    // Not a Produce request, unknown version, bad header fields, tagged fields.
    n = build(b, 8, "client-1", NULL, 0, 40);
    b[5] = 1; // api key 1 = Fetch
    assert_equal(0, complete(b, n, n), "not a Produce request");
    n = build(b, 8, "client-1", NULL, 0, 40);
    b[7] = 14;
    assert_equal(0, complete(b, n, n), "unknown Produce version");
    n = build(b, 8, "client-1", NULL, 0, 40);
    b[8] = 0x80; // negative correlation id
    assert_equal(0, complete(b, n, n), "bad correlation id");
    n = build(b, 9, "client-1", NULL, 0, 40);
    b[12 + 2 + 8] = 1; // one tagged field: not parsed
    assert_equal(0, complete(b, n, n), "flexible header with tagged fields");
    n = build(b, 8, "client-1", NULL, 0, 40);
    b[12] = 0x80; // negative client id length other than -1
    assert_equal(0, complete(b, n, n), "bad client id length");

    printf("kafka produce complete: all tests passed\n");
    return 0;
}
