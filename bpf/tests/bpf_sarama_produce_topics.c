// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run me with: make bpf_sarama_produce_topics && ./bpf_sarama_produce_topics
//
// sarama_produce_topics reads the topic names of encoded Produce requests from
// testdata/kafka_produce (see the header comment of each case for its source).

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static long test_probe_read(void *dst, unsigned int size, const void *src);

#define bpf_probe_read_user test_probe_read
#include <gotracer/go_sarama_produce.h>
#undef bpf_probe_read_user

static int failures;

// The request under test. A read outside of it fails, like a read of unmapped user memory.
static const unsigned char *g_base;
static u32 g_len;
static int g_out_of_bounds;

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    const unsigned char *s = src;
    if (s < g_base || s + size > g_base + g_len) {
        g_out_of_bounds++;
        memset(dst, 0, size);
        return -14;
    }
    memcpy(dst, s, size);
    return 0;
}

static void expect(bool ok, const char *name, const char *msg) {
    printf("%s: %s: %s\n", ok ? "PASS" : "FAIL", name, msg);
    if (!ok) {
        failures++;
    }
}

// Reads a hex fixture: lowercase hex digits, white space and lines that start with '#' are skipped.
static unsigned char *load(const char *name, u32 *len) {
    char path[256];
    snprintf(path, sizeof(path), "testdata/kafka_produce/%s.hex", name);
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("FAIL: cannot open %s\n", path);
        exit(1);
    }
    unsigned char *b = malloc(65536);
    u32 n = 0;
    int hi = -1;
    bool comment = false;
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (c == '\n') {
            comment = false;
        } else if (c == '#') {
            comment = true;
        }
        if (comment || c == '\n' || c == ' ' || c == '\r') {
            continue;
        }
        int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
        if (v < 0 || n >= 65536) {
            printf("FAIL: bad character in %s\n", path);
            exit(1);
        }
        if (hi < 0) {
            hi = v;
        } else {
            b[n++] = (unsigned char)(hi << 4 | v);
            hi = -1;
        }
    }
    fclose(f);
    if (hi >= 0) {
        printf("FAIL: odd number of digits in %s\n", path);
        exit(1);
    }
    *len = n;
    return b;
}

// Runs the walk on the first len bytes of the request: the buffer has exactly len bytes.
static void walk(const unsigned char *data, u32 len, kafka_produce_topics_t *out) {
    unsigned char *copy = malloc(len ? len : 1);
    memcpy(copy, data, len);
    g_base = copy;
    g_len = len;
    g_out_of_bounds = 0;
    memset(out, 0, sizeof(*out));
    sarama_produce_topics(copy, len, out);
    free(copy);
}

static bool name_is(const kafka_produce_topics_t *t, u32 i, const char *want) {
    u32 off = 0;
    for (u32 k = 0; k < i; k++) {
        off += t->name_len[k] > k_kafka_produce_topic_name_max ? k_kafka_produce_topic_name_max
                                                               : t->name_len[k];
    }
    u32 n = t->name_len[i] > k_kafka_produce_topic_name_max ? k_kafka_produce_topic_name_max
                                                            : t->name_len[i];
    return n == strlen(want) && memcmp(&t->names[off], want, n) == 0;
}

static void check_numbered(const char *name, u32 topics) {
    u32 len;
    unsigned char *data = load(name, &len);
    kafka_produce_topics_t t;
    walk(data, len, &t);
    const u32 named = topics < k_kafka_produce_max_topics ? topics : k_kafka_produce_max_topics;
    expect(t.total == topics, name, "total is the topic count of the request");
    expect(t.count == named, name, "every topic up to the limit has a name");
    bool names_ok = true;
    bool parts_ok = true;
    for (u32 i = 0; i < named; i++) {
        char want[32];
        snprintf(want, sizeof(want), "orders.topic-%02u", i);
        names_ok = names_ok && name_is(&t, i, want);
        parts_ok = parts_ok && t.partition[i] == (s32)i;
    }
    expect(names_ok, name, "names in request order");
    expect(parts_ok, name, "first partition of each topic");
    expect(g_out_of_bounds == 0, name, "no read outside the request");

    // Every shorter buffer gives a prefix of the full result and never reads outside it.
    bool prefix_ok = true;
    bool bounds_ok = true;
    for (u32 cut = 0; cut < len; cut++) {
        kafka_produce_topics_t c;
        walk(data, cut, &c);
        if (c.count > t.count) {
            prefix_ok = false;
        }
        for (u32 i = 0; i < c.count; i++) {
            if (c.name_len[i] != t.name_len[i]) {
                prefix_ok = false;
            }
        }
        bounds_ok = bounds_ok && g_out_of_bounds == 0;
    }
    expect(prefix_ok, name, "a truncated request gives a prefix of the topics");
    expect(bounds_ok, name, "a truncated request is not read outside its end");
    free(data);
}

static void test_numbered_requests(void) {
    check_numbered("kmsg_v3_1_topic", 1);
    check_numbered("kmsg_v3_3_topics", 3);
    check_numbered("kmsg_v7_3_topics", 3);
    check_numbered("kmsg_v8_9_topics", 9);
}

// The second topic starts after the record data of the first, far after 256 bytes.
static void test_second_topic_after_prefix(void) {
    u32 len;
    unsigned char *data = load("kmsg_v7_3_topics", &len);
    kafka_produce_topics_t t;
    walk(data, 256, &t);
    expect(t.count == 1, "kmsg_v7_3_topics", "256 bytes hold only the first topic");
    free(data);
}

static void test_name_at_cap(void) {
    u32 len;
    unsigned char *data = load("kmsg_v8_name_at_cap", &len);
    kafka_produce_topics_t t;
    walk(data, len, &t);
    char cap[k_kafka_produce_topic_name_max + 1];
    memset(cap, 'c', k_kafka_produce_topic_name_max);
    cap[k_kafka_produce_topic_name_max] = 0;
    expect(t.count == 3, "kmsg_v8_name_at_cap", "3 names");
    expect(name_is(&t, 0, "short") && name_is(&t, 1, cap) && name_is(&t, 2, "after-cap"),
           "kmsg_v8_name_at_cap",
           "a name of exactly the cap is complete");
    free(data);
}

static void test_name_over_cap(void) {
    u32 len;
    unsigned char *data = load("kmsg_v8_name_over_cap", &len);
    kafka_produce_topics_t t;
    walk(data, len, &t);
    char cut[k_kafka_produce_topic_name_max + 1];
    memset(cut, 'l', k_kafka_produce_topic_name_max);
    cut[k_kafka_produce_topic_name_max] = 0;
    expect(t.count == 2, "kmsg_v8_name_over_cap", "2 names");
    expect(t.name_len[0] == 200, "kmsg_v8_name_over_cap", "the length as sent is kept");
    expect(name_is(&t, 0, cut) && name_is(&t, 1, "after-long"),
           "kmsg_v8_name_over_cap",
           "a long name is cut at the cap, the next name follows");
    free(data);
}

// Flexible versions (varint lengths) and topic ids (version 13) are not read: userspace keeps
// the first topic of the request prefix.
static void check_not_read(const char *name) {
    u32 len;
    unsigned char *data = load(name, &len);
    kafka_produce_topics_t t;
    walk(data, len, &t);
    expect(t.total == 0 && t.count == 0, name, "the version is not read");
    expect(g_out_of_bounds == 0, name, "no read outside the request");
    free(data);
}

static void test_not_read(void) {
    check_not_read("kmsg_v9_3_topics");
    check_not_read("kmsg_v12_9_topics");
    check_not_read("kmsg_v13_1_topic");
}

// More partitions than loop steps: the walk stops and keeps the topics read before.
static void test_step_limit(void) {
    u32 len;
    unsigned char *data = load("kmsg_v7_300_partitions", &len);
    kafka_produce_topics_t t;
    walk(data, len, &t);
    expect(t.total == 2 && t.count == 1,
           "kmsg_v7_300_partitions",
           "the step limit keeps the first topic");
    expect(g_out_of_bounds == 0, "kmsg_v7_300_partitions", "no read outside the request");
    free(data);
}

static void check_sarama(const char *name) {
    u32 len;
    unsigned char *data = load(name, &len);
    kafka_produce_topics_t t;
    walk(data, len, &t);
    expect(t.total == 5 && t.count == 5, name, "5 topics, 5 names");
    const char *want[] = {"alpha", "bravo", "charlie", "delta", "echo"};
    int found = 0;
    for (u32 w = 0; w < 5; w++) {
        for (u32 i = 0; i < t.count; i++) {
            if (name_is(&t, i, want[w])) {
                found++;
                break;
            }
        }
    }
    bool parts_ok = true;
    for (u32 i = 0; i < t.count; i++) {
        parts_ok = parts_ok && (t.partition[i] == 0 || t.partition[i] == 1);
    }
    expect(found == 5, name, "every topic name is found");
    expect(parts_ok, name, "partitions are 0 or 1");
    expect(g_out_of_bounds == 0, name, "no read outside the request");
    free(data);
}

static void test_not_produce(void) {
    // Fetch v11 header: api key 1
    const unsigned char fetch[] = {0, 0, 0, 20, 0, 1, 0, 11, 0, 0, 0, 7, 0, 2, 'i', 'd', 0, 0, 0, 0};
    kafka_produce_topics_t t;
    walk(fetch, sizeof(fetch), &t);
    expect(t.total == 0 && t.count == 0, "fetch", "a Fetch request is not read");
}

int main(void) {
    test_numbered_requests();
    test_second_topic_after_prefix();
    test_name_at_cap();
    test_name_over_cap();
    test_not_read();
    test_step_limit();
    check_sarama("sarama_v0_11_5_topics");
    check_sarama("sarama_v2_4_5_topics");
    test_not_produce();

    if (failures) {
        printf("%d failures\n", failures);
        return 1;
    }
    printf("all passed\n");
    return 0;
}
