// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/kafka_produce_topics.h>

// Reads the topic names of a Kafka Produce request that a Go Sarama client writes. The request is
// in user memory at buf, len bytes, and starts with the message size.
//
// Wire format: https://kafka.apache.org/protocol#The_Messages_Produce
//   message_size int32, api_key int16, api_version int16, correlation_id int32,
//   client_id nullable string (int16 length),
//   [version >= 3: transactional_id nullable string],
//   acks int16, timeout_ms int32,
//   [topic_data]: name string, [partition_data]: index int32, records nullable bytes (int32 length).
// Versions 0 to 8 are read. Versions 9 and later (flexible versions, varint lengths) are not read:
// Go Sarama does not send them, and their varint paths make the program too complex for the
// verifier.
//
// This header uses only bpf_probe_read_user, so a unit test can include it.

enum {
    k_sarama_produce_api_key = 0,
    k_sarama_produce_first_transactional_version = 3,
    k_sarama_produce_max_version = 8,
    // message_size + api_key + api_version + correlation_id
    k_sarama_produce_fixed_header_len = 12,
    k_sarama_peek_len = 8,
    // Loop steps: one step reads one topic header or one partition. The step count limits the
    // partitions that come before the last topic that gets a name.
    k_sarama_produce_max_steps = 256,
};

// Hides the value from the compiler, so the compiler keeps the bound check or mask that follows;
// the verifier needs it to bound a size or an offset.
static __always_inline u32 sarama_opaque(u32 v) {
    asm volatile("" : "+r"(v));
    return v;
}

// Returns v, which the caller has checked to be 1..max, in a form that bounds a helper size for
// the verifier. max is a power of two. Kernels before 6.8 lose the bound of a compare when the
// compiler spills the value before the compare; the mask keeps the bound and does not change v.
static __always_inline u32 sarama_size(u32 v, u32 max) {
    return ((sarama_opaque(v) - 1) & (max - 1)) + 1;
}

// Reads up to k_sarama_peek_len bytes at buf + off into out, never after buf + len. The bytes
// after the end of the buffer are zero. Returns false when off is at or after the end or the read
// fails. The caller checks that the bytes it uses are before the end.
static __always_inline bool sarama_peek(const unsigned char *buf,
                                        u32 len,
                                        u32 off,
                                        unsigned char out[k_sarama_peek_len]) {
    __builtin_memset(out, 0, k_sarama_peek_len);
    if (off >= len) {
        return false;
    }
    u32 n = sarama_opaque(len - off);
    if (n > k_sarama_peek_len) {
        n = k_sarama_peek_len;
    }
    n = sarama_size(n, k_sarama_peek_len);
    return bpf_probe_read_user(out, n, buf + off) == 0;
}

static __always_inline u32 sarama_be16(const unsigned char *b) {
    return ((u32)b[0] << 8) | (u32)b[1];
}

static __always_inline u32 sarama_be32(const unsigned char *b) {
    return ((u32)b[0] << 24) | ((u32)b[1] << 16) | ((u32)b[2] << 8) | (u32)b[3];
}

// True when n bytes from off are in the buffer. off may be after the end.
static __always_inline bool sarama_has(u32 len, u32 off, u32 n) {
    return off <= len && n <= len - off;
}

// Skips a nullable string (int16 length, -1 is null) at buf + off. Returns the offset after it,
// or 0 on error.
static __always_inline u32 sarama_skip_string(const unsigned char *buf, u32 len, u32 off) {
    unsigned char b[k_sarama_peek_len];
    if (!sarama_peek(buf, len, off, b) || !sarama_has(len, off, 2)) {
        return 0;
    }
    u32 n = sarama_be16(b);
    if (n == 0xffff) {
        n = 0;
    } else if (n >= 0x8000) {
        return 0;
    }
    if (!sarama_has(len, off + 2, n)) {
        return 0;
    }
    return off + 2 + n;
}

// Fills out with the topics of the Produce request in buf. out must be zero. On a parse error
// out keeps the topics read before the error.
static __always_inline void
sarama_produce_topics(const unsigned char *buf, u32 len, kafka_produce_topics_t *out) {
    unsigned char b[k_sarama_peek_len];
    if (!sarama_has(len, 0, k_sarama_produce_fixed_header_len + 2) ||
        !sarama_peek(buf, len, 4, b)) {
        return;
    }
    if (sarama_be16(&b[0]) != k_sarama_produce_api_key) {
        return;
    }
    const u32 version = sarama_be16(&b[2]);
    if (version > k_sarama_produce_max_version) {
        return;
    }

    u32 off = sarama_skip_string(buf, len, k_sarama_produce_fixed_header_len); // client_id
    if (!off) {
        return;
    }
    if (version >= k_sarama_produce_first_transactional_version) {
        off = sarama_skip_string(buf, len, off); // transactional_id
        if (!off) {
            return;
        }
    }
    off += 2 + 4; // acks, timeout_ms

    if (!sarama_peek(buf, len, off, b) || !sarama_has(len, off, 4)) {
        return;
    }
    const u32 total = sarama_be32(b);
    if (total == 0 || total >= 0x80000000) {
        return;
    }
    off += 4;
    out->total = total;

    // The loop keeps the topic count, the bytes used in names[] and the first partition in out
    // (map memory) and not in registers: the verifier does not track map memory, so states of one
    // step that differ only in these values are pruned as one. The volatile reads keep the
    // compiler from holding the values in registers.
    u32 parts_left = 0;

    for (u32 step = 0; step < k_sarama_produce_max_steps; step++) {
        if (!sarama_peek(buf, len, off, b)) {
            break;
        }
        if (parts_left == 0) {
            // topic header: name, then the partition count
            const u32 count = *(volatile u8 *)&out->count;
            if (count >= total || count >= k_kafka_produce_max_topics) {
                break;
            }
            if (!sarama_has(len, off, 2)) {
                break;
            }
            const u32 name_len = sarama_be16(b);
            if (name_len == 0 || name_len >= 0x8000) {
                break;
            }
            off += 2;
            if (!sarama_has(len, off, name_len)) {
                break;
            }

            u32 copy = sarama_opaque(name_len);
            if (copy > k_kafka_produce_topic_name_max) {
                copy = k_kafka_produce_topic_name_max;
            }
            copy = sarama_size(copy, k_kafka_produce_topic_name_max);
            u32 start = *(volatile u16 *)&out->names_used;
            if (start >= k_kafka_produce_names_start_max) {
                break;
            }
            // The 6.1 verifier does not bound the offset by the compare: the mask does, and does
            // not change a checked value.
            start = sarama_opaque(start) & (k_kafka_produce_names_start_max - 1);
            if (bpf_probe_read_user(&out->names[start], copy, buf + off) != 0) {
                break;
            }
            off += name_len;

            if (!sarama_peek(buf, len, off, b) || !sarama_has(len, off, 4)) {
                break;
            }
            const u32 parts = sarama_be32(b);
            if (parts >= 0x80000000) {
                break;
            }
            off += 4;

            // count < k_kafka_produce_max_topics here; without the asm the compiler drops the mask
            // that bounds the index for the verifier
            const u32 idx = sarama_opaque(count) & (k_kafka_produce_max_topics - 1);
            out->name_len[idx] = name_len > 255 ? 255 : name_len;
            out->partition[idx] = -1;
            out->names_used = start + copy;
            out->count = count + 1;

            parts_left = parts;
            continue;
        }

        // partition: index, then the record set (int32 length, -1 is null)
        if (!sarama_has(len, off, 8)) {
            break;
        }
        const u32 index = sarama_be32(b);
        u32 records = sarama_be32(&b[4]);
        if (records == 0xffffffff) {
            records = 0;
        } else if (records >= 0x80000000) {
            break;
        }
        off += 8;
        if (!sarama_has(len, off, records)) {
            break;
        }
        // the topic header set the partition to -1
        const u32 idx =
            sarama_opaque(*(volatile u8 *)&out->count - 1) & (k_kafka_produce_max_topics - 1);
        if (*(volatile s32 *)&out->partition[idx] == -1) {
            out->partition[idx] = (s32)index;
        }
        off += records;
        parts_left--;
    }
}
