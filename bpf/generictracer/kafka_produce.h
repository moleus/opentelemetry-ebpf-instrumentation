// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// A Kafka Produce request with acks=0 gets no response from the broker. The generic TCP
// tracker closes a request on the response, so it must find out from the request bytes
// alone that no response will come. These helpers only read a bounded prefix of the
// captured request: they use no BPF helper and no map, so a unit test includes this header.
//
// Wire format: https://kafka.apache.org/protocol#protocol_messages
//   message_size int32, api_key int16, api_version int16, correlation_id int32,
//   client_id nullable string (int16 length),
//   [version >= 9: tagged fields, one 0 byte when there are none],
//   [version >= 3: transactional_id nullable string, compact from version 9],
//   acks int16.
enum {
    k_kafka_api_key_produce = 0,
    // latest Produce version known to the userspace parser
    k_kafka_max_produce_api_version = 13,
    // same limit as KafkaMaxPayloadLen in the userspace parser
    k_kafka_max_payload_len = 20 * 1024 * 1024,

    k_kafka_produce_first_transactional_version = 3,
    k_kafka_produce_first_flexible_version = 9,
    // message_size + api_key + api_version + correlation_id
    k_kafka_produce_fixed_header_len = 12,
    // The captured prefix is read up to this length. It is a power of two (the offsets are
    // masked) and the generic tracker always captures at least this many bytes of a request
    // that is at least this long.
    k_kafka_produce_window = 128,
    // an acks value that no request carries
    k_kafka_acks_unknown = 0x10000,
};

// Bounds an offset that the caller has already checked against captured. That check does not
// give the verifier a bound: the compiler drops a check that captured <= the window implies,
// and kernels before 6.8 do not bound a register by a compare with another register. The empty
// asm hides the range from the compiler, so the compiler keeps the mask; the mask bounds the
// map-value pointer. For a checked offset the mask does not change the value.
static __always_inline u32 kafka_window_off(u32 off) {
    asm volatile("" : "+r"(off));
    return off & (k_kafka_produce_window - 1);
}

static __always_inline u32 kafka_be16(const unsigned char *b, u32 off, u32 captured) {
    // Use subtraction after guarding captured to avoid an overflowing off + 2 expression.
    if (captured < 2 || off > k_kafka_produce_window - 2 || off > captured - 2) {
        return k_kafka_acks_unknown;
    }
    off = kafka_window_off(off);
    return ((u32)b[off] << 8) | (u32)b[off + 1];
}

// Narrow parser-controlled string lengths before adding them to an offset. The BPF verifier
// does not infer a 16-bit range from two byte loads combined with shift/OR, so keep it explicit.
static __always_inline u32 kafka_unsigned16(const unsigned char *b, u32 off, u32 captured) {
    const u32 value = kafka_be16(b, off, captured);
    if (value == k_kafka_acks_unknown) {
        return k_kafka_acks_unknown;
    }
    return (u16)value;
}

static __always_inline u32 kafka_be32(const unsigned char *b) {
    return ((u32)b[0] << 24) | ((u32)b[1] << 16) | ((u32)b[2] << 8) | (u32)b[3];
}

// Returns the acks of the Produce request in buf[0, captured), or k_kafka_acks_unknown when
// the buffer is not a Produce request or does not reach the acks field.
static __always_inline int kafka_produce_acks(const unsigned char *buf, u32 captured) {
    if (captured > k_kafka_produce_window) {
        captured = k_kafka_produce_window;
    }
    if (captured < k_kafka_produce_fixed_header_len + 2) {
        return k_kafka_acks_unknown;
    }
    if (kafka_be16(buf, 4, captured) != k_kafka_api_key_produce) {
        return k_kafka_acks_unknown;
    }
    const u32 version = kafka_be16(buf, 6, captured);
    if (version > k_kafka_max_produce_api_version) {
        return k_kafka_acks_unknown;
    }

    u32 off = k_kafka_produce_fixed_header_len;
    // client_id: int16 length, -1 is null
    u32 n = kafka_unsigned16(buf, off, captured);
    if (n == k_kafka_acks_unknown) {
        return k_kafka_acks_unknown;
    }
    off += 2;
    if (n >= 0x8000) {
        if (n != 0xffff) {
            return k_kafka_acks_unknown;
        }
        n = 0;
    }
    off += n;

    if (version >= k_kafka_produce_first_flexible_version) {
        // no tagged fields: a single 0 byte
        if (off >= captured || buf[kafka_window_off(off)] != 0) {
            return k_kafka_acks_unknown;
        }
        off += 1;
    }
    if (version >= k_kafka_produce_first_transactional_version) {
        if (version >= k_kafka_produce_first_flexible_version) {
            // compact nullable string: length + 1 as a varint, 0 is null
            if (off >= captured) {
                return k_kafka_acks_unknown;
            }
            const u32 b = buf[kafka_window_off(off)];
            off += 1;
            if (b >= 0x80) {
                return k_kafka_acks_unknown;
            }
            if (b > 1) {
                off += b - 1;
            }
        } else {
            if (captured < 2 || off > captured - 2) {
                return k_kafka_acks_unknown;
            }
            n = kafka_unsigned16(buf, off, captured);
            if (n == k_kafka_acks_unknown) {
                return k_kafka_acks_unknown;
            }
            off += 2;
            if (n >= 0x8000) {
                if (n != 0xffff) {
                    return k_kafka_acks_unknown;
                }
                n = 0;
            }
            off += n;
        }
    }
    if (captured < 2 || off > captured - 2) {
        return k_kafka_acks_unknown;
    }
    const u32 acks = kafka_be16(buf, off, captured);
    return (acks >= 0x8000) ? (int)acks - 0x10000 : (int)acks;
}

// True when the request that starts in buf is one complete Produce request with acks=0:
// req_len is the number of bytes read for the request so far (not the number captured) and
// captured is the number of valid bytes in buf. Such a request is final: no response comes.
static __always_inline bool
kafka_is_complete_acks0_produce(const unsigned char *buf, u32 captured, u32 req_len) {
    if (captured < k_kafka_produce_fixed_header_len + 2) {
        return false;
    }
    const u32 message_size = kafka_be32(&buf[0]);
    const u32 correlation_id = kafka_be32(&buf[8]);
    if (correlation_id >= 0x80000000 || message_size > k_kafka_max_payload_len ||
        message_size < k_kafka_produce_fixed_header_len - 4 + 2 || req_len != message_size + 4) {
        return false;
    }
    return kafka_produce_acks(buf, captured) == 0;
}
