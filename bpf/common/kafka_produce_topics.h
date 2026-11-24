// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum {
    // Topics of one Produce request that get a span. A request with more topics reports the first
    // k_kafka_produce_max_topics; total keeps the topic count of the request.
    k_kafka_produce_max_topics = 8,
    // A longer topic name is cut to this length.
    k_kafka_produce_topic_name_max = 128,
    // Names follow each other in names[]. A name starts before offset
    // k_kafka_produce_names_start_max (a power of two), so the last name always fits.
    k_kafka_produce_names_start_max = 512,
    k_kafka_produce_names_len = k_kafka_produce_names_start_max + k_kafka_produce_topic_name_max,
};

// The topics of a Produce request, read from the full request buffer. The record data of a topic
// comes before the next topic, so a fixed prefix of the request holds only the first topic.
typedef struct kafka_produce_topics {
    // Number of topics in the request. 0: the request was not read (not a Produce request, or a
    // version that is not supported).
    u32 total;
    // Number of names in names[].
    u8 count;
    // Name length as sent in the request, at most 255. The copy in names[] is at most
    // k_kafka_produce_topic_name_max bytes.
    u8 name_len[k_kafka_produce_max_topics];
    u8 _pad;
    // Bytes used in names[].
    u16 names_used;
    // First partition of each topic, -1 when the topic has no partition data.
    s32 partition[k_kafka_produce_max_topics];
    unsigned char names[k_kafka_produce_names_len];
} kafka_produce_topics_t;
