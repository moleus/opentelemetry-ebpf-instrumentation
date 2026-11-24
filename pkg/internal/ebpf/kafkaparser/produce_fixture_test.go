// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// The encoded requests in bpf/tests/testdata/kafka_produce. The record data of a topic comes
// before the next topic: the full request has every topic, a 256-byte prefix (the buffer that
// the Go Sarama probe sends) has only the first one complete.
func TestParseProduceRequestFixtures(t *testing.T) {
	tests := []struct {
		fixture string
		topics  int
	}{
		{fixture: "kmsg_v3_1_topic", topics: 1},
		{fixture: "kmsg_v3_3_topics", topics: 3},
		{fixture: "kmsg_v7_3_topics", topics: 3},
		{fixture: "kmsg_v8_9_topics", topics: 9},
		{fixture: "kmsg_v9_3_topics", topics: 3},
		{fixture: "kmsg_v12_9_topics", topics: 9},
		{fixture: "sarama_v0_11_5_topics", topics: 5},
		{fixture: "sarama_v2_4_5_topics", topics: 5},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			text, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "bpf", "tests", "testdata", "kafka_produce", tt.fixture+".hex"))
			require.NoError(t, err)
			data, err := hex.DecodeString(stripHexComments(string(text)))
			require.NoError(t, err)

			parse := func(b []byte) *ProduceRequest {
				hdr, err := NewKafkaRequestHeader(largebuf.NewLargeBufferFrom(b))
				require.NoError(t, err)
				r, err := hdr.NewBodyReader()
				require.NoError(t, err)
				req, err := ParseProduceRequest(&r, hdr)
				require.NoError(t, err)
				return req
			}
			full := parse(data).Topics
			require.Len(t, full, tt.topics)
			for _, topic := range full {
				assert.NotEmpty(t, topic.Name)
			}
			prefix := parse(data[:256]).Topics
			require.NotEmpty(t, prefix)
			assert.Equal(t, full[0].Name, prefix[0].Name)
			if len(full) > 1 {
				for _, topic := range prefix[1:] {
					assert.NotEqual(t, full[1].Name, topic.Name, "the second topic is after the prefix")
				}
			}
		})
	}
}

// stripHexComments removes the lines that start with # and the white space of a hex fixture.
func stripHexComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "#") {
			b.WriteString(strings.TrimSpace(line))
		}
	}
	return b.String()
}
