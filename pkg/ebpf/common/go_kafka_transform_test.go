// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestReadGoKafkaGoRequestIntoSpanOperation(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   uint8
		method   string
		spanKind string
	}{
		{
			name:     "fetch",
			apiKey:   kafkaGoAPIFetch,
			method:   request.MessagingProcess,
			spanKind: "SPAN_KIND_CONSUMER",
		},
		{
			name:     "produce",
			apiKey:   kafkaGoAPIProduce,
			method:   request.MessagingSend,
			spanKind: "SPAN_KIND_PRODUCER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := GoKafkaGoClientInfo{Op: tt.apiKey}
			copy(event.Topic[:], "test-topic")

			var raw bytes.Buffer
			require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))

			span, ignore, err := ReadGoKafkaGoRequestIntoSpan(&ringbuf.Record{RawSample: raw.Bytes()})

			require.NoError(t, err)
			assert.False(t, ignore)
			assert.Equal(t, request.EventTypeKafkaClient, span.Type)
			assert.Equal(t, "github.com/segmentio/kafka-go", span.Statement)
			assert.Equal(t, tt.method, span.Method)
			assert.Equal(t, "test-topic", span.Path)
			assert.Equal(t, tt.method+" test-topic", span.TraceName())
			assert.Equal(t, tt.spanKind, span.ServiceGraphKind())
		})
	}
}

func TestReadGoKafkaGoRequestIntoSpanTraceFlags(t *testing.T) {
	event := GoKafkaGoClientInfo{Op: kafkaGoAPIProduce}
	event.Tp.Flags = TPFlagSampled

	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))

	span, _, err := ReadGoKafkaGoRequestIntoSpan(&ringbuf.Record{RawSample: raw.Bytes()})

	require.NoError(t, err)
	assert.Equal(t, uint8(TPFlagSampled), span.TraceFlags)
}

// saramaEvent builds the event of the eBPF program for a request from
// bpf/tests/testdata/kafka_produce: the first bytes of the request, and the topics
// that the program reads from the full request.
func saramaEvent(t *testing.T, fixture string, names []string, nameLen []int, partitions []int32, total uint32) []byte {
	t.Helper()
	text, err := os.ReadFile(filepath.Join("..", "..", "..", "bpf", "tests", "testdata", "kafka_produce", fixture+".hex"))
	require.NoError(t, err)
	var digits strings.Builder
	for _, line := range strings.Split(string(text), "\n") {
		if !strings.HasPrefix(line, "#") {
			digits.WriteString(strings.TrimSpace(line))
		}
	}
	data, err := hex.DecodeString(digits.String())
	require.NoError(t, err)

	event := GoSaramaClientInfo{Type: EventTypeGoSarama, StartMonotimeNs: 100, EndMonotimeNs: 200}
	copy(event.Buf[:], data)
	event.Conn.S_port = 40000
	event.Conn.D_port = 9092
	event.Conn.S_addr[15] = 1
	event.Conn.D_addr[15] = 2
	event.Pid.HostPid = 7
	event.Topics.Total = total
	event.Topics.Count = uint8(len(names))
	off := 0
	for i, name := range names {
		n := copy(event.Topics.Names[off:], name)
		off += n
		event.Topics.NameLen[i] = uint8(len(name))
		if nameLen != nil {
			event.Topics.NameLen[i] = uint8(nameLen[i])
		}
		event.Topics.Partition[i] = partitions[i]
	}

	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))
	return raw.Bytes()
}

func numberedTopics(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("orders.topic-%02d", i)
	}
	return out
}

// letterNames returns n names of 128 bytes: "aaa...", "bbb...", ...
func letterNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strings.Repeat(string(rune('a'+i)), 128)
	}
	return out
}

func TestReadGoSaramaRequestIntoSpanTopics(t *testing.T) {
	long200 := strings.Repeat("l", 200)
	tests := []struct {
		name       string
		raw        func(t *testing.T) []byte
		clientID   string
		method     string
		topics     []string
		partitions []int
	}{
		{
			name: "produce v3 one topic",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v3_1_topic", numberedTopics(1), nil, []int32{0}, 1)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: numberedTopics(1), partitions: []int{0},
		},
		{
			name: "produce v7 three topics",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v7_3_topics", numberedTopics(3), nil, []int32{0, 1, 2}, 3)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: numberedTopics(3), partitions: []int{0, 1, 2},
		},
		{
			name: "produce v8 nine topics reports the first eight",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v8_9_topics", numberedTopics(8), nil, []int32{0, 1, 2, 3, 4, 5, 6, 7}, 9)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: numberedTopics(8), partitions: []int{0, 1, 2, 3, 4, 5, 6, 7},
		},
		{
			name: "flexible produce v9 is not read by the eBPF program: first topic only",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v9_3_topics", nil, nil, nil, 0)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: numberedTopics(1), partitions: []int{0},
		},
		{
			name: "topic without partition data",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v7_3_topics", numberedTopics(2), nil, []int32{0, -1}, 2)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: numberedTopics(2), partitions: []int{0, -1},
		},
		{
			name: "name at the cap",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v8_name_at_cap", []string{"short", strings.Repeat("c", 128), "after-cap"}, nil, []int32{0, 1, 2}, 3)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: []string{"short", strings.Repeat("c", 128), "after-cap"}, partitions: []int{0, 1, 2},
		},
		{
			name: "a cut first name comes complete from the request prefix",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v8_name_over_cap", []string{long200[:128], "after-long"}, []int{200, 10}, []int32{0, 1}, 2)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: []string{long200, "after-long"}, partitions: []int{0, 1},
		},
		{
			name: "produce without names keeps the first topic of the prefix",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v3_3_topics", nil, nil, nil, 0)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: numberedTopics(1), partitions: []int{0},
		},
		{
			name: "names after the end of the name buffer are dropped",
			raw: func(t *testing.T) []byte {
				return saramaEvent(t, "kmsg_v7_3_topics", letterNames(8), []int{255, 255, 255, 255, 255, 255, 255, 255}, []int32{0, 1, 2, 3, 4, 5, 6, 7}, 8)
			},
			clientID: "producer-1", method: request.MessagingSend,
			topics: letterNames(5), partitions: []int{0, 1, 2, 3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseCtx := NewEBPFParseContext(nil, nil, nil)
			var emitted []request.Span
			parseCtx.emitSpans = func(spans []request.Span) { emitted = append(emitted, spans...) }

			span, ignore, err := ReadGoSaramaRequestIntoSpan(parseCtx, &ringbuf.Record{RawSample: tt.raw(t)})
			require.NoError(t, err)
			require.False(t, ignore)

			spans := append([]request.Span{span}, emitted...)
			require.Len(t, spans, len(tt.topics))
			for i, s := range spans {
				assert.Equal(t, tt.topics[i], s.Path, "topic %d", i)
				assert.Equal(t, tt.method, s.Method)
				assert.Equal(t, tt.clientID, s.Statement)
				assert.Equal(t, request.EventTypeKafkaClient, s.Type)
				assert.Equal(t, int64(100), s.Start)
				assert.Equal(t, int64(200), s.End)
				assert.Equal(t, 9092, s.HostPort)
				assert.Equal(t, spans[0].Peer, s.Peer)
				assert.Equal(t, spans[0].Host, s.Host)
				if tt.partitions[i] < 0 {
					assert.Nil(t, s.MessagingInfo, "topic %d", i)
				} else {
					require.NotNil(t, s.MessagingInfo, "topic %d", i)
					assert.Equal(t, tt.partitions[i], s.MessagingInfo.Partition, "topic %d", i)
				}
			}
		})
	}
}

// A Fetch request reports its first topic, as before.
func TestReadGoSaramaFetchKeepsFirstTopic(t *testing.T) {
	// Fetch v4: replica_id, max_wait, min_bytes, max_bytes, isolation, 2 topics of 1 partition
	var b bytes.Buffer
	w := func(v any) { require.NoError(t, binary.Write(&b, binary.BigEndian, v)) }
	str := func(s string) { w(int16(len(s))); b.WriteString(s) }
	w(int32(0)) // message size, set below
	w(int16(1))
	w(int16(4))
	w(int32(9))
	str("consumer-1")
	w(int32(-1))
	w(int32(500))
	w(int32(1))
	w(int32(1 << 20))
	w(int8(0))
	w(int32(2))
	for _, topic := range []string{"fetch-a", "fetch-b"} {
		str(topic)
		w(int32(1))
		w(int32(0))
		w(int64(10))
		w(int32(1 << 20))
	}

	req := b.Bytes()
	binary.BigEndian.PutUint32(req, uint32(len(req)-4))
	event := GoSaramaClientInfo{Type: EventTypeGoSarama}
	copy(event.Buf[:], req)
	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))

	parseCtx := NewEBPFParseContext(nil, nil, nil)
	var emitted []request.Span
	parseCtx.emitSpans = func(spans []request.Span) { emitted = append(emitted, spans...) }
	span, ignore, err := ReadGoSaramaRequestIntoSpan(parseCtx, &ringbuf.Record{RawSample: raw.Bytes()})
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, request.MessagingProcess, span.Method)
	assert.Equal(t, "fetch-a", span.Path)
	assert.Equal(t, "consumer-1", span.Statement)
	assert.Empty(t, emitted)
}
