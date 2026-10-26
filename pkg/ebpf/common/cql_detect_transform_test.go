// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func cqlTestFrame(version, flags byte, stream uint16, op byte, payload []byte) []byte {
	b := make([]byte, 9+len(payload))
	b[0], b[1], b[4] = version, flags, op
	binary.BigEndian.PutUint16(b[2:4], stream)
	binary.BigEndian.PutUint32(b[5:9], uint32(len(payload)))
	copy(b[9:], payload)
	return b
}

func cqlTestQuery(s string) []byte {
	b := make([]byte, 4+len(s)+3)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	b[len(b)-2] = 1 // ONE consistency
	return b
}

func TestMatchCQLRejectsFalseMSSQLSpan(t *testing.T) {
	text := "INSERT INTO billing.orders_v2 (id) VALUES (1)"
	req := cqlTestFrame(4, 0, 0, 7, cqlTestQuery(text))
	// Forces the collision with the old kernel TDS response classifier.
	binary.BigEndian.PutUint16(req[2:4], uint16(len(req)))
	resp := cqlTestFrame(0x84, 0, uint16(len(req)), 8, []byte{0, 0, 0, 1})
	event := &TCPRequestInfo{StartMonotimeNs: 100, EndMonotimeNs: 200, RespLen: uint32(len(resp))}

	span, ignore, matched, err := matchCQL(event, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(resp))
	require.NoError(t, err)
	assert.True(t, matched)
	assert.False(t, ignore)
	assert.Equal(t, "INSERT", span.Method)
	assert.Equal(t, text, span.Statement)
	assert.Equal(t, int(request.DBCassandra), span.SubType)
	assert.Equal(t, int64(200), span.End)
	assert.Equal(t, 0, span.Status)

	// A response from another in-flight stream must not fabricate a duration.
	other := cqlTestFrame(0x84, 0, uint16(len(req))+1, 8, []byte{0, 0, 0, 1})
	_, ignore, matched, err = matchCQL(event, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(other))
	require.NoError(t, err)
	assert.True(t, matched)
	assert.True(t, ignore)
}

func TestMatchCQLCannotInventDurations(t *testing.T) {
	req := cqlTestFrame(4, 0, 15, 7, cqlTestQuery("SELECT * FROM store.customer_orders"))
	resp := cqlTestFrame(0x84, 0, 15, 8, []byte{0, 0, 0, 1})
	cases := []struct {
		name string
		req  []byte
		resp []byte
	}{
		{"request only", req, nil},
		{"response only", nil, resp},
		{"truncated request", req[:len(req)-1], resp},
		{"coalesced requests", append(append([]byte(nil), req...), req...), resp},
		{"compressed request", cqlTestFrame(4, 1, 15, 7, cqlTestQuery("SELECT * FROM store.customer_orders")), resp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ignore, matched, err := matchCQL(&TCPRequestInfo{}, largebuf.NewLargeBufferFrom(tc.req), largebuf.NewLargeBufferFrom(tc.resp))
			require.NoError(t, err)
			assert.True(t, matched)
			assert.True(t, ignore)
		})
	}
}

func TestMatchCQLPreservesTDSSignatures(t *testing.T) {
	packet := makeTDSPacket(kMSSQLBatch, 1, []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, ' ', 0, '1', 0})
	assert.True(t, isMSSQL(largebuf.NewLargeBufferFrom(packet)))
	_, _, matched, err := matchCQL(&TCPRequestInfo{}, largebuf.NewLargeBufferFrom(packet), largebuf.NewLargeBufferFrom(nil))
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestMatchCQLErrorResponse(t *testing.T) {
	req := cqlTestFrame(4, 0, 25, 7, cqlTestQuery("INSERT INTO billing.inv_v1 (id) VALUES (1)"))
	resp := cqlTestFrame(0x84, 0, 25, 0, []byte{0, 0, 0, 0x0a, 0, 0})
	span, ignore, matched, err := matchCQL(&TCPRequestInfo{}, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(resp))
	require.NoError(t, err)
	assert.True(t, matched)
	assert.False(t, ignore)
	assert.Equal(t, 1, span.Status)
}
