// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package largebuf

import (
	"bytes"
	"testing"
)

func FuzzLargeBufferLimitAndChunking(f *testing.F) {
	f.Add([]byte("abcDEF123"), uint16(4), uint8(1))
	f.Add([]byte{}, uint16(0), uint8(3))
	f.Fuzz(func(t *testing.T, input []byte, maxLen uint16, split uint8) {
		if len(input) > 4096 {
			input = input[:4096]
		}
		limit := int(maxLen % 1024)
		step := int(split%32) + 1
		lb := NewLargeBuffer()
		dropped := 0
		for i := 0; i < len(input); i += step {
			dropped += lb.AppendChunkWithLimit(input[i:min(i+step, len(input))], limit)
		}
		want := input[:min(len(input), limit)]
		if lb.Len() != len(want) || !bytes.Equal(lb.CloneBytes(), want) || dropped != len(input)-len(want) {
			t.Fatalf("limit invariant failed: bytes=%d retained=%d dropped=%d", len(input), lb.Len(), dropped)
		}
		// A read of every valid slice must match the owned copy.
		for i := range len(want) {
			n := len(want) - i
			got, err := lb.UnsafeViewAt(i, n)
			if err != nil || !bytes.Equal(got, want[i:]) {
				t.Fatalf("view mismatch at %d: %v", i, err)
			}
		}
	})
}
