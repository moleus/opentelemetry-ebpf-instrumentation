// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import (
	"encoding/binary"
	"reflect"
	"testing"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func fetchV4Seed() []byte {
	body := make([]byte, 0, 48)
	body = append(body, make([]byte, 17)...)      // fixed v4 fields
	body = binary.BigEndian.AppendUint32(body, 1) // one topic
	body = binary.BigEndian.AppendUint16(body, 4)
	body = append(body, []byte("test")...)
	body = binary.BigEndian.AppendUint32(body, 0) // zero partitions
	packet := make([]byte, 14)
	binary.BigEndian.PutUint16(packet[4:6], uint16(APIKeyFetch))
	binary.BigEndian.PutUint16(packet[6:8], 4)
	binary.BigEndian.PutUint32(packet[8:12], 42)
	packet = append(packet, body...)
	binary.BigEndian.PutUint32(packet[0:4], uint32(len(packet)-4))
	return packet
}

// Parse results should not depend on ring-buffer chunk segmentation.
// These calls use the real production parser and LargeBuffer implementation.
func FuzzKafkaChunkBoundaryInvariant(f *testing.F) {
	f.Add(fetchV4Seed(), uint8(3))
	f.Add([]byte{0, 0, 0, 40, 0, 1, 0, 4, 0, 0, 0, 1, 0, 0}, uint8(1))
	f.Add([]byte{}, uint8(1))
	f.Fuzz(func(t *testing.T, input []byte, split uint8) {
		if len(input) > 4096 {
			input = input[:4096]
		}
		flat := largebuf.NewLargeBufferFrom(input)
		chunked := largebuf.NewLargeBuffer()
		step := int(split%32) + 1
		for i := 0; i < len(input); i += step {
			chunked.AppendChunk(input[i:min(i+step, len(input))])
		}
		hdrFlat, errFlat := NewKafkaRequestHeader(flat)
		hdrChunks, errChunks := NewKafkaRequestHeader(chunked)
		if (errFlat == nil) != (errChunks == nil) {
			t.Fatalf("header success differs: flat=%v chunks=%v", errFlat, errChunks)
		}
		if errFlat != nil {
			if errFlat.Error() != errChunks.Error() {
				t.Fatalf("error differs: %v / %v", errFlat, errChunks)
			}
			return
		}
		if hdrFlat.MessageSize() != hdrChunks.MessageSize() || hdrFlat.APIKey() != hdrChunks.APIKey() ||
			hdrFlat.APIVersion() != hdrChunks.APIVersion() || hdrFlat.CorrelationID() != hdrChunks.CorrelationID() ||
			hdrFlat.ClientID() != hdrChunks.ClientID() {
			t.Fatal("decoded header differs between chunking strategies")
		}
		readerA, errA := hdrFlat.NewBodyReader()
		readerB, errB := hdrChunks.NewBodyReader()
		if (errA == nil) != (errB == nil) {
			t.Fatal("body reader differs")
		}
		if errA != nil {
			return
		}
		if hdrFlat.APIKey() == APIKeyFetch {
			a, ea := ParseFetchRequest(&readerA, hdrFlat)
			b, eb := ParseFetchRequest(&readerB, hdrChunks)
			if (ea == nil) != (eb == nil) || !reflect.DeepEqual(a, b) {
				t.Fatalf("Fetch differs: %v / %v", ea, eb)
			}
		}
		if hdrFlat.APIKey() == APIKeyProduce {
			a, ea := ParseProduceRequest(&readerA, hdrFlat)
			b, eb := ParseProduceRequest(&readerB, hdrChunks)
			if (ea == nil) != (eb == nil) || !reflect.DeepEqual(a, b) {
				t.Fatalf("Produce differs: %v / %v", ea, eb)
			}
		}
	})
}

func TestFetchV4SeedIsValid(t *testing.T) {
	lb := largebuf.NewLargeBufferFrom(fetchV4Seed())
	header, err := NewKafkaRequestHeader(lb)
	if err != nil {
		t.Fatal(err)
	}
	r, err := header.NewBodyReader()
	if err != nil {
		t.Fatal(err)
	}
	res, err := ParseFetchRequest(&r, header)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Topics) != 1 || res.Topics[0].Name != "test" {
		t.Fatalf("invalid seed result: %+v", res)
	}
}
