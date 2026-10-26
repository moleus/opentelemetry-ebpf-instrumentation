// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cqlparser

import (
	"encoding/binary"
	"testing"
)

func frame(version byte, flags byte, stream uint16, opcode byte, body []byte) []byte {
	b := make([]byte, 9+len(body))
	b[0], b[1] = version, flags
	binary.BigEndian.PutUint16(b[2:], stream)
	b[4] = opcode
	binary.BigEndian.PutUint32(b[5:], uint32(len(body)))
	copy(b[9:], body)
	return b
}

func queryBody(q string) []byte {
	b := make([]byte, 4+len(q)+3)
	binary.BigEndian.PutUint32(b, uint32(len(q)))
	copy(b[4:], q)
	// ONE consistency and no query values
	b[len(b)-3], b[len(b)-2], b[len(b)-1] = 0, 1, 0
	return b
}

func TestCQLRealWorldInsertCollision(t *testing.T) {
	// Stream ID equals complete frame length. Old BPF is_mssql accepts this
	// as an exactly-sized TDS RESPONSE packet, even with no port heuristic.
	q := "INSERT INTO billing.orders_v2 (id) VALUES (?)"
	b := frame(0x04, 0, 0, opcodeQuery, queryBody(q))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	if !LooksLikeHeader(b) {
		t.Fatal("CQL header not identified")
	}
	if b[0] != 0x04 || b[1] != 0 || binary.BigEndian.Uint16(b[2:4]) != uint16(len(b)) || b[7] != 0 {
		t.Fatalf("bad TDS-collision fixture: %x", b[:9])
	}
	f, ok := ParseFrame(b)
	if !ok {
		t.Fatal("not a complete CQL frame")
	}
	op, got, ok := Operation(f)
	if !ok || op != "QUERY" || got != q || QueryOperation(got) != "INSERT" {
		t.Fatalf("parsed %q %q %v", op, got, ok)
	}
	r := frame(0x84, 0, uint16(len(b)), opcodeResult, []byte{0, 0, 0, 1})
	resp, ok := ParseFrame(r)
	if !ok || !PairedResponse(f, resp) {
		t.Fatal("valid response not paired")
	}
	r[3]++
	mismatch, _ := ParseFrame(r)
	if PairedResponse(f, mismatch) {
		t.Fatal("incorrectly paired another CQL stream")
	}
}

func TestValidVersionsAndOperations(t *testing.T) {
	cases := []struct {
		name      string
		v         byte
		opcode    byte
		body      []byte
		op, text  string
		supported bool
	}{
		{"v3 query", 3, opcodeQuery, queryBody("SELECT * FROM store.customer_orders"), "QUERY", "SELECT * FROM store.customer_orders", true},
		{"v4 query", 4, opcodeQuery, queryBody("INSERT INTO billing.inv_v1 (id) VALUES (7)"), "QUERY", "INSERT INTO billing.inv_v1 (id) VALUES (7)", true},
		{"prepare", 4, opcodePrepare, append([]byte{0, 0, 0, 8}, []byte("SELECT 1")...), "PREPARE", "SELECT 1", true},
		{"execute", 4, opcodeExecute, []byte{0, 2, 0xaa, 0xbb, 0, 1, 0}, "EXECUTE", "", true},
		{"batch", 4, opcodeBatch, []byte{0, 0, 1, 0, 0}, "BATCH", "", true},
		{"v5 excluded", 5, opcodeQuery, queryBody("SELECT 1"), "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := frame(tc.v, 0, 1, tc.opcode, tc.body)
			if !LooksLikeHeader(b) {
				t.Fatal("header missing")
			}
			f, ok := ParseFrame(b)
			if !ok {
				t.Fatal("complete frame missing")
			}
			op, txt, valid := Operation(f)
			if op != tc.op || txt != tc.text || valid != tc.supported {
				t.Fatalf("got op %q text %q supported %v", op, txt, valid)
			}
		})
	}
}

func TestCQLRejectBadCaptures(t *testing.T) {
	q := frame(4, 0, 1, opcodeQuery, queryBody("INSERT INTO billing.test (id) VALUES (1)"))
	for n := 0; n < len(q); n++ {
		_, ok := ParseFrame(q[:n])
		if ok {
			t.Fatalf("truncated frame %d parsed", n)
		}
	}
	two := append(append([]byte{}, q...), q...)
	if _, ok := ParseFrame(two); ok {
		t.Fatal("coalesced requests parsed as one duration")
	}
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"invalid version", func(b []byte) { b[0] = 2 }},
		{"invalid opcode", func(b []byte) { b[4] = 4 }},
		{"bad flags", func(b []byte) { b[1] = 0x80 }},
		{"invalid stream", func(b []byte) { b[2] = 0x80 }},
		{"body length huge", func(b []byte) { b[5] = 0x40 }},
		{"null query", func(b []byte) { b[15] = 0 }},
		{"compression", func(b []byte) { b[1] = 1 }},
		{"custom payload", func(b []byte) { b[1] = 4 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), q...)
			tc.edit(b)
			f, ok := ParseFrame(b)
			if ok {
				_, _, opok := Operation(f)
				if opok {
					t.Fatal("unsafe operation accepted")
				}
			}
		})
	}
}

func TestResponseChecks(t *testing.T) {
	req, _ := ParseFrame(frame(4, 0, 55, opcodeQuery, queryBody("SELECT 1")))
	cases := []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"result", frame(0x84, 0, 55, opcodeResult, []byte{0, 0, 0, 1}), true},
		{"error", frame(0x84, 0, 55, opcodeError, []byte{0, 0, 0, 0x0a, 0, 0}), true},
		{"other stream", frame(0x84, 0, 56, opcodeResult, []byte{0, 0, 0, 1}), false},
		{"wrong version", frame(0x83, 0, 55, opcodeResult, []byte{0, 0, 0, 1}), false},
		{"no result body", frame(0x84, 0, 55, opcodeResult, nil), false},
		{"compressed", frame(0x84, 1, 55, opcodeResult, []byte{0, 0, 0, 1}), false},
		{"traced result", frame(0x84, 2, 55, opcodeResult, []byte{0, 0, 0, 1}), false},
		{"invalid result kind", frame(0x84, 0, 55, opcodeResult, []byte{0, 0, 0, 99}), false},
		{"truncated error message", frame(0x84, 0, 55, opcodeError, []byte{0, 0, 0, 0x0a, 0, 5}), false},
		{"event", frame(0x84, 0, 0xffff, 0x0c, []byte{0, 0, 0, 1}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := ParseFrame(tc.data)
			if !ok {
				t.Fatal("frame not parsed")
			}
			if PairedResponse(req, f) != tc.valid {
				t.Fatal("wrong correlation")
			}
		})
	}
}

func TestOtherProtocolsDoNotLookLikeCQL(t *testing.T) {
	cases := [][]byte{
		{1, 1, 0, 16, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // TDS batch
		{4, 1, 0, 16, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // TDS response
		[]byte("GET / HTTP/1.1\r\n"),
		[]byte("POST /v1/ HTTP/1.1\r\n"),
		[]byte("*2\r\n$3\r\nGET\r\n"),                     // Redis RESP
		{0, 0, 0, 20, 0, 3, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0}, // Kafka
		{0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},           // DNS data
		[]byte("Q\x00\x00\x00\x0cSELECT 1\x00"),           // PG query
	}
	for i, b := range cases {
		if LooksLikeHeader(b) {
			t.Fatalf("protocol corpus %d accepted as CQL: %x", i, b)
		}
	}
}

func FuzzCQLParserNeverPanics(f *testing.F) {
	f.Add(frame(4, 0, 12, opcodeQuery, queryBody("INSERT INTO t (id) VALUES (1)")))
	f.Add([]byte{4, 0, 0, 8, 7, 0, 0, 0, 99})
	f.Add([]byte{4, 0, 0, 8, 7, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		q, ok := ParseFrame(b)
		if !ok {
			return
		}
		_, _, _ = Operation(q)
		if q.Response {
			return
		}
		rb := append([]byte(nil), b...)
		rb[0] |= 0x80
		_, _ = ParseFrame(rb)
	})
}
