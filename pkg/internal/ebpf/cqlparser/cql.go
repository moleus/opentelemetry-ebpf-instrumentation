// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package cqlparser identifies uncompressed Cassandra native protocol v3/v4
// messages. It never infers a CQL query from an arbitrary binary SQL substring.
package cqlparser

import (
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

const (
	headerSize    = 9
	maxFrameBody  = 1 << 28 // Native protocol v4 limit: 256 MiB
	opcodeError   = 0x00
	opcodeQuery   = 0x07
	opcodeResult  = 0x08
	opcodePrepare = 0x09
	opcodeExecute = 0x0a
	opcodeBatch   = 0x0d
)

type Frame struct {
	Version  byte
	Flags    byte
	Stream   uint16
	Opcode   byte
	Body     []byte
	Response bool
}

func validOpcode(op byte, response bool) bool {
	if response {
		switch op {
		case 0x00, 0x02, 0x03, 0x06, 0x08, 0x0c, 0x0e, 0x10:
			return true
		}
	} else {
		switch op {
		case 0x01, 0x05, 0x07, 0x09, 0x0a, 0x0b, 0x0d, 0x0f:
			return true
		}
	}
	return false
}

// LooksLikeHeader is deliberately usable for truncated frames. It blocks the
// MSSQL fallback when CQL's version byte (0x04) looks like TDS RESPONSE.
// It does not claim that an entire query has been captured.
func LooksLikeHeader(b []byte) bool {
	if len(b) < headerSize {
		return false
	}
	version := b[0] & 0x7f
	if version < 3 || version > 5 || b[1]&0xf0 != 0 {
		return false
	}
	response := b[0]&0x80 != 0
	if !validOpcode(b[4], response) {
		return false
	}
	stream := binary.BigEndian.Uint16(b[2:4])
	if stream&0x8000 != 0 && !(response && b[4] == 0x0c && stream == 0xffff) {
		return false
	}
	return binary.BigEndian.Uint32(b[5:9]) <= maxFrameBody
}

// ParseFrame requires exactly one complete frame. Multiple coalesced frames
// cannot be timed safely by OBI's connection-level TCP tracker.
func ParseFrame(b []byte) (Frame, bool) {
	if !LooksLikeHeader(b) {
		return Frame{}, false
	}
	size := uint64(binary.BigEndian.Uint32(b[5:9])) + headerSize
	if size != uint64(len(b)) {
		return Frame{}, false
	}
	return Frame{
		Version:  b[0] & 0x7f,
		Flags:    b[1],
		Stream:   binary.BigEndian.Uint16(b[2:4]),
		Opcode:   b[4],
		Body:     b[headerSize:],
		Response: b[0]&0x80 != 0,
	}, true
}

// PairedResponse verifies protocol, stream identifier, and successful capture.
// A CQL event must not be timed against a different in-flight CQL request.
func PairedResponse(req, resp Frame) bool {
	if req.Response || !resp.Response || req.Version != resp.Version || req.Stream != resp.Stream {
		return false
	}
	if req.Version != 3 && req.Version != 4 {
		return false // v5 has different framing/negotiation cases; not supported yet
	}
	if resp.Opcode != opcodeResult && resp.Opcode != opcodeError {
		return false
	}
	// Compressed, traced, custom-payload and warning-prefixed responses need
	// additional decoding. Do not interpret their first bytes as a result code.
	if resp.Flags&0x0f != 0 || len(resp.Body) < 4 {
		return false
	}
	if resp.Opcode == opcodeResult {
		kind := binary.BigEndian.Uint32(resp.Body[:4])
		return kind >= 1 && kind <= 5 // VOID, ROWS, SET_KEYSPACE, PREPARED, SCHEMA_CHANGE
	}
	if len(resp.Body) < 6 { // ERROR: [int code] [string message]
		return false
	}
	n := int(binary.BigEndian.Uint16(resp.Body[4:6]))
	return len(resp.Body) >= 6+n
}

func SafeText(q []byte) bool {
	if !utf8.Valid(q) || len(q) == 0 {
		return false
	}
	for _, r := range string(q) {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

// Operation returns only information actually present in the wire protocol.
// EXECUTE uses a prepared statement ID, not a query string; BATCH can contain
// multiple queries, so neither is assigned a guessed db.query.text.
func Operation(f Frame) (operation, query string, ok bool) {
	if f.Response || (f.Version != 3 && f.Version != 4) || f.Flags&0x05 != 0 {
		return "", "", false // compressed or custom payload not decoded
	}
	switch f.Opcode {
	case opcodeQuery, opcodePrepare:
		if len(f.Body) < 4 {
			return "", "", false
		}
		n := uint64(binary.BigEndian.Uint32(f.Body[:4]))
		if n > uint64(len(f.Body)-4) || n == 0 {
			return "", "", false
		}
		if f.Opcode == opcodeQuery && uint64(len(f.Body)) < 4+n+3 { // consistency + flags
			return "", "", false
		}
		if f.Opcode == opcodePrepare && uint64(len(f.Body)) != 4+n {
			return "", "", false
		}
		raw := f.Body[4 : 4+int(n)]
		if !SafeText(raw) {
			return "", "", false
		}
		return map[byte]string{opcodeQuery: "QUERY", opcodePrepare: "PREPARE"}[f.Opcode], string(raw), true
	case opcodeExecute:
		if len(f.Body) < 2 {
			return "", "", false
		}
		n := int(binary.BigEndian.Uint16(f.Body[:2]))
		if n == 0 || len(f.Body) < 2+n+3 {
			return "", "", false
		}
		return "EXECUTE", "", true
	case opcodeBatch:
		if len(f.Body) < 5 || f.Body[0] > 2 || binary.BigEndian.Uint16(f.Body[1:3]) == 0 {
			return "", "", false
		}
		return "BATCH", "", true
	default:
		return "", "", false
	}
}

// QueryOperation returns a parsed verb when the query text contains one.
// Do not blindly treat text following the CQL header as an SQL statement.
func QueryOperation(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return ""
	}
	for _, op := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "TRUNCATE", "USE", "BEGIN"} {
		if len(q) >= len(op) && strings.EqualFold(q[:len(op)], op) &&
			(len(q) == len(op) || q[len(op)] == ' ' || q[len(op)] == '\t' || q[len(op)] == '\n') {
			return op
		}
	}
	return ""
}
