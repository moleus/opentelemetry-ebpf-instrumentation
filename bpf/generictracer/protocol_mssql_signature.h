// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Pure byte-level checks. No BPF helpers, so the host test includes THIS header.
// CQL v3/v4/v5 requests use version 03/04/05; TDS response uses type 04.
// See Apache Cassandra native_protocol_v4.spec and Microsoft MS-TDS Packet Header.
static __always_inline bool looks_like_cql_request_header(const u8 *h) {
    if (h[0] != 0x03 && h[0] != 0x04 && h[0] != 0x05) {
        return false;
    }
    // Only known frame flags; compression and custom payload are allowed.
    if ((h[1] & 0xf0) != 0 || (h[2] & 0x80) != 0) {
        return false;
    }
    // Client request opcodes: STARTUP, OPTIONS, QUERY, PREPARE, EXECUTE,
    // REGISTER, BATCH, AUTH_RESPONSE. Never guess using SQL text or port.
    switch (h[4]) {
    case 0x01:
    case 0x05:
    case 0x07:
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0d:
    case 0x0f:
        break;
    default:
        return false;
    }
    const u32 body_len = ((u32)h[5] << 24) | ((u32)h[6] << 16) |
                         ((u32)h[7] << 8) | (u32)h[8];
    // The native protocol bounds a frame body to 256 MiB.
    return body_len <= (1U << 28);
}

static __always_inline bool valid_tds_packet_header(const u8 *h) {
    switch (h[0]) {
    case 0x01: // SQL batch
    case 0x03: // RPC
    case 0x04: // response
    case 0x10: // Login7
    case 0x12: // prelogin
        break;
    default:
        return false;
    }
    // MS-TDS Status: EOM=01, IGNORE=02, RESET=08, SKIPTRAN=10.
    // RESET/SKIPTRAN are valid only on client SQL batches and RPCs.
    // Unlike the old Go check, bit 0x10 is NOT reserved.
    const u8 status = h[1];
    if ((status & 0xe4) != 0 || h[7] != 0 ||
        ((status & 0x02) != 0 && (status & 0x01) == 0) ||
        (status & 0x18) == 0x18 ||
        ((status & 0x18) != 0 && h[0] != 0x01 && h[0] != 0x03)) {
        return false;
    }
    const u16 len = ((u16)h[2] << 8) | (u16)h[3];
    return len >= 8 && len <= 32767;
}
