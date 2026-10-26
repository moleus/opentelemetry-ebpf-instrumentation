// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Host test includes the exact pure classifier used by eBPF, not a copy.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#include "../generictracer/protocol_mssql_signature.h"

static int failures;
static void check(const char *name, int got, int expected) {
    if (got != expected) {
        fprintf(stderr, "FAIL %s: got %d want %d\n", name, got, expected);
        failures++;
    } else {
        printf("ok %s\n",name);
    }
}

// Mirrors the BPF classifier's packet-walk around the tested header checks.
static int classified_mssql(const u8 *data, u32 len) {
    if (len < 8 || (len >= 9 && looks_like_cql_request_header(data))) {
        return 0;
    }
    u32 off = 0;
    int any = 0;
    for (u8 i=0; i<10; i++) {
        if (off+8 > len) break;
        if (!valid_tds_packet_header(data+off)) return 0;
        u16 n = (u16)((u16)data[off+2] << 8 | data[off+3]);
        if (n > len-off) return 0;
        any = 1;
        off += n;
    }
    return off==len && any;
}

static void test_cql_collision(void) {
    const char query[] = "INSERT INTO billing.orders_v2 (id) VALUES (?)";
    // Body = [int 4-byte query length] + text + consistency + flags.
    const u32 bodylen=4+sizeof(query)-1+3;
    const u32 total=9+bodylen;
    u8 bytes[256]={0};
    bytes[0]=0x04; // CQL v4 request AND TDS RESPONSE
    bytes[2]=(u8)(total>>8);bytes[3]=(u8)total; // CQL stream == TDS length
    bytes[4]=0x07; // CQL QUERY opcode
    bytes[8]=(u8)bodylen;
    bytes[12]=(u8)(sizeof(query)-1);
    memcpy(bytes+13,query,sizeof(query)-1);
    bytes[13+sizeof(query)-1+1]=1;
    check("old TDS header accepts CQL v4", valid_tds_packet_header(bytes), 1);
    check("CQL v4 signature", looks_like_cql_request_header(bytes), 1);
    check("CQL v4 is not classified as MSSQL", classified_mssql(bytes,total), 0);
    bytes[0]=0x03;
    check("CQL v3 is not classified as MSSQL",classified_mssql(bytes,total),0);
    bytes[0]=0x05;
    check("CQL v5 is not classified as MSSQL",classified_mssql(bytes,total),0);
    bytes[0]=0x04;bytes[1]=1; // Snappy/LZ4 compression flag
    check("compressed CQL signature",looks_like_cql_request_header(bytes),1);
    check("compressed CQL not MSSQL",classified_mssql(bytes,total),0);
}

static void test_real_tds(void) {
    u8 batch[22]={1,1,0,22,0,0,1,0,'S',0,'E',0,'L',0,'E',0,'C',0,'T',0,' ',0};
    check("TDS batch",classified_mssql(batch,sizeof(batch)),1);
    u8 response[12]={4,1,0,12,0,0,1,0,0,0,0,0};
    check("TDS response",classified_mssql(response,sizeof(response)),1);
    u8 rpc[8]={3,1,0,8,0,0,1,0};
    check("TDS RPC",classified_mssql(rpc,sizeof(rpc)),1);
    u8 login[8]={0x10,1,0,8,0,0,1,0};
    check("TDS login",classified_mssql(login,sizeof(login)),1);
    u8 prelogin[8]={0x12,1,0,8,0,0,1,0};
    check("TDS prelogin",classified_mssql(prelogin,sizeof(prelogin)),1);
    u8 mixed[16];memcpy(mixed,rpc,8);memcpy(mixed+8,rpc,8);
    check("coalesced TDS RPC",classified_mssql(mixed,sizeof(mixed)),1);
    u8 batch_reset_skiptran[8]={1,0x10,0,8,0,0,1,0};
    check("TDS batch RESETCONNECTIONSKIPTRAN",classified_mssql(batch_reset_skiptran,8),1);
    u8 rpc_reset[8]={3,0x08,0,8,0,0,1,0};
    check("TDS RPC RESETCONNECTION",classified_mssql(rpc_reset,8),1);
}

static void test_reject_other_protocols(void) {
    u8 dns[20]={4,1,0,8,1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0};
    check("DNS not MSSQL",classified_mssql(dns,sizeof(dns)),0);
    u8 badstatus[8]={1,0x20,0,8,0,0,1,0};
    check("reserved TDS status",classified_mssql(badstatus,8),0);
    u8 badresponse_status[8]={4,0x10,0,8,0,0,1,0};
    check("server response with client reset flag",classified_mssql(badresponse_status,8),0);
    u8 conflicting_reset[8]={1,0x18,0,8,0,0,1,0};
    check("conflicting TDS reset flags",classified_mssql(conflicting_reset,8),0);
    u8 badwindow[8]={1,1,0,8,0,0,1,1};
    check("nonzero TDS window",classified_mssql(badwindow,8),0);
    u8 unknown[8]={0x0d,1,0,8,0,0,1,0};
    check("unknown TDS type",classified_mssql(unknown,8),0);
    u8 truncated[8]={1,1,0,20,0,0,1,0};
    check("incomplete TDS",classified_mssql(truncated,8),0);
    u8 withjunk[16]={1,1,0,8,0,0,1,0,0xff,0,0,8,0,0,0,0};
    check("TDS followed by junk",classified_mssql(withjunk,16),0);
}
int main(void) {
    test_cql_collision();
    test_real_tds();
    test_reject_other_protocols();
    return failures ? EXIT_FAILURE:EXIT_SUCCESS;
}
