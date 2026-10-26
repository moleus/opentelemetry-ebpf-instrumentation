// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Host test for the real bpf/common/sql.h: a SQL keyword counts only as a
// whole token, so host names and URL paths such as "insert-hot" are not SQL.
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// The shared bpfcore stub of bpf_probe_read copies nothing; use a real copy.
static long host_probe_read(void *dst, u32 size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}
#define bpf_probe_read(dst, size, src) host_probe_read(dst, size, src)

#include <common/sql.h>

static int failures;

// The BPF code reads k_max_sql_op_len bytes, so pad the input with zeros.
static int find(const char *s, size_t n) {
    char buf[64] = {0};
    memcpy(buf, s, n);
    return find_sql_query(buf);
}

#define CHECK(name, str, want)                                                                     \
    do {                                                                                           \
        int got = find(str, sizeof(str) - 1);                                                      \
        if (got != (want)) {                                                                       \
            fprintf(stderr, "FAIL %s: got %d want %d\n", name, got, (int)(want));                  \
            failures++;                                                                            \
        } else {                                                                                   \
            printf("ok %s\n", name);                                                               \
        }                                                                                          \
    } while (0)

int main(void) {
    CHECK("select space", "SELECT 1", 0);
    CHECK("select star", "SELECT* FROM t", 0);
    CHECK("select newline", "select\n1", 0);
    CHECK("insert paren", "INSERT(a)", 0);
    CHECK("keyword after flag bytes", "\x03\x00INSERT INTO t", 2);
    CHECK("with comment", "WITH/* x */ a AS (SELECT 1)", 0);
    CHECK("insert-hot host", "\x00insert-hot-x", -1);
    CHECK("alter-models host", "\x00alter-models", -1);
    CHECK("insert path segment", "/insert/0/prometheus", -1);
    CHECK("keyword at end of data", "UPDATE", 0);
    CHECK("keyword followed by a letter", "UPDATES x", -1);
    CHECK("keyword followed by a dot", "\x00insert.hot", -1);
    if (failures) {
        return 1;
    }
    printf("All sql keyword boundary tests passed\n");
    return 0;
}
