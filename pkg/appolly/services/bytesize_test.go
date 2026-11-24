// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/caarlos0/env/v11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestByteSizeUnmarshalText(t *testing.T) {
	for in, want := range map[string]ByteSize{
		"":         0,
		"0":        0,
		"67108864": 64 << 20,
		"64MiB":    64 << 20,
		"64mib":    64 << 20,
		" 64 MiB ": 64 << 20,
		"64M":      64 << 20,
		"64MB":     64 << 20,
		"512k":     512 << 10,
		"2GiB":     2 << 30,
		"1.5GiB":   3 << 29,
		"100B":     100,
	} {
		var got ByteSize
		require.NoError(t, got.UnmarshalText([]byte(in)), in)
		assert.Equal(t, want, got, in)
	}
}

func TestByteSizeUnmarshalTextErrors(t *testing.T) {
	for _, in := range []string{"abc", "-1", "MiB", "64XiB", "1e400", "99999999999GiB", "NaN"} {
		var got ByteSize
		assert.Error(t, got.UnmarshalText([]byte(in)), in)
	}
}

// The limit comes from OTEL_EBPF_GO_MAX_PCLNTAB_SIZE: it must accept a unit.
func TestGoMaxPclntabSizeFromEnv(t *testing.T) {
	for in, want := range map[string]ByteSize{"64MiB": 64 << 20, "1048576": 1 << 20} {
		cfg := DiscoveryConfig{}
		require.NoError(t, env.ParseWithOptions(&cfg, env.Options{
			Environment: map[string]string{"OTEL_EBPF_GO_MAX_PCLNTAB_SIZE": in},
		}))
		assert.Equal(t, want, cfg.GoMaxPclntabSize, in)
	}
}
