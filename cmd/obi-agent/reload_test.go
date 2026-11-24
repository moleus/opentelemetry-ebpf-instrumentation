// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/cmd/obi-agent/internal/rules"
	"go.opentelemetry.io/obi/cmd/obi-agent/internal/sampler"
)

func newTestWatcher(t *testing.T, path string) (*rulesWatcher, *sampler.Sampler) {
	t.Helper()
	reg := prometheus.NewRegistry()
	smp := sampler.New(&rules.Set{}, reg, time.Now)
	return newRulesWatcher(path, time.Hour, smp, reg), smp
}

func TestReload_KeepsPreviousRulesOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	w, smp := newTestWatcher(t, path)

	require.NoError(t, os.WriteFile(path, []byte("default: {ratio: 0.5}"), 0o600))
	w.reload()
	assert.InDelta(t, 0.5, smp.Rules().Default.Ratio, 0)
	assert.Equal(t, 1.0, testutil.ToFloat64(w.valid))

	require.NoError(t, os.WriteFile(path, []byte("default: {ratio: 5}"), 0o600))
	w.reload()
	assert.InDelta(t, 0.5, smp.Rules().Default.Ratio, 0, "an invalid file keeps the rules in use")
	assert.Equal(t, 0.0, testutil.ToFloat64(w.valid))
	assert.NotEmpty(t, w.status().Error)

	w.reload()
	assert.Equal(t, 1.0, testutil.ToFloat64(w.reloads.WithLabelValues("error")), "an unchanged file is not parsed again")
}

func TestReload_MissingFileExportsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	w, smp := newTestWatcher(t, path)

	require.NoError(t, os.WriteFile(path, []byte("default: {ratio: 1}"), 0o600))
	w.reload()
	require.NoError(t, os.Remove(path))
	w.reload()
	assert.Zero(t, smp.Rules().Default.Ratio)
}

// A ConfigMap volume swaps a "..data" symlink to a new directory; the file path stays the same.
func TestReload_ConfigMapSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	writeVersion := func(name, content string) {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, name), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name, "rules.yaml"), []byte(content), 0o600))
		tmp := filepath.Join(dir, "..data_tmp")
		require.NoError(t, os.Symlink(name, tmp))
		require.NoError(t, os.Rename(tmp, filepath.Join(dir, "..data")))
	}
	writeVersion("v1", "default: {ratio: 0.1}")
	path := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.Symlink("..data/rules.yaml", path))

	w, smp := newTestWatcher(t, path)
	w.reload()
	assert.InDelta(t, 0.1, smp.Rules().Default.Ratio, 0)

	writeVersion("v2", "default: {ratio: 0.2}")
	w.reload()
	assert.InDelta(t, 0.2, smp.Rules().Default.Ratio, 0)
}
