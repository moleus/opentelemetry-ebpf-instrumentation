// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/cmd/obi-agent/internal/rules"
	"go.opentelemetry.io/obi/cmd/obi-agent/internal/sampler"
)

// rulesWatcher reads the rules file on every tick and gives a changed, valid file to the sampler.
// A missing or invalid file keeps the rules in use. Polling works with a Kubernetes ConfigMap volume,
// which replaces the file by a symlink swap that file watchers often miss.
type rulesWatcher struct {
	path     string
	interval time.Duration
	sampler  *sampler.Sampler
	log      *slog.Logger

	mu       sync.Mutex
	last     []byte
	loadedAt time.Time
	lastErr  error

	reloads *prometheus.CounterVec
	valid   prometheus.Gauge
}

type watcherStatus struct {
	Path     string    `json:"path"`
	LoadedAt time.Time `json:"loaded_at"`
	Error    string    `json:"error,omitempty"`
}

func newRulesWatcher(path string, interval time.Duration, s *sampler.Sampler, reg prometheus.Registerer) *rulesWatcher {
	w := &rulesWatcher{
		path: path, interval: interval, sampler: s, log: slog.With("component", "obi-agent.rules"),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "obi_agent", Name: "rules_reloads_total",
			Help: "Reads of a changed rules file, by result (ok, error).",
		}, []string{"result"}),
		valid: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "obi_agent", Name: "rules_file_valid",
			Help: "1 when the last read of the rules file was valid, 0 when the agent uses older rules.",
		}),
	}
	reg.MustRegister(w.reloads, w.valid)
	return w
}

func (w *rulesWatcher) run(ctx context.Context) {
	w.reload()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.reload()
		}
	}
}

func (w *rulesWatcher) reload() {
	data, err := os.ReadFile(w.path)
	if errors.Is(err, fs.ErrNotExist) {
		data, err = nil, nil
	}
	if err == nil && w.unchanged(data) {
		return
	}

	var set *rules.Set
	if err == nil {
		set, err = rules.Parse(data, time.Now())
	}
	w.record(data, err)
	if err != nil {
		w.log.Error("rules file rejected, the previous rules stay in use", "path", w.path, "error", err)
		return
	}
	w.sampler.SetRules(set)
	w.log.Info("rules loaded", "path", w.path, "default_ratio", set.Default.Ratio, "rules", len(set.Rules),
		"spans_per_second", set.Limits.SpansPerSecond)
}

func (w *rulesWatcher) unchanged(data []byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last != nil && bytes.Equal(w.last, data)
}

func (w *rulesWatcher) record(data []byte, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if data == nil {
		data = []byte{}
	}
	w.last = data
	w.lastErr = err
	if err != nil {
		w.reloads.WithLabelValues("error").Inc()
		w.valid.Set(0)
		return
	}
	w.loadedAt = time.Now()
	w.reloads.WithLabelValues("ok").Inc()
	w.valid.Set(1)
}

func (w *rulesWatcher) status() watcherStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := watcherStatus{Path: w.path, LoadedAt: w.loadedAt}
	if w.lastErr != nil {
		st.Error = w.lastErr.Error()
	}
	return st
}
