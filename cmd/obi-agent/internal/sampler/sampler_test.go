// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sampler

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/cmd/obi-agent/internal/rules"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newSampler(t *testing.T, doc string, c *clock) *Sampler {
	t.Helper()
	set, err := rules.Parse([]byte(doc), c.t)
	require.NoError(t, err)
	return New(set, prometheus.NewRegistry(), c.now)
}

// traceID returns a trace ID whose ratio position is p (0..1): TraceIDRatioBased keeps it when p < ratio.
func traceID(p float64) trace.TraceID {
	var id trace.TraceID
	binary.BigEndian.PutUint64(id[8:], uint64(p*(1<<63))<<1)
	return id
}

func serverSpan(namespace, workload string, p float64) *request.Span {
	return &request.Span{
		Type:    request.EventTypeHTTP,
		Status:  200,
		TraceID: traceID(p),
		Service: svc.Attrs{
			UID:      svc.UID{Name: workload},
			Metadata: map[attr.Name]string{attr.K8sNamespaceName: namespace, attr.K8sOwnerName: workload},
		},
	}
}

func TestDecide_Ratio(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	s := newSampler(t, "default: {ratio: 0.1}", c)

	assert.True(t, s.Decide(serverSpan("ns", "app", 0.05)))
	assert.False(t, s.Decide(serverSpan("ns", "app", 0.5)))
}

func TestDecide_RuleUntilExpires(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	s := newSampler(t, `
default: {ratio: 0}
rules:
  - {name: debug, match: {namespace: search, kind: server}, ratio: 1, until: 2026-10-05T12:30:00Z}
`, c)

	assert.True(t, s.Decide(serverSpan("search", "gate", 0.9)))
	assert.False(t, s.Decide(serverSpan("other", "gate", 0.9)), "the rule matches only its namespace")

	c.t = c.t.Add(time.Hour)
	assert.False(t, s.Decide(serverSpan("search", "gate", 0.9)), "after until the default applies")
	assert.Equal(t, 1.0, testutil.ToFloat64(s.metrics.exported.WithLabelValues("debug")))
}

func TestDecide_Errors(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	s := newSampler(t, "default: {ratio: 0, errors: true}", c)

	failed := serverSpan("ns", "app", 0.9)
	failed.Status = 503
	assert.True(t, s.Decide(failed))
	assert.False(t, s.Decide(serverSpan("ns", "app", 0.9)))
}

func TestDecide_RateLimit(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	s := newSampler(t, "default: {ratio: 1}\nlimits: {spans_per_second: 2}", c)

	exported := 0
	for range 10 {
		if s.Decide(serverSpan("ns", "app", 0.5)) {
			exported++
		}
	}
	assert.Equal(t, 2, exported, "the burst is the rate")

	c.t = c.t.Add(time.Second)
	assert.True(t, s.Decide(serverSpan("ns", "app", 0.5)), "tokens come back with time")
	assert.Equal(t, 8.0, testutil.ToFloat64(s.metrics.dropped.WithLabelValues("default", reasonRateLimit)))
}

func TestSetRules_AppliesToTheNextSpan(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	s := newSampler(t, "default: {ratio: 0}", c)
	require.False(t, s.Decide(serverSpan("ns", "app", 0.5)))

	set, err := rules.Parse([]byte("default: {ratio: 1}"), c.t)
	require.NoError(t, err)
	s.SetRules(set)
	assert.True(t, s.Decide(serverSpan("ns", "app", 0.5)))
}

func TestSpanAttrs_Kind(t *testing.T) {
	client := &request.Span{Type: request.EventTypeHTTPClient}
	assert.Equal(t, "client", spanAttrs(client).Kind)
	assert.Equal(t, "server", spanAttrs(serverSpan("", "", 0)).Kind)
}
