// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package sampler decides which spans obi-agent exports as traces, from rules that can change while
// the agent runs.
package sampler // import "go.opentelemetry.io/obi/cmd/obi-agent/internal/sampler"

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/cmd/obi-agent/internal/rules"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const (
	defaultRuleName  = "default"
	reasonRatio      = "ratio"
	reasonRateLimit  = "rate_limit"
	spanKindPrefix   = "SPAN_KIND_"
	metricsNamespace = "obi_agent"
)

// Sampler is safe for one caller of Decide and any number of callers of SetRules and Rules.
type Sampler struct {
	state   atomic.Pointer[state]
	now     func() time.Time
	limiter limiter
	metrics metrics
}

type state struct {
	set            *rules.Set
	defaultSampler sdktrace.Sampler
	ruleSamplers   []sdktrace.Sampler
	// ruleLimiters are used by the Decide goroutine only; a rules change starts them again
	ruleLimiters []limiter
}

type metrics struct {
	exported *prometheus.CounterVec
	dropped  *prometheus.CounterVec
}

// New returns a Sampler with the rules. reg receives the metrics of the decisions.
func New(set *rules.Set, reg prometheus.Registerer, now func() time.Time) *Sampler {
	s := &Sampler{now: now}
	s.metrics = metrics{
		exported: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Name: "spans_exported_total",
			Help: "Spans exported as traces, by the rule that selected them.",
		}, []string{"rule"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Name: "spans_dropped_total",
			Help: "Spans not exported as traces, by the rule and the reason (ratio, rate_limit).",
		}, []string{"rule", "reason"}),
	}
	reg.MustRegister(s.metrics.exported, s.metrics.dropped)
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: metricsNamespace, Name: "rules_active",
		Help: "Rules that apply now (not expired).",
	}, func() float64 { return float64(s.activeRules()) }))
	s.SetRules(set)
	return s
}

// SetRules replaces the rules. The next Decide call uses them.
func (s *Sampler) SetRules(set *rules.Set) {
	st := &state{set: set, defaultSampler: ratioSampler(set.Default.Ratio)}
	for i := range set.Rules {
		st.ruleSamplers = append(st.ruleSamplers, ratioSampler(set.Rules[i].Ratio))
	}
	st.ruleLimiters = make([]limiter, len(set.Rules))
	s.state.Store(st)
}

// Rules returns the rules in use.
func (s *Sampler) Rules() *rules.Set {
	return s.state.Load().set
}

// Decide returns true when the span must be exported as a trace.
func (s *Sampler) Decide(span *request.Span) bool {
	st := s.state.Load()
	now := s.now()

	index, name, action, ratio := s.selectAction(st, span, now)
	if !keepByAction(span, action, ratio) {
		s.metrics.dropped.WithLabelValues(name, reasonRatio).Inc()
		return false
	}
	if index >= 0 && !st.ruleLimiters[index].allow(now, st.set.Rules[index].SpansPerSecond, st.set.Rules[index].SpansPerSecond) {
		s.metrics.dropped.WithLabelValues(name, reasonRateLimit).Inc()
		return false
	}
	if !s.limiter.allow(now, st.set.Limits.SpansPerSecond, st.set.Limits.Burst) {
		s.metrics.dropped.WithLabelValues(name, reasonRateLimit).Inc()
		return false
	}
	s.metrics.exported.WithLabelValues(name).Inc()
	return true
}

// selectAction returns the index of the rule that decides (-1 for the default), its name and action.
func (s *Sampler) selectAction(st *state, span *request.Span, now time.Time) (int, string, rules.Action, sdktrace.Sampler) {
	attrs := spanAttrs(span)
	for i := range st.set.Rules {
		r := &st.set.Rules[i]
		if r.ActiveAt(now) && r.Matches(&attrs) {
			return i, ruleName(r, i), r.Action, st.ruleSamplers[i]
		}
	}
	return -1, defaultRuleName, st.set.Default, st.defaultSampler
}

func (s *Sampler) activeRules() int {
	now := s.now()
	active := 0
	for i := range s.Rules().Rules {
		if s.Rules().Rules[i].ActiveAt(now) {
			active++
		}
	}
	return active
}

func keepByAction(span *request.Span, action rules.Action, ratio sdktrace.Sampler) bool {
	if action.Errors && request.SpanStatusCode(span) == request.StatusCodeError {
		return true
	}
	result := ratio.ShouldSample(sdktrace.SamplingParameters{TraceID: span.TraceID})
	return result.Decision == sdktrace.RecordAndSample
}

// ratioSampler uses the OpenTelemetry TraceIDRatioBased algorithm, so the decision for a trace ID is
// the same in every agent and in any OpenTelemetry SDK with the same ratio.
func ratioSampler(ratio float64) sdktrace.Sampler {
	return sdktrace.TraceIDRatioBased(ratio)
}

func ruleName(r *rules.CompiledRule, index int) string {
	if r.Name != "" {
		return r.Name
	}
	return "rules[" + strconv.Itoa(index) + "]"
}

func spanAttrs(span *request.Span) rules.Attrs {
	md := span.Service.Metadata
	return rules.Attrs{
		Namespace: md[attr.K8sNamespaceName],
		Workload:  md[attr.K8sOwnerName],
		Service:   span.Service.UID.Name,
		Kind:      strings.ToLower(strings.TrimPrefix(span.ServiceGraphKind(), spanKindPrefix)),
		Name:      span.TraceName(),
	}
}
