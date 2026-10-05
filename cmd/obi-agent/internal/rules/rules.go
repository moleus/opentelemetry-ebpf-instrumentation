// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules reads the trace selection rules of obi-agent: which spans are exported as traces,
// with which ratio, and until when.
package rules // import "go.opentelemetry.io/obi/cmd/obi-agent/internal/rules"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"
)

// DefaultMaxRuleDuration limits how long a rule can export more than the default ratio.
const DefaultMaxRuleDuration = 24 * time.Hour

// File is the YAML document of the rules file.
type File struct {
	// Default applies to the spans that match no rule.
	Default Action `yaml:"default"`
	// Rules are checked in order; the first active rule that matches the span decides.
	Rules  []Rule `yaml:"rules"`
	Limits Limits `yaml:"limits"`
}

// Action tells what to do with a span.
type Action struct {
	// Ratio of traces to export, 0..1. The decision depends only on the trace ID, so all the spans
	// of one trace get the same decision on every node (when they use the same ratio).
	Ratio float64 `yaml:"ratio"`
	// Errors exports every span with an error status, in addition to the ratio.
	Errors bool `yaml:"errors"`
}

// Rule selects spans and gives them an action.
type Rule struct {
	Name  string `yaml:"name"`
	Match Match  `yaml:"match"`
	// Action fields are inline: ratio, errors.
	Action `yaml:",inline"`
	// Until is the end of the rule. After it, the rule is ignored. A rule that exports more than the
	// default (a higher ratio, or errors that the default does not export) needs Until or SpansPerSecond.
	Until *time.Time `yaml:"until"`
	// SpansPerSecond limits the spans that this rule exports (0 = no own limit). A rule with a limit
	// can stay without Until: for rare events, such as crashes.
	SpansPerSecond float64 `yaml:"spans_per_second"`
}

// Match is a set of glob patterns (gobwas/glob syntax: *, ?, {a,b}). An empty pattern matches all.
type Match struct {
	Namespace string `yaml:"namespace"` // k8s.namespace.name
	Workload  string `yaml:"workload"`  // k8s.owner.name: deployment, statefulset, daemonset...
	Service   string `yaml:"service"`   // service.name
	Kind      string `yaml:"kind"`      // server, client, producer, consumer, internal
	Name      string `yaml:"name"`      // span name, for example "GET /api/*" or "SIG*"
}

// Limits protect the node and the backend.
type Limits struct {
	// SpansPerSecond limits the exported spans of this agent, after the ratio. 0 = no limit.
	SpansPerSecond float64 `yaml:"spans_per_second"`
	// Burst of the limiter; default = SpansPerSecond.
	Burst float64 `yaml:"burst"`
	// MaxRuleDuration limits Until of a rule that exports more than the default. Default 24h.
	MaxRuleDuration time.Duration `yaml:"max_rule_duration"`
}

// Set is a validated, compiled File.
type Set struct {
	Default Action
	Rules   []CompiledRule
	Limits  Limits
}

// CompiledRule is a Rule with compiled patterns.
type CompiledRule struct {
	Rule
	namespace, workload, service, kind, name glob.Glob
}

// Attrs are the span attributes that the rules match.
type Attrs struct {
	Namespace, Workload, Service, Kind, Name string
}

// Matches tells whether the rule selects the span attributes.
func (r *CompiledRule) Matches(a *Attrs) bool {
	return matches(r.namespace, a.Namespace) && matches(r.workload, a.Workload) &&
		matches(r.service, a.Service) && matches(r.kind, a.Kind) && matches(r.name, a.Name)
}

// ActiveAt tells whether the rule applies at the time.
func (r *CompiledRule) ActiveAt(now time.Time) bool {
	return r.Until == nil || now.Before(*r.Until)
}

func matches(g glob.Glob, value string) bool {
	return g == nil || g.Match(value)
}

// Parse reads and validates a rules document. now is used to check the Until limits.
func Parse(data []byte, now time.Time) (*Set, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// an empty document is valid: it means "the defaults" (export nothing)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing rules: %w", err)
	}
	return Compile(&f, now)
}

// Compile validates the file and compiles the patterns.
func Compile(f *File, now time.Time) (*Set, error) {
	var errs []error
	if err := checkRatio(f.Default.Ratio); err != nil {
		errs = append(errs, fmt.Errorf("default: %w", err))
	}
	maxDuration := f.Limits.MaxRuleDuration
	if maxDuration == 0 {
		maxDuration = DefaultMaxRuleDuration
	}
	if f.Limits.SpansPerSecond < 0 || f.Limits.Burst < 0 || maxDuration < 0 {
		errs = append(errs, errors.New("limits: values must not be negative"))
	}
	set := &Set{Default: f.Default, Limits: f.Limits}
	set.Limits.MaxRuleDuration = maxDuration
	if set.Limits.Burst == 0 {
		set.Limits.Burst = set.Limits.SpansPerSecond
	}
	for i := range f.Rules {
		r := f.Rules[i]
		id := fmt.Sprintf("rules[%d]", i)
		if r.Name != "" {
			id += " " + r.Name
		}
		if err := checkRatio(r.Ratio); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
		exportsMore := r.Ratio > f.Default.Ratio || (r.Errors && !f.Default.Errors)
		switch {
		case r.SpansPerSecond < 0:
			errs = append(errs, fmt.Errorf("%s: spans_per_second must not be negative", id))
		case exportsMore && r.Until == nil && r.SpansPerSecond == 0:
			errs = append(errs, fmt.Errorf("%s: exports more than the default, so it needs 'until' or 'spans_per_second'", id))
		case exportsMore && r.Until != nil && r.Until.Sub(now) > maxDuration:
			errs = append(errs, fmt.Errorf("%s: 'until' is more than %s from now", id, maxDuration))
		}
		cr := CompiledRule{Rule: r}
		var err error
		if cr.namespace, err = compile(r.Match.Namespace); err != nil {
			errs = append(errs, fmt.Errorf("%s: namespace: %w", id, err))
		}
		if cr.workload, err = compile(r.Match.Workload); err != nil {
			errs = append(errs, fmt.Errorf("%s: workload: %w", id, err))
		}
		if cr.service, err = compile(r.Match.Service); err != nil {
			errs = append(errs, fmt.Errorf("%s: service: %w", id, err))
		}
		if cr.kind, err = compile(strings.ToLower(r.Match.Kind)); err != nil {
			errs = append(errs, fmt.Errorf("%s: kind: %w", id, err))
		}
		if cr.name, err = compile(r.Match.Name); err != nil {
			errs = append(errs, fmt.Errorf("%s: name: %w", id, err))
		}
		set.Rules = append(set.Rules, cr)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return set, nil
}

func checkRatio(r float64) error {
	if r < 0 || r > 1 {
		return fmt.Errorf("ratio %v is not in 0..1", r)
	}
	return nil
}

func compile(pattern string) (glob.Glob, error) {
	if pattern == "" || pattern == "*" {
		return nil, nil
	}
	return glob.Compile(pattern)
}
