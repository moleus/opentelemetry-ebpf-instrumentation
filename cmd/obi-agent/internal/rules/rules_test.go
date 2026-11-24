// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func TestParse(t *testing.T) {
	set, err := Parse([]byte(`
default: {ratio: 0.01}
rules:
  - name: gate-debug
    match: {namespace: search, workload: "gate-*", kind: server}
    ratio: 1
    until: 2026-10-05T14:00:00Z
  - name: errors
    errors: true
    until: 2026-10-05T13:00:00Z
  - name: silence-health
    match: {service: "{healthcheck,probe}"}
    ratio: 0
limits: {spans_per_second: 500}
`), now)
	require.NoError(t, err)

	assert.InDelta(t, 0.01, set.Default.Ratio, 0)
	require.Len(t, set.Rules, 3)
	assert.Equal(t, 500.0, set.Limits.Burst, "burst defaults to the rate")
	assert.Equal(t, DefaultMaxRuleDuration, set.Limits.MaxRuleDuration)

	gate := &set.Rules[0]
	assert.True(t, gate.Matches(&Attrs{Namespace: "search", Workload: "gate-api", Kind: "server"}))
	assert.False(t, gate.Matches(&Attrs{Namespace: "search", Workload: "gate-api", Kind: "client"}))
	assert.False(t, gate.Matches(&Attrs{Namespace: "other", Workload: "gate-api", Kind: "server"}))
	assert.True(t, gate.ActiveAt(now))
	assert.False(t, gate.ActiveAt(time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)))

	assert.True(t, set.Rules[1].Matches(&Attrs{}), "an empty match selects every span")
	assert.True(t, set.Rules[2].Matches(&Attrs{Service: "probe"}))
	assert.True(t, set.Rules[2].ActiveAt(now.Add(1000*time.Hour)), "a rule without until never expires")
}

func TestParse_EmptyDocumentExportsNothing(t *testing.T) {
	set, err := Parse(nil, now)
	require.NoError(t, err)
	assert.Zero(t, set.Default.Ratio)
	assert.Empty(t, set.Rules)
}

func TestParse_Errors(t *testing.T) {
	tests := map[string]string{
		"unknown field":         "default: {ratoi: 1}",
		"ratio above 1":         "default: {ratio: 2}",
		"negative limit":        "limits: {spans_per_second: -1}",
		"more without until":    "rules: [{ratio: 1}]",
		"errors without until":  "rules: [{errors: true}]",
		"until too far":         "rules: [{ratio: 1, until: 2026-10-07T12:00:00Z}]",
		"until above the limit": "limits: {max_rule_duration: 1h}\nrules: [{ratio: 1, until: 2026-10-05T14:00:00Z}]",
		"bad glob":              "rules: [{match: {namespace: \"[\"}}]",
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(doc), now)
			assert.Error(t, err)
		})
	}
}

func TestParse_OwnLimitNeedsNoUntil(t *testing.T) {
	set, err := Parse([]byte(`rules: [{name: crashes, match: {name: "SIG*", kind: internal}, ratio: 1, spans_per_second: 1}]`), now)
	require.NoError(t, err)
	assert.True(t, set.Rules[0].Matches(&Attrs{Name: "SIGSEGV", Kind: "internal"}))
	assert.False(t, set.Rules[0].Matches(&Attrs{Name: "GET /", Kind: "internal"}))

	_, err = Parse([]byte("rules: [{ratio: 1, spans_per_second: -1}]"), now)
	assert.Error(t, err)
}

func TestParse_LessThanDefaultNeedsNoUntil(t *testing.T) {
	_, err := Parse([]byte("default: {ratio: 0.5, errors: true}\nrules: [{ratio: 0.1, errors: true}]"), now)
	assert.NoError(t, err)
}

// A malformed rules file must never enable unlimited export.
func TestCompileRejectsNonFiniteValues(t *testing.T) {
	bad := []float64{math.NaN(), math.Inf(1), math.Inf(-1)}
	for _, value := range bad {
		for _, change := range []struct {
			name  string
			apply func(*File)
		}{
			{"default ratio", func(f *File) { f.Default.Ratio = value }},
			{"rule ratio", func(f *File) { f.Rules = []Rule{{Action: Action{Ratio: value}}} }},
			{"global rate", func(f *File) { f.Limits.SpansPerSecond = value }},
			{"global burst", func(f *File) { f.Limits.Burst = value }},
			{"rule rate", func(f *File) { f.Rules = []Rule{{SpansPerSecond: value}} }},
		} {
			t.Run(change.name+"/"+strconv.FormatFloat(value, 'g', -1, 64), func(t *testing.T) {
				f := &File{}
				change.apply(f)
				_, err := Compile(f, now)
				assert.Error(t, err)
			})
		}
	}
}

func TestParseRejectsAdditionalYAMLDocuments(t *testing.T) {
	for _, input := range []string{
		"default: {ratio: 0.01}\n---\ndefault: {ratio: 1}\n",
		"default: {ratio: 0.01}\n---\n",
	} {
		_, err := Parse([]byte(input), now)
		assert.Error(t, err)
	}
}

func TestParseRejectsNonFiniteYAMLValues(t *testing.T) {
	for _, input := range []string{
		"default: {ratio: .nan}",
		"limits: {spans_per_second: .inf}",
		"limits: {burst: -.inf}",
		"rules: [{spans_per_second: .nan}]",
	} {
		_, err := Parse([]byte(input), now)
		assert.Error(t, err)
	}
}
