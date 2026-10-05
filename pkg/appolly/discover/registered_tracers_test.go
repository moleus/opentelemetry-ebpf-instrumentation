// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/obi"
)

// fakeTracer satisfies ebpf.Tracer; the test only checks that the instance reaches the tracer group.
type fakeTracer struct {
	ebpf.Tracer
}

func TestRegisterTracers(t *testing.T) {
	saved := registeredTracers.factories
	t.Cleanup(func() { registeredTracers.factories = saved })

	cfg := obi.DefaultConfig
	custom := &fakeTracer{}
	var gotCfg *obi.Config
	RegisterTracers(func(c *obi.Config, _ imetrics.Reporter, _ ebpfcommon.ServiceFilter) []ebpf.Tracer {
		gotCfg = c
		return []ebpf.Tracer{custom}
	})

	tracers := newCommonTracersGroup(&cfg, imetrics.NoopReporter{}, nil)

	require.NotEmpty(t, tracers)
	assert.Same(t, custom, tracers[len(tracers)-1])
	assert.Same(t, &cfg, gotCfg)
}
