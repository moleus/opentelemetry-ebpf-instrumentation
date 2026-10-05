// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"sync"

	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/obi"
)

// TracerFactory creates tracers that OBI loads together with its common tracers (context propagation,
// log enricher...): once, when the first process is instrumented. The tracers send their spans to the
// same pipeline as the OBI tracers, so they get the Kubernetes decoration, filters and exporters.
type TracerFactory func(cfg *obi.Config, metrics imetrics.Reporter, pidFilter ebpfcommon.ServiceFilter) []ebpf.Tracer

var registeredTracers struct {
	mu        sync.Mutex
	factories []TracerFactory
}

// RegisterTracers adds tracers of an application that embeds OBI as a library. Call it before
// instrumenter.Run.
func RegisterTracers(factory TracerFactory) {
	registeredTracers.mu.Lock()
	defer registeredTracers.mu.Unlock()
	registeredTracers.factories = append(registeredTracers.factories, factory)
}

func newRegisteredTracers(cfg *obi.Config, metrics imetrics.Reporter, pidFilter ebpfcommon.ServiceFilter) []ebpf.Tracer {
	registeredTracers.mu.Lock()
	defer registeredTracers.mu.Unlock()
	var tracers []ebpf.Tracer
	for _, factory := range registeredTracers.factories {
		tracers = append(tracers, factory(cfg, metrics, pidFilter)...)
	}
	return tracers
}
