// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly // import "go.opentelemetry.io/obi/pkg/appolly"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// TraceDeciderGate asks the decider for every span that is still exported as a trace. A span that the
// decider refuses is marked with request.SetIgnoreTraces: the traces exporters skip it, while the
// metrics exporters still count it. Without a decider, the node forwards the spans unchanged.
func TraceDeciderGate(
	decider global.TraceDecider,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if decider == nil {
			return swarm.Bypass(input, output)
		}
		in := input.Subscribe(msg.SubscriberName("appolly.TraceDeciderGate"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(spans []request.Span) {
				for i := range spans {
					if request.IgnoreTraces(&spans[i]) {
						continue
					}
					if !decider(&spans[i]) {
						request.SetIgnoreTraces(&spans[i])
					}
				}
				output.SendCtx(ctx, spans)
			})
		}, nil
	}
}
