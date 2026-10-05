// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestTraceDeciderGate(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	outCh := output.Subscribe()

	var asked []string
	decider := func(s *request.Span) bool {
		asked = append(asked, s.Path)
		return s.Path != "/drop"
	}
	runFn, err := TraceDeciderGate(decider, input, output)(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go runFn(ctx)

	ignored := request.Span{Path: "/already-ignored"}
	request.SetIgnoreTraces(&ignored)
	input.Send([]request.Span{{Path: "/keep"}, {Path: "/drop"}, ignored})

	out := testutil.ReadChannel(t, outCh, gateTestTimeout)
	require.Len(t, out, 3)
	assert.False(t, request.IgnoreTraces(&out[0]))
	assert.True(t, request.IgnoreTraces(&out[1]))
	assert.True(t, request.IgnoreTraces(&out[2]))
	// a span that is already ignored for traces is not passed to the decider
	assert.Equal(t, []string{"/keep", "/drop"}, asked)
	// the decider changes only the traces flag
	assert.False(t, request.IgnoreMetrics(&out[1]))
}

func TestTraceDeciderGate_NilDeciderBypasses(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	outCh := output.Subscribe()

	runFn, err := TraceDeciderGate(nil, input, output)(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go runFn(ctx)

	input.Send([]request.Span{{Path: "/a"}})
	out := testutil.ReadChannel(t, outCh, gateTestTimeout)
	require.Len(t, out, 1)
	assert.False(t, request.IgnoreTraces(&out[0]))
}
