// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package fatalsignal

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

func TestEventToSpan(t *testing.T) {
	var event BpfFatalSignalEventT
	event.Timestamp = 42
	event.Pid.HostPid, event.Pid.UserPid, event.Pid.Ns = 1000, 7, 4026531836
	event.Sig = int32(unix.SIGSEGV)
	event.Code = 1
	copy(event.Comm[:], "worker")

	span := eventToSpan(&event)

	assert.Equal(t, request.EventTypeManualSpan, span.Type)
	assert.Equal(t, "SIGSEGV", span.TraceName())
	assert.Equal(t, trace.SpanKindInternal, span.SpanKind)
	assert.Equal(t, request.StatusCodeError, request.SpanStatusCode(&span))
	assert.Equal(t, app.PID(1000), span.Pid.HostPID)
	assert.Equal(t, int64(42), span.Start)
	assert.True(t, span.TraceID.IsValid())

	var attrs []tracesgen.SpanAttr
	require.NoError(t, json.Unmarshal([]byte(span.Statement), &attrs))
	keys := map[string]string{}
	for _, a := range attrs {
		keys[unix.ByteSliceToString(a.Key[:])] = unix.ByteSliceToString(a.Value[:a.ValLength])
	}
	assert.Equal(t, "SIGSEGV", keys["signal.name"])
	assert.Equal(t, "worker", keys["process.command"])
	assert.Contains(t, keys, "signal.number")
}
