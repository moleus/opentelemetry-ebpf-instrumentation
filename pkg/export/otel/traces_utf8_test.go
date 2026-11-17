// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

// truncatedRune is the first two bytes of a three-byte character: what a
// fixed-size capture buffer leaves when it ends inside a character.
const truncatedRune = "\xe2\x82"

type captureTraceClient struct {
	uploaded [][]*tracepb.ResourceSpans
}

func (*captureTraceClient) Start(context.Context) error { return nil }
func (*captureTraceClient) Stop(context.Context) error  { return nil }

func (c *captureTraceClient) UploadTraces(_ context.Context, rs []*tracepb.ResourceSpans) error {
	c.uploaded = append(c.uploaded, rs)
	return nil
}

func utf8TestSpan(typ request.EventType) request.Span {
	now := time.Now()
	return request.Span{
		Type:         typ,
		RequestStart: now.UnixNano(),
		Start:        now.UnixNano(),
		End:          now.Add(time.Millisecond).UnixNano(),
	}
}

func TestTraceExportKeepsSpansWithInvalidUTF8(t *testing.T) {
	// The body of a bulk request cut by the capture buffer.
	bulkBody := strings.Repeat(`{"index":{}}`+"\n"+`{"f":"€"}`+"\n", 3) + `{"f":"` + truncatedRune

	cases := map[string]request.Span{
		"elasticsearch db.query.text": func() request.Span {
			s := utf8TestSpan(request.EventTypeHTTPClient)
			s.SubType = request.HTTPSubtypeElasticsearch
			s.Method = "POST"
			s.Path = "/_bulk"
			s.Elasticsearch = &request.Elasticsearch{
				DBOperationName: "bulk",
				DBQueryText:     bulkBody,
				DBSystemName:    "opensearch",
			}
			return s
		}(),
		"sql db.query.text": func() request.Span {
			s := utf8TestSpan(request.EventTypeSQLClient)
			s.Method = "INSERT"
			s.Statement = "INSERT INTO t VALUES ('" + truncatedRune
			return s
		}(),
		"redis db.query.text": func() request.Span {
			s := utf8TestSpan(request.EventTypeRedisClient)
			s.Method = "SET"
			s.Path = "SET k " + truncatedRune
			return s
		}(),
		"kafka topic and client id": func() request.Span {
			s := utf8TestSpan(request.EventTypeKafkaClient)
			s.Method = "publish"
			s.Path = "topic" + truncatedRune
			s.Statement = "client" + truncatedRune
			return s
		}(),
		"http client url.path": func() request.Span {
			s := utf8TestSpan(request.EventTypeHTTPClient)
			s.Method = "GET"
			s.Path = "/" + truncatedRune
			s.Status = 200
			return s
		}(),
		"http server url.path and user agent": func() request.Span {
			s := utf8TestSpan(request.EventTypeHTTP)
			s.Method = "GET"
			s.Path = "/p" + truncatedRune
			s.UserAgent = "agent" + truncatedRune
			s.Status = 200
			return s
		}(),
	}

	selected, err := tracesgen.UserSelectedAttributes(&attributes.SelectorConfig{
		SelectionCfg: attributes.Selection{
			attributes.Traces.Section: attributes.InclusionLists{
				Include: []string{string(attr.DBQueryText), "*"},
			},
		},
	})
	require.NoError(t, err)

	for name, span := range cases {
		t.Run(name, func(t *testing.T) {
			attrs := tracesgen.TraceAttributesSelector(&span, selected)
			traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, nil, hostID,
				groupFromSpanAndAttributes(&span, attrs), reporterName)
			require.Equal(t, 1, traces.SpanCount())

			// The real OTLP path: marshal, decode into the wire types, upload.
			client := &captureTraceClient{}
			exp := newOTLPTracesExporter(otelcfg.TracesConfig{}, nil, client)
			require.NoError(t, exp.ConsumeTraces(context.Background(), traces))
			require.Len(t, client.uploaded, 1)

			assertValidUTF8(t, traces)
		})
	}

	t.Run("sanitized value keeps the valid prefix", func(t *testing.T) {
		span := cases["elasticsearch db.query.text"]
		attrs := tracesgen.TraceAttributesSelector(&span, selected)
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, nil, hostID,
			groupFromSpanAndAttributes(&span, attrs), reporterName)
		got, ok := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().Get(string(attr.DBQueryText.OTEL()))
		require.True(t, ok)
		assert.Equal(t, strings.TrimSuffix(bulkBody, truncatedRune), got.Str())
	})
}

func TestTraceExportSanitizesSliceAndResourceAttributes(t *testing.T) {
	span := utf8TestSpan(request.EventTypeHTTP)
	span.Method = "GET"
	span.Path = "/ok"
	span.Status = 200
	attrs := []attribute.KeyValue{
		attribute.StringSlice("http.request.header.x-test", []string{"first" + truncatedRune, "second"}),
	}
	extraResource := attribute.String("test.resource", "resource"+truncatedRune)

	traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, nil, hostID,
		groupFromSpanAndAttributes(&span, attrs), reporterName, extraResource)

	client := &captureTraceClient{}
	exp := newOTLPTracesExporter(otelcfg.TracesConfig{}, nil, client)
	require.NoError(t, exp.ConsumeTraces(context.Background(), traces))
	require.Len(t, client.uploaded, 1)

	rs := traces.ResourceSpans().At(0)
	res, ok := rs.Resource().Attributes().Get("test.resource")
	require.True(t, ok)
	assert.Equal(t, "resource", res.Str())

	header, ok := rs.ScopeSpans().At(0).Spans().At(0).Attributes().Get("http.request.header.x-test")
	require.True(t, ok)
	require.Equal(t, 2, header.Slice().Len())
	assert.Equal(t, "first", header.Slice().At(0).Str())
	assert.Equal(t, "second", header.Slice().At(1).Str())
}

func assertValidUTF8(t *testing.T, traces ptrace.Traces) {
	t.Helper()
	rs := traces.ResourceSpans()
	for i := range rs.Len() {
		spans := rs.At(i).ScopeSpans()
		for j := range spans.Len() {
			ss := spans.At(j).Spans()
			for k := range ss.Len() {
				assert.True(t, utf8.ValidString(ss.At(k).Name()))
				ss.At(k).Attributes().Range(func(key string, v pcommon.Value) bool {
					assert.True(t, utf8.ValidString(v.AsString()), key)
					return true
				})
			}
		}
	}
}

func BenchmarkGenerateTracesQueryText(b *testing.B) {
	body := strings.Repeat(`{"index":{}}`+"\n"+`{"f":"v"}`+"\n", 400)[:8192]
	for name, text := range map[string]string{
		"valid":   body,
		"invalid": body[:8190] + truncatedRune,
	} {
		b.Run(name, func(b *testing.B) {
			span := utf8TestSpan(request.EventTypeSQLClient)
			span.Method = "INSERT"
			span.Statement = text
			attrs := []attribute.KeyValue{attribute.String("db.query.text", text)}
			group := groupFromSpanAndAttributes(&span, attrs)
			b.ReportAllocs()
			for b.Loop() {
				tracesgen.GenerateTracesWithAttributes(cache, &span.Service, nil, hostID, group, reporterName)
			}
		})
	}
}
