// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package fatalsignal is an eBPF tracer that reports processes terminated by a signal: crashes and
// kills (including the OOM killer). It is registered with discover.RegisterTracers, so its spans get
// the same Kubernetes decoration and export as the OBI spans.
package fatalsignal // import "go.opentelemetry.io/obi/cmd/obi-agent/internal/fatalsignal"

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type fatal_signal_event_t -target amd64,arm64 Bpf fatalsignal.c -- -I../../../../bpf

// Tracer is an obiebpf.Tracer with one BTF tracepoint and one ring buffer.
type Tracer struct {
	cfg        *obi.Config
	metrics    imetrics.Reporter
	pidsFilter ebpfcommon.ServiceFilter
	bpfObjects BpfObjects
	closers    []io.Closer
	log        *slog.Logger
}

// Factory creates the tracer for discover.RegisterTracers.
func Factory(cfg *obi.Config, metrics imetrics.Reporter, pidFilter ebpfcommon.ServiceFilter) []obiebpf.Tracer {
	return []obiebpf.Tracer{&Tracer{
		cfg: cfg, metrics: metrics, pidsFilter: pidFilter, log: slog.With("component", "fatalsignal.Tracer"),
	}}
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	return []*ebpfcommon.SpecBundle{{Spec: spec, Objects: &p.bpfObjects}}, nil
}

// Tracing attaches the BTF tracepoint with a BPF link: a classic tracepoint would need tracefs mounted
// in the container.
func (p *Tracer) Tracing() []*ebpfcommon.Tracing {
	return []*ebpfcommon.Tracing{{Program: p.bpfObjects.ObiTpBtfSignalDeliver, AttachAs: ebpf.AttachTraceRawTp}}
}

func (p *Tracer) Run(ctx context.Context, eventCtx *ebpfcommon.EBPFEventContext, out *msg.Queue[[]request.Span]) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.FatalSignalEvents,
		p.readEvent,
		eventCtx.CommonPIDsFilter.Filter,
		p.log,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, out)
}

func (p *Tracer) readEvent(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[BpfFatalSignalEventT](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}
	return eventToSpan(event), false, nil
}

func eventToSpan(event *BpfFatalSignalEventT) request.Span {
	name := unix.SignalName(unix.Signal(event.Sig))
	comm := unix.ByteSliceToString(event.Comm[:])
	ts := int64(event.Timestamp)
	return request.Span{
		Type:         request.EventTypeManualSpan,
		SpanKind:     trace.SpanKindInternal,
		Method:       name,
		Path:         name + " terminated " + comm,
		Status:       int(codes.Error),
		RequestStart: ts,
		Start:        ts,
		End:          ts,
		TraceID:      idgen.RandomTraceID(),
		SpanID:       idgen.RandomSpanID(),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
		Statement: spanAttributes(
			stringAttr("signal.name", name),
			intAttr("signal.number", int64(event.Sig)),
			intAttr("signal.code", int64(event.Code)),
			stringAttr("process.command", comm),
		),
	}
}

// spanAttributes encodes the attributes in the format that the OBI exporters read from manual spans.
func spanAttributes(attrs ...tracesgen.SpanAttr) string {
	data, err := json.Marshal(attrs)
	if err != nil {
		return ""
	}
	return string(data)
}

func stringAttr(key, value string) tracesgen.SpanAttr {
	a := tracesgen.SpanAttr{Vtype: uint8(attribute.STRING)}
	copy(a.Key[:], key)
	a.ValLength = uint16(copy(a.Value[:], value))
	return a
}

func intAttr(key string, value int64) tracesgen.SpanAttr {
	a := tracesgen.SpanAttr{Vtype: uint8(attribute.INT64), ValLength: 8}
	copy(a.Key[:], key)
	binary.LittleEndian.PutUint64(a.Value[:8], uint64(value))
	return a
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	p.pidsFilter.AllowPID(pid, ns, fi, ebpfcommon.PIDTypeKProbes)
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) { p.pidsFilter.BlockPID(pid, ns) }

func (p *Tracer) AddCloser(c ...io.Closer) { p.closers = append(p.closers, c...) }

func (p *Tracer) Close() error {
	return ebpfcommon.CloseResources(append(p.closers, &p.bpfObjects)...)
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc               { return nil }
func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc           { return nil }
func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc { return nil }
func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc     { return nil }
func (p *Tracer) SocketFilters() []*ebpf.Program                         { return nil }
func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg                         { return nil }
func (p *Tracer) SockOps() []ebpfcommon.SockOps                          { return nil }
func (p *Tracer) Iters() []*ebpfcommon.Iter                              { return nil }
func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc           { return nil }
func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer)              {}
func (p *Tracer) AddInstrumentedLibRef(uint64)                           {}
func (p *Tracer) AlreadyInstrumentedLib(uint64) bool                     { return false }
func (p *Tracer) UnlinkInstrumentedLib(uint64)                           {}
func (p *Tracer) RegisterOffsets(*exec.FileInfo, *obiebpf.GoOffsets)     {}
func (p *Tracer) ProcessBinary(*exec.FileInfo)                           {}
func (p *Tracer) SetEventContext(*ebpfcommon.EBPFEventContext)           {}
func (p *Tracer) Required() bool                                         { return false }
func (p *Tracer) Capabilities() ebpfcommon.TracerCapability              { return 0 }
