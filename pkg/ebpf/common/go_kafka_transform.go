// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"unsafe"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	// Keep these values aligned with k_kafka_api_* in bpf/gotracer/types/kafka.h.
	kafkaGoAPIFetch uint8 = iota
	kafkaGoAPIProduce
)

// saramaTopicNameMax is k_kafka_produce_topic_name_max in bpf/common/kafka_produce_topics.h.
const saramaTopicNameMax = 128

func ReadGoSaramaRequestIntoSpan(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoSaramaClientInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	proc := KafkaProcess{Ns: event.Pid.Ns, Pid: event.Pid.UserPid}
	var groups *KafkaConsumerGroups
	if parseCtx != nil {
		groups = parseCtx.kafkaConsumerGroups
	}
	infos, ignore, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(event.Buf[:]), nil, nil, groups, proc, event.Conn)
	if err != nil || ignore || len(infos) == 0 {
		return request.Span{}, true, nil // ignore if we couldn't parse it
	}

	infos = saramaTopicInfos(event, infos)
	span := GoKafkaSaramaToSpan(event, infos[0])
	if len(infos) > 1 {
		extra := make([]request.Span, 0, len(infos)-1)
		for _, info := range infos[1:] {
			extra = append(extra, GoKafkaSaramaToSpan(event, info))
		}
		detachExtraSpans(extra)
		parseCtx.emitExtraSpans(extra...)
	}
	return span, false, nil
}

// saramaTopicInfos returns one KafkaInfo per topic of the request. The event buffer holds
// only a prefix of the request, which is enough for the header and the first topic. For a
// Produce request the eBPF program also reads the topic names from the full request (see
// bpf/common/kafka_produce_topics.h): at most k_kafka_produce_max_topics names, each cut at
// k_kafka_produce_topic_name_max bytes. Without these names (other requests, or a Produce
// version that the eBPF program does not read) only the first topic is reported.
func saramaTopicInfos(event *GoSaramaClientInfo, infos []*KafkaInfo) []*KafkaInfo {
	first := infos[0]
	topics := &event.Topics
	count := int(topics.Count)
	if first.Operation != Produce || count == 0 {
		return infos[:1]
	}
	count = min(count, len(topics.NameLen))

	out := make([]*KafkaInfo, 0, count)
	off := 0
	for i := range count {
		n := min(int(topics.NameLen[i]), saramaTopicNameMax)
		if off+n > len(topics.Names) {
			break
		}
		name := string(topics.Names[off : off+n])
		off += n
		// the prefix parse has the complete name when the copy was cut
		if i == 0 && int(topics.NameLen[i]) > n && len(first.Topic) == int(topics.NameLen[i]) {
			name = first.Topic
		}
		var partition *PartitionInfo
		if p := topics.Partition[i]; p >= 0 {
			partition = &PartitionInfo{Partition: int(p)}
		}
		out = append(out, &KafkaInfo{
			Operation:     Produce,
			Topic:         name,
			ClientID:      first.ClientID,
			PartitionInfo: partition,
		})
	}
	if len(out) == 0 {
		return infos[:1]
	}
	return out
}

func GoKafkaSaramaToSpan(event *GoSaramaClientInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	return request.Span{
		Type:          request.EventTypeKafkaClient,
		Method:        data.Operation.String(),
		Statement:     data.ClientID,
		Path:          data.Topic,
		Peer:          peer,
		PeerPort:      int(event.Conn.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(event.StartMonotimeNs),
		Start:         int64(event.StartMonotimeNs),
		End:           int64(event.EndMonotimeNs),
		Status:        0,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
		MessagingInfo: kafkaMessagingInfo(data),
	}
}

func ReadGoKafkaGoRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoKafkaGoClientInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	peer := ""
	hostname := ""
	hostPort := 0

	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	op := kafkaGoOperation(event.Op)

	return request.Span{
		Type:          request.EventTypeKafkaClient,
		Method:        op.String(),
		Statement:     "github.com/segmentio/kafka-go",
		Path:          cstr(event.Topic[:]),
		Peer:          peer,
		PeerPort:      int(event.Conn.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(event.StartMonotimeNs),
		Start:         int64(event.StartMonotimeNs),
		End:           int64(event.EndMonotimeNs),
		TraceID:       trace.TraceID(event.Tp.TraceId),
		SpanID:        trace.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace.SpanID(event.Tp.ParentId),
		TraceFlags:    event.Tp.Flags,
		Status:        0,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}

func kafkaGoOperation(apiKey uint8) Operation {
	if apiKey == kafkaGoAPIProduce {
		return Produce
	}

	return Fetch
}
