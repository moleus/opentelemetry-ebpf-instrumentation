# obi-agent

OBI with trace selection rules that change while it runs. The rules file is read again every few seconds,
so a Kubernetes ConfigMap edit applies to every node without a restart of the DaemonSet and without a
reload of the eBPF programs.

The rules decide only which spans are **exported as traces**. The eBPF probes, the span metrics and the
network metrics do not change.

## Configuration

The OBI configuration is the same as for the `obi` binary: `--config` or `OTEL_EBPF_CONFIG_PATH`, and the
`OTEL_EBPF_*` variables. Keep the OBI trace sampler at its default; the rules replace it.

| Variable | Default | Meaning |
|---|---|---|
| `OBI_AGENT_RULES_PATH` | `/etc/obi-agent/rules.yaml` | Rules file |
| `OBI_AGENT_RULES_RELOAD_INTERVAL` | `10s` | How often the file is read |
| `OBI_AGENT_HTTP_ADDR` | `:9466` | `/healthz`, `/metrics`, `/rules`. Empty: no HTTP server |

## Rules

```yaml
# spans that match no rule
default:
  ratio: 0.01        # 1% of traces
  errors: false      # true: also every span with an error status
rules:               # the first active rule that matches decides
  - name: checkout-debug
    match:           # glob patterns; empty = any
      namespace: shop          # k8s.namespace.name
      workload: "checkout-*"   # k8s.owner.name (deployment, statefulset, ...)
      service: ""              # service.name
      kind: server             # server, client, producer, consumer, internal
    ratio: 1
    errors: true
    until: 2026-10-05T18:00:00Z
  - name: no-probes
    match: {service: "{healthcheck,probe}"}
    ratio: 0
limits:
  spans_per_second: 1000       # per agent, after the ratio; 0 = no limit
  burst: 1000                  # default = spans_per_second
  max_rule_duration: 24h       # default 24h
```

- The ratio uses the OpenTelemetry `TraceIDRatioBased` algorithm on the trace ID. All spans of one trace,
  on all nodes, get the same decision when they have the same ratio.
- A rule that exports more than the default (a higher ratio, or `errors` that the default does not
  export) must have `until`, at most `max_rule_duration` from the time the file is read. After `until`,
  the rule is ignored. A large flow cannot stay on by mistake.
- An empty or missing file exports nothing.
- An invalid file is rejected as a whole; the rules in use stay. See `/rules` and
  `obi_agent_rules_file_valid`.

## Metrics

| Metric | Meaning |
|---|---|
| `obi_agent_spans_exported_total{rule}` | spans exported as traces |
| `obi_agent_spans_dropped_total{rule,reason}` | `reason`: `ratio` or `rate_limit` |
| `obi_agent_rules_active` | rules that are not expired |
| `obi_agent_rules_file_valid` | 0: the last read of the file was rejected |
| `obi_agent_rules_reloads_total{result}` | reads of a changed file, `ok` or `error` |

## Kubernetes

Mount the ConfigMap as a directory (not with `subPath`: a `subPath` mount does not receive updates):

```yaml
containers:
  - name: obi
    image: <registry>/obi-agent:<tag>
    args: ["--config=/config/obi-config.yml"]
    volumeMounts:
      - {name: config, mountPath: /config}
      - {name: rules, mountPath: /etc/obi-agent}
volumes:
  - {name: rules, configMap: {name: obi-agent-rules}}
```

The kubelet updates a mounted ConfigMap within about a minute, then the agent reads it within
`OBI_AGENT_RULES_RELOAD_INTERVAL`.

## Library extensions

obi-agent uses two options of the OBI library that other embedders can use too:

- `instrumenter.WithTraceDecider(func(*request.Span) bool)`: a decision per span before the traces
  exporters. A refused span is still counted by the span metrics.
- `discover.RegisterTracers(factory)`: additional eBPF tracers, loaded with the OBI common tracers. Their
  spans go through the same pipeline (Kubernetes decoration, filters, exporters).
