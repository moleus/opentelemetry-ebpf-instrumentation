# Limit Go offset inspection

Go-specific probes require offsets from the executable's `.gopclntab` section.
Reading a large table and building the function index can consume a large heap.
Set `capture.runtimes.go.max_pclntab_size` to limit the uncompressed section size
in bytes. The default is `0`, which disables the limit.

For standalone Config v2, the field is under `extensions.obi`:

```yaml
extensions:
  obi:
    capture:
      runtimes:
        go:
          enabled: true
          max_pclntab_size: ${OTEL_EBPF_GO_MAX_PCLNTAB_SIZE:-0}
```

With environment-based runtime configuration, use
`OTEL_EBPF_GO_MAX_PCLNTAB_SIZE`. Config v2 reads that variable through the
explicit substitution above. There is no new Config v1 YAML field.

A section larger than the limit bypasses Go offset inspection and uses the
existing generic instrumentation path. This loses Go-specific probes, including
Go runtime metrics and Go TLS visibility. Generic probes can still observe
supported traffic, but do not provide equivalent coverage.

OBI writes one warning per uncached executable inspection with the executable
path, section size, and limit. It increments the internal Prometheus counter
`obi_go_inspection_skipped_total{reason="pclntab_too_large"}`. The counter has no
path or PID label. With the OTEL internal exporter, the metric is
`obi.go.inspection.skipped` and the attribute is `obi.go.inspection.skip.reason`.
The executable cache avoids counting each process instance. Eviction, process
removal, or an OBI restart can cause a later inspection to count again.

The counter records skipped inspections, not failed attachments or skipped
processes. For example, show skips in the current OBI lifetimes with:

```promql
sum by (reason) (obi_go_inspection_skipped_total)
```

A query using `increase` can miss increments before the first Prometheus scrape,
including skips during startup. The raw counter shows those skips, but resets
when OBI restarts.

This limit is not a total memory budget. It does not bound DWARF, ELF symbol
tables, generic probe setup, or several smaller executables. It only checks a
named `.gopclntab` section. Choose a limit using representative executables and
memory measurements; section size alone does not predict the peak heap.
