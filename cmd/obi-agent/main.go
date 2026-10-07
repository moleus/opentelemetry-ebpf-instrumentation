// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// obi-agent runs OBI with trace selection rules that are read from a file while OBI runs: the ratio
// per namespace, workload, service and span kind, with an end time, and a limit of spans per second.
// The OBI configuration is the same as for the obi binary (--config, OTEL_EBPF_* variables).
// The agent itself is configured only by environment variables (see envConfig).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go.opentelemetry.io/obi/cmd/obi-agent/internal/fatalsignal"
	"go.opentelemetry.io/obi/cmd/obi-agent/internal/rules"
	"go.opentelemetry.io/obi/cmd/obi-agent/internal/sampler"
	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/kube/klogbridge"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	envRulesPath      = "OBI_AGENT_RULES_PATH"
	envReloadInterval = "OBI_AGENT_RULES_RELOAD_INTERVAL"
	envHTTPAddr       = "OBI_AGENT_HTTP_ADDR"
	envTracers        = "OBI_AGENT_TRACERS"

	defaultRulesPath      = "/etc/obi-agent/rules.yaml"
	defaultReloadInterval = 10 * time.Second
	defaultHTTPAddr       = ":9466"
	httpShutdownTimeout   = 5 * time.Second
	httpReadHeaderTimeout = 5 * time.Second
)

// envConfig is the configuration of the agent, read from the environment.
type envConfig struct {
	rulesPath      string
	reloadInterval time.Duration
	httpAddr       string   // empty: no HTTP server
	tracers        []string // additional eBPF tracers, see extraTracers
}

// extraTracers are the eBPF tracers of the agent that OBI does not have. They are enabled by name
// in OBI_AGENT_TRACERS (comma-separated).
var extraTracers = map[string]discover.TracerFactory{
	"fatalsignal": fatalsignal.Factory,
}

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "", "path to the OBI configuration file")
	flag.Parse()
	if p := os.Getenv("OTEL_EBPF_CONFIG_PATH"); p != "" {
		configPath = &p
	}

	env, err := loadEnv()
	if err != nil {
		slog.Error("wrong environment", "error", err)
		return 1
	}
	config, err := loadOBIConfig(*configPath)
	if err != nil {
		slog.Error("wrong OBI configuration", "error", err)
		return 1
	}
	if err := setupLogger(config); err != nil {
		slog.Error("wrong OBI configuration", "error", err)
		return 1
	}
	slog.Info("obi-agent", "version", buildinfo.Version, "revision", buildinfo.Revision, "rules", env.rulesPath)

	if err := obi.CheckOSSupport(); err != nil {
		slog.Error("can't start", "error", err)
		return 1
	}
	if err := config.Validate(); err != nil {
		slog.Error("wrong OBI configuration", "error", err)
		return 1
	}

	for _, name := range env.tracers {
		discover.RegisterTracers(extraTracers[name])
		slog.Info("additional tracer enabled", "tracer", name)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	// No traces until the rules file is read: a missing or invalid file must not open a large flow.
	smp := sampler.New(&rules.Set{}, reg, time.Now)
	watcher := newRulesWatcher(env.rulesPath, env.reloadInterval, smp, reg)
	go watcher.run(ctx)

	srv := startHTTP(env.httpAddr, reg, watcher, smp)
	defer shutdownHTTP(srv)

	if err := instrumenter.Run(ctx, config, instrumenter.WithTraceDecider(smp.Decide)); err != nil {
		slog.Error("OBI ran with errors", "error", err)
		return 1
	}
	slog.Info("obi-agent stopped")
	return 0
}

func loadEnv() (envConfig, error) {
	env := envConfig{rulesPath: defaultRulesPath, reloadInterval: defaultReloadInterval, httpAddr: defaultHTTPAddr}
	if v, ok := os.LookupEnv(envRulesPath); ok {
		env.rulesPath = v
	}
	if v, ok := os.LookupEnv(envHTTPAddr); ok {
		env.httpAddr = v
	}
	for _, name := range strings.Split(os.Getenv(envTracers), ",") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		if _, ok := extraTracers[name]; !ok {
			return env, fmt.Errorf("%s: unknown tracer %q", envTracers, name)
		}
		env.tracers = append(env.tracers, name)
	}
	if v, ok := os.LookupEnv(envReloadInterval); ok {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return env, fmt.Errorf("%s: %q is not a positive duration", envReloadInterval, v)
		}
		env.reloadInterval = d
	}
	return env, nil
}

// loadOBIConfig reads the OBI configuration like the obi binary: config v2 first, then v1.
func loadOBIConfig(path string) (*obi.Config, error) {
	var data []byte
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if data, err = io.ReadAll(f); err != nil {
			return nil, err
		}
	}

	doc, _, err := schema.ParseStandaloneYAML(obicfg.ReplaceEnv(data))
	if err == nil {
		return convert.DocumentToRuntime(doc)
	}
	if _, ok := errors.AsType[*schema.NotV2Error](err); !ok {
		return nil, fmt.Errorf("config v2: %w", err)
	}
	var legacy io.Reader
	if path != "" {
		legacy = bytes.NewReader(data)
	}
	return obi.LoadConfig(legacy)
}

func setupLogger(config *obi.Config) error {
	var lvl slog.LevelVar
	if err := lvl.UnmarshalText([]byte(config.LogLevel)); err != nil {
		return fmt.Errorf("log_level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: &lvl}
	var h slog.Handler = slog.NewTextHandler(os.Stdout, opts)
	if obi.LogFormat(strings.ToLower(string(config.LogFormat))) == obi.LogFormatJSON {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))
	klogbridge.Install()
	return nil
}

// startHTTP serves /healthz, /metrics (the agent metrics) and /rules (the rules in use and the
// state of the rules file).
func startHTTP(addr string, reg *prometheus.Registry, w *rulesWatcher, smp *sampler.Sampler) *http.Server {
	if addr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("ok\n"))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	if os.Getenv("OBI_AGENT_PPROF") != "" {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	}
	mux.HandleFunc("GET /rules", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{"file": w.status(), "rules": describe(smp.Rules(), time.Now())})
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: httpReadHeaderTimeout}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server stopped", "addr", addr, "error", err)
		}
	}()
	return srv
}

func shutdownHTTP(srv *http.Server) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

type ruleView struct {
	Name   string      `json:"name,omitempty"`
	Match  rules.Match `json:"match"`
	Ratio  float64     `json:"ratio"`
	Errors bool        `json:"errors"`
	Until  *time.Time  `json:"until,omitempty"`
	Active bool        `json:"active"`
}

func describe(set *rules.Set, now time.Time) map[string]any {
	views := make([]ruleView, 0, len(set.Rules))
	for i := range set.Rules {
		r := &set.Rules[i]
		views = append(views, ruleView{Name: r.Name, Match: r.Match, Ratio: r.Ratio, Errors: r.Errors, Until: r.Until, Active: r.ActiveAt(now)})
	}
	return map[string]any{"default": set.Default, "rules": views, "limits": set.Limits}
}
