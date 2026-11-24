// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

// CaptureRuntimes groups language runtime capture settings.
type CaptureRuntimes struct {
	Go     GoRuntime   `yaml:"go"`
	NodeJS Runtime     `yaml:"nodejs"`
	Java   JavaRuntime `yaml:"java"`
}

// Runtime describes generic language runtime capture settings.
type Runtime struct {
	Enabled bool             `yaml:"enabled"`
	Filter  AttributeFilters `yaml:"filter,omitempty"`
}

// GoRuntime describes Go probe enablement, channel span links and offset inspection limits.
type GoRuntime struct {
	Enabled      bool             `yaml:"enabled"`
	Filter       AttributeFilters `yaml:"filter,omitempty"`
	ChannelLinks *bool            `yaml:"channel_links,omitempty"`
	// MaxPclntabSize is the maximum uncompressed .gopclntab size in bytes; zero disables the limit.
	MaxPclntabSize uint64 `yaml:"max_pclntab_size,omitempty"`
}

// JavaRuntime describes Java runtime capture and debug settings.
type JavaRuntime struct {
	Enabled       bool             `yaml:"enabled"`
	Filter        AttributeFilters `yaml:"filter,omitempty"`
	Debug         JavaDebug        `yaml:"debug"`
	AttachTimeout Duration         `yaml:"attach_timeout"`
}

// JavaDebug describes Java runtime debug instrumentation settings.
type JavaDebug struct {
	Enabled                 bool `yaml:"enabled"`
	BytecodeInstrumentation bool `yaml:"bytecode_instrumentation"`
}
