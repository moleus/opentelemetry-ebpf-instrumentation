// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ByteSize is a size in bytes. It is read from text as a plain number of
// bytes ("67108864") or as a number with a unit ("64MiB", "1.5GiB", "512k").
// Units are powers of 1024 (KiB, MiB, GiB) or the same with the short and
// decimal spellings (K, KB, M, MB, G, GB); both mean powers of 1024, as in
// container resource limits written with an "i" suffix.
type ByteSize uint64

var byteSizeUnits = []struct {
	suffix string
	mult   uint64
}{
	// Longer suffixes first: "KiB" must match before "B".
	{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30},
	{"kb", 1 << 10}, {"mb", 1 << 20}, {"gb", 1 << 30},
	{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30},
	{"b", 1},
}

// UnmarshalText implements encoding.TextUnmarshaler, used by the environment
// variable and YAML parsers.
func (b *ByteSize) UnmarshalText(text []byte) error {
	s := strings.ToLower(strings.TrimSpace(string(text)))
	if s == "" {
		*b = 0
		return nil
	}
	mult := uint64(1)
	for _, u := range byteSizeUnits {
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			s = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			break
		}
	}
	if n, err := strconv.ParseUint(s, 10, 64); err == nil {
		if n > math.MaxUint64/mult {
			return fmt.Errorf("size %q overflows 64 bits", text)
		}
		*b = ByteSize(n * mult)
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) || f*float64(mult) >= math.MaxUint64 {
		return fmt.Errorf("invalid size %q: use bytes or a unit, for example 67108864 or 64MiB", text)
	}
	*b = ByteSize(f * float64(mult))
	return nil
}
