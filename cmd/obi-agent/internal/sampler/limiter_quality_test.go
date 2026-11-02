// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sampler

import (
	"math"
	"testing"
	"time"
)

func TestLimiterRejectsNonFiniteInput(t *testing.T) {
	for _, val := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		var l limiter
		if l.allow(time.Unix(1, 0), val, 1) {
			t.Fatalf("accepted invalid rate %v", val)
		}
		if l.allow(time.Unix(1, 0), 1, val) {
			t.Fatalf("accepted invalid burst %v", val)
		}
	}
	var disabled limiter
	if !disabled.allow(time.Unix(1, 0), 0, 0) {
		t.Fatal("zero-rate should disable limiter")
	}
}

// For monotonic time, the budget must never be exceeded.
func FuzzLimiterBudget(f *testing.F) {
	f.Add(uint8(3), uint8(2), uint16(250), uint8(20))
	f.Add(uint8(1), uint8(1), uint16(0), uint8(50))
	f.Fuzz(func(t *testing.T, irate, iburst uint8, millis uint16, attempts uint8) {
		rate := float64(irate%30 + 1)
		burst := float64(iburst%20 + 1)
		var l limiter
		now := time.Unix(1, 0)
		accepted := 0
		for i := 0; i < int(attempts%60); i++ {
			if l.allow(now, rate, burst) {
				accepted++
			}
		}
		later := now.Add(time.Duration(millis) * time.Millisecond)
		for i := 0; i < int(attempts%60); i++ {
			if l.allow(later, rate, burst) {
				accepted++
			}
		}
		budget := int(math.Floor(burst + float64(millis)*rate/1000))
		if accepted > budget {
			t.Fatalf("accepted %d > budget %d", accepted, budget)
		}
	})
}
