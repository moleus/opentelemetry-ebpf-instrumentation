// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sampler

import "time"

// limiter is a token bucket for one goroutine. The rate and the burst are passed on every call,
// so a rules change applies at once; the tokens are kept within the new burst.
type limiter struct {
	tokens float64
	last   time.Time
}

func (l *limiter) allow(now time.Time, perSecond, burst float64) bool {
	if perSecond <= 0 {
		return true
	}
	// a rate below 1/s still lets one span through
	burst = max(burst, 1)
	if l.last.IsZero() {
		l.tokens = burst
	} else {
		l.tokens += now.Sub(l.last).Seconds() * perSecond
	}
	l.last = now
	l.tokens = min(l.tokens, burst)

	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
