// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"fmt"
	"io"
	"strings"
)

// sectionData returns the contents of a section in one buffer of the exact size.
// elf.Section.Data reads big sections through saferio in 10 MiB steps and
// grows the result by append, so it allocates several times the section size.
func sectionData(s *elf.Section) ([]byte, error) {
	if s.Type == elf.SHT_NOBITS || s.Flags&elf.SHF_COMPRESSED != 0 || strings.HasPrefix(s.Name, ".zdebug") {
		return s.Data()
	}
	if s.Size > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("section %s is too large: %d bytes", s.Name, s.Size)
	}
	// Check the last byte before allocating from an untrusted section header.
	if s.Size > 0 {
		var last [1]byte
		if _, err := s.ReadAt(last[:], int64(s.Size-1)); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, s.Size)
	if _, err := io.ReadFull(s.Open(), buf); err != nil {
		return nil, err
	}
	return buf, nil
}
