// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func testDataSection(t *testing.T, data []byte, size uint64, typ elf.SectionType) *elf.Section {
	t.Helper()
	var image bytes.Buffer
	header := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: 1,
		Shoff: 64, Ehsize: 64, Shentsize: 64, Shnum: 2}
	copy(header.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1})
	require.NoError(t, binary.Write(&image, binary.LittleEndian, header))
	require.NoError(t, binary.Write(&image, binary.LittleEndian, elf.Section64{}))
	require.NoError(t, binary.Write(&image, binary.LittleEndian, elf.Section64{Type: uint32(typ), Off: 192, Size: size}))
	image.Write(data)
	f, err := elf.NewFile(bytes.NewReader(image.Bytes()))
	require.NoError(t, err)
	return f.Sections[1]
}

func TestSectionData(t *testing.T) {
	data := bytes.Repeat([]byte{0x39, 0x42, 0x71}, 4<<20)
	section := testDataSection(t, data, uint64(len(data)), elf.SHT_PROGBITS)
	got, err := sectionData(section)
	require.NoError(t, err)
	require.Equal(t, data, got)
	// Section.Data grows its buffer above the 10 MiB saferio chunk size.
	result := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			contents, readErr := sectionData(section)
			if readErr != nil || len(contents) != len(data) {
				b.Fatal(readErr)
			}
		}
	})
	require.Less(t, result.AllocedBytesPerOp(), int64(len(data)+1<<20))
}

func TestSectionDataInvalidSize(t *testing.T) {
	for _, size := range []uint64{4, 1 << 62, ^uint64(0)} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			section := testDataSection(t, []byte{1, 2, 3}, 3, elf.SHT_PROGBITS)
			section.Size = size
			_, err := sectionData(section)
			require.Error(t, err)
		})
	}
}

func TestSectionDataNoBits(t *testing.T) {
	section := testDataSection(t, nil, 4, elf.SHT_NOBITS)
	_, err := sectionData(section)
	require.Error(t, err)
}

func TestSectionDataEmpty(t *testing.T) {
	got, err := sectionData(testDataSection(t, nil, 0, elf.SHT_PROGBITS))
	require.NoError(t, err)
	require.Empty(t, got)
}
