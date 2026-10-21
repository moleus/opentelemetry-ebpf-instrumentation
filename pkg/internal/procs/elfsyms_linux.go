//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

const (
	// symChunkEntries is the number of symbol table entries read from the file at once.
	symChunkEntries = 1024
	// strBlockSize and strBlockCount bound the cache of the string table: a symbol name is
	// read through a direct-mapped cache of strBlockCount blocks of strBlockSize bytes.
	strBlockSize  = 4 << 10
	strBlockCount = 64
	// maxSymbolNameLen is the longest symbol name that is looked at. A longer name does not match.
	maxSymbolNameLen = 1 << 20
)

// elfSymbol is a symbol table entry. The name is read from the string table only when it is asked for.
type elfSymbol struct {
	Info  byte
	Value uint64
	Size  uint64

	nameIdx uint32
	names   *strtabReader
}

// name returns the name of the symbol, or false if the string table has no such string.
// The slice is valid only until the next call of name on any symbol of the same table.
func (s *elfSymbol) name() ([]byte, bool) {
	return s.names.cString(s.nameIdx)
}

// forEachELFSymbol calls fn for each entry of the first section of type typ (elf.SHT_SYMTAB or
// elf.SHT_DYNSYM), in file order, skipping the null entry. It visits the same entries as
// (*elf.File).Symbols and (*elf.File).DynamicSymbols, but it does not load the symbol table
// and the string table into memory: the memory it uses does not depend on their size
// (the standard library reads both whole and makes a Go string of each name; for a C++ server
// with 500 thousand symbols that is more than 100 MiB for each call).
// It returns elf.ErrNoSymbols if the file has no such section.
func forEachELFSymbol(f *elf.File, typ elf.SectionType, fn func(*elfSymbol)) error {
	var symtab *elf.Section
	for _, s := range f.Sections {
		if s.Type == typ {
			symtab = s
			break
		}
	}
	if symtab == nil {
		return elf.ErrNoSymbols
	}
	if symtab.Link == 0 || int(symtab.Link) >= len(f.Sections) {
		return fmt.Errorf("symbol table has an invalid string table link %d", symtab.Link)
	}
	strSec := f.Sections[symtab.Link]
	if strSec.Type != elf.SHT_STRTAB {
		return errors.New("linked section of the symbol table is not a string table")
	}

	symR, symSize, err := sectionReaderAt(symtab)
	if err != nil {
		return err
	}
	strR, strSize, err := sectionReaderAt(strSec)
	if err != nil {
		return err
	}

	var entSize int
	switch f.Class {
	case elf.ELFCLASS64:
		entSize = elf.Sym64Size
	case elf.ELFCLASS32:
		entSize = elf.Sym32Size
	case elf.ELFCLASSNONE:
		fallthrough
	default:
		return fmt.Errorf("unsupported ELF class %v", f.Class)
	}
	if symSize%int64(entSize) != 0 {
		return errors.New("length of the symbol table is not a multiple of the entry size")
	}

	sym := elfSymbol{names: newStrtabReader(strR, strSize)}
	buf := make([]byte, symChunkEntries*entSize)
	count := symSize / int64(entSize)
	for first := int64(1); first < count; first += symChunkEntries {
		n := int(min(count-first, symChunkEntries))
		chunk := buf[:n*entSize]
		if err := readFullAt(symR, chunk, first*int64(entSize)); err != nil {
			return fmt.Errorf("can't read the symbol table: %w", err)
		}
		for i := range n {
			e := chunk[i*entSize:]
			sym.nameIdx = f.ByteOrder.Uint32(e[0:4])
			if f.Class == elf.ELFCLASS64 {
				sym.Info = e[4]
				sym.Value = f.ByteOrder.Uint64(e[8:16])
				sym.Size = f.ByteOrder.Uint64(e[16:24])
			} else {
				sym.Value = uint64(f.ByteOrder.Uint32(e[4:8]))
				sym.Size = uint64(f.ByteOrder.Uint32(e[8:12]))
				sym.Info = e[12]
			}
			fn(&sym)
		}
	}
	return nil
}

// sectionReaderAt returns a reader of the contents of a section and their size. A compressed
// section (never seen for a symbol table) is decompressed into memory.
func sectionReaderAt(s *elf.Section) (io.ReaderAt, int64, error) {
	if s.Type == elf.SHT_NOBITS {
		return nil, 0, fmt.Errorf("section %s has no contents", s.Name)
	}
	if s.Flags&elf.SHF_COMPRESSED != 0 {
		data, err := s.Data()
		if err != nil {
			return nil, 0, err
		}
		return bytes.NewReader(data), int64(len(data)), nil
	}
	return s.ReaderAt, int64(s.FileSize), nil
}

// readFullAt fills p from r at off. A reader may report io.EOF together with the last bytes.
func readFullAt(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// strtabReader reads NUL-terminated strings of an ELF string table through a small cache.
type strtabReader struct {
	r      io.ReaderAt
	size   int64
	blocks [strBlockCount]strBlock
	// spill holds a string that crosses the end of a block.
	spill []byte
}

type strBlock struct {
	idx  int64  // index of the block in the table
	n    int    // number of valid bytes in data; 0: the block is empty
	data []byte // strBlockSize bytes, allocated at the first use
}

func newStrtabReader(r io.ReaderAt, size int64) *strtabReader {
	return &strtabReader{r: r, size: size}
}

// block returns the bytes of block idx: strBlockSize bytes, or less for the last block of the table.
func (t *strtabReader) block(idx int64) ([]byte, bool) {
	b := &t.blocks[idx%strBlockCount]
	if b.n > 0 && b.idx == idx {
		return b.data[:b.n], true
	}
	start := idx * strBlockSize
	if start >= t.size {
		return nil, false
	}
	if b.data == nil {
		b.data = make([]byte, strBlockSize)
	}
	b.n = 0
	n := int(min(t.size-start, strBlockSize))
	if err := readFullAt(t.r, b.data[:n], start); err != nil {
		return nil, false
	}
	b.idx, b.n = idx, n
	return b.data[:n], true
}

// cString returns the string that starts at offset off, without the terminating NUL.
// It returns false if off is outside of the table, or if the string has no terminator within
// the table or is longer than maxSymbolNameLen. The slice is valid until the next call.
func (t *strtabReader) cString(off uint32) ([]byte, bool) {
	pos := int64(off)
	if pos >= t.size {
		return nil, false
	}
	t.spill = t.spill[:0]
	for {
		blk, ok := t.block(pos / strBlockSize)
		if !ok {
			return nil, false
		}
		in := blk[pos%strBlockSize:]
		if end := bytes.IndexByte(in, 0); end >= 0 {
			if len(t.spill) == 0 {
				return in[:end], true
			}
			t.spill = append(t.spill, in[:end]...)
			return t.spill, true
		}
		if len(t.spill)+len(in) > maxSymbolNameLen {
			return nil, false
		}
		t.spill = append(t.spill, in...)
		pos += int64(len(in))
		if pos >= t.size {
			return nil, false
		}
	}
}
