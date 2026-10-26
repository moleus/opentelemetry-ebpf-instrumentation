//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// referenceFindExeSymbols is the lookup as it was before the tables were streamed: it loads both
// tables with the standard library. The streaming lookup must return the same result and the
// same errors: any error but elf.ErrNoSymbols is returned.
func referenceFindExeSymbols(t testing.TB, f *elf.File, names []string, types ...elf.SymType) (map[string]Sym, error) {
	t.Helper()
	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}
	exact := map[string]Sym{}
	collect := func(syms []elf.Symbol) {
		for _, s := range syms {
			if !slices.Contains(types, elf.ST_TYPE(s.Info)) {
				continue
			}
			if slices.Contains(names, s.Name) {
				exact[s.Name] = resolveSymbol(f, s)
			}
		}
	}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	collect(syms)
	dyn, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	collect(dyn)
	return exact, nil
}

// openSelf opens a Go executable that has a symbol table: the test binary is stripped in some
// setups, the go command of the toolchain that runs the tests is not.
func openSelf(t testing.TB) *elf.File {
	t.Helper()
	for _, path := range []string{os.Args[0], filepath.Join(runtime.GOROOT(), "bin", "go")} {
		f, err := elf.Open(path)
		if err != nil {
			continue
		}
		if syms, err := f.Symbols(); err == nil && len(syms) > 1000 {
			t.Cleanup(func() { _ = f.Close() })
			return f
		}
		_ = f.Close()
	}
	t.Skip("no executable with a symbol table found")
	return nil
}

func TestFindExeSymbolsMatchesStandardLibrary(t *testing.T) {
	f := openSelf(t)
	syms, err := f.Symbols()
	require.NoError(t, err)

	// every 97th function name as an exact name, plus names that do not exist
	var names []string
	for i, s := range syms {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && i%97 == 0 {
			names = append(names, s.Name)
		}
	}
	names = append(names, "no.such.symbol", "")

	for _, types := range [][]elf.SymType{nil, {elf.STT_OBJECT}, {elf.STT_FUNC, elf.STT_OBJECT}} {
		want, err := referenceFindExeSymbols(t, f, names, types...)
		require.NoError(t, err)
		got, err := FindExeSymbols(f, names, types...)
		require.NoError(t, err)
		assert.Equal(t, want, got, "types %v", types)
	}
}

func TestFindExeSymbolsDynamicTable(t *testing.T) {
	for _, path := range []string{"/bin/sh", "/bin/ls", "/usr/bin/env"} {
		f, err := elf.Open(path)
		if err != nil {
			continue
		}
		dyn, err := f.DynamicSymbols()
		if err != nil || len(dyn) == 0 {
			_ = f.Close()
			continue
		}
		var names []string
		for _, s := range dyn {
			names = append(names, s.Name)
		}
		want, err := referenceFindExeSymbols(t, f, names)
		require.NoError(t, err)
		got, err := FindExeSymbols(f, names)
		_ = f.Close()
		require.NoError(t, err)
		assert.Equal(t, want, got, path)
		return
	}
	t.Skip("no dynamically linked executable found")
}

// The lookup must not allocate in proportion to the size of the tables.
func TestFindExeSymbolsAllocatesLittle(t *testing.T) {
	f := openSelf(t)
	var tableBytes uint64
	for _, s := range f.Sections {
		if s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_DYNSYM || s.Name == ".strtab" || s.Name == ".dynstr" {
			tableBytes += s.Size
		}
	}

	measure := func(fn func()) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	names := []string{"runtime.mallocgc"}
	oldBytes := measure(func() { _, _ = referenceFindExeSymbols(t, f, names) })
	newBytes := measure(func() {
		_, err := FindExeSymbols(f, names)
		require.NoError(t, err)
	})
	t.Logf("tables %d bytes, standard library lookup allocated %d, streaming lookup %d", tableBytes, oldBytes, newBytes)
	// The cache of the string table is the largest part: strBlockCount * strBlockSize.
	assert.Less(t, newBytes, uint64(strBlockCount*strBlockSize+256<<10))
	assert.Less(t, newBytes*2, oldBytes)
}

func TestStrtabReader(t *testing.T) {
	// names around block boundaries, one longer than a block, one without terminator at the end
	long := strings.Repeat("L", strBlockSize*2+17)
	var tab bytes.Buffer
	tab.WriteByte(0)
	offsets := map[string]uint32{}
	for _, n := range []string{"a", "bb", strings.Repeat("x", strBlockSize-tab.Len()-1), "boundary", long, "tail"} {
		offsets[n] = uint32(tab.Len())
		tab.WriteString(n)
		tab.WriteByte(0)
	}
	noTerm := uint32(tab.Len())
	tab.WriteString("unterminated")

	r := newStrtabReader(bytes.NewReader(tab.Bytes()), int64(tab.Len()))
	for n, off := range offsets {
		got, ok := r.cString(off)
		require.True(t, ok, n)
		assert.Equal(t, n, string(got))
	}
	// again, in the opposite order, after blocks were replaced
	for round := range 3 {
		for n, off := range offsets {
			got, ok := r.cString(off)
			require.True(t, ok, "round %d %s", round, n)
			assert.Equal(t, n, string(got))
		}
	}
	got, ok := r.cString(0)
	assert.True(t, ok)
	assert.Empty(t, got)

	_, ok = r.cString(noTerm)
	assert.False(t, ok, "a string without terminator")
	_, ok = r.cString(uint32(tab.Len()))
	assert.False(t, ok, "offset at the end of the table")
	_, ok = r.cString(1 << 30)
	assert.False(t, ok, "offset after the end of the table")
}

func TestStrtabReaderManyBlocks(t *testing.T) {
	// more blocks than the cache holds, read in a scattered order
	const names = 20000
	var tab bytes.Buffer
	tab.WriteByte(0)
	offs := make([]uint32, names)
	for i := range names {
		offs[i] = uint32(tab.Len())
		tab.WriteString(strings.Repeat("n", 40+i%50))
		tab.WriteString(string(rune('A' + i%26)))
		tab.WriteByte(0)
	}
	r := newStrtabReader(bytes.NewReader(tab.Bytes()), int64(tab.Len()))
	for _, i := range []int{names - 1, 0, names / 2, 1, names - 2, 12345, 7, 19999, 3} {
		got, ok := r.cString(offs[i])
		require.True(t, ok)
		assert.Len(t, got, 40+i%50+1)
		assert.Equal(t, byte('A'+i%26), got[len(got)-1])
	}
}

type failingReaderAt struct{}

func (failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestStrtabReaderReadError(t *testing.T) {
	r := newStrtabReader(failingReaderAt{}, 100)
	_, ok := r.cString(1)
	assert.False(t, ok)
	assert.ErrorIs(t, r.err, io.ErrUnexpectedEOF, "a read error is kept, it is not a missing string")

	r = newStrtabReader(bytes.NewReader([]byte("\x00abc\x00")), 5)
	_, ok = r.cString(100)
	assert.False(t, ok)
	assert.NoError(t, r.err, "a name outside of the table is not a read error")
}

// The limit is on the length of the name, wherever the terminating NUL is.
func TestStrtabReaderNameLimit(t *testing.T) {
	// start puts the end of a name of maxSymbolNameLen bytes at the end of a block, so that
	// the NUL is the first byte of the next block
	startAtBlockEnd := strBlockSize - (maxSymbolNameLen % strBlockSize)
	for _, tc := range []struct {
		name    string
		start   int
		nameLen int
		ok      bool
	}{
		{"max, NUL in the same block as the last letter", 1, maxSymbolNameLen, true},
		{"max, NUL in the next block", startAtBlockEnd, maxSymbolNameLen, true},
		{"max + 1, NUL in the same block", 1, maxSymbolNameLen + 1, false},
		{"max + 1, NUL in the next block", startAtBlockEnd - 1, maxSymbolNameLen + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tab := make([]byte, tc.start+tc.nameLen+1)
			for i := range tc.nameLen {
				tab[tc.start+i] = 'n'
			}
			r := newStrtabReader(bytes.NewReader(tab), int64(len(tab)))
			got, ok := r.cString(uint32(tc.start))
			assert.Equal(t, tc.ok, ok)
			assert.NoError(t, r.err)
			if ok {
				assert.Len(t, got, tc.nameLen)
			}
		})
	}
}

// failAtReaderAt serves the file but fails for any read that touches [off, off+size).
type failAtReaderAt struct {
	r         io.ReaderAt
	off, size int64
}

var errInjected = errors.New("injected read failure")

func (f failAtReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < f.off+f.size && off+int64(len(p)) > f.off {
		return 0, errInjected
	}
	return f.r.ReadAt(p, off)
}

// openWithUnreadableSection opens the executable at path with the standard library, and a
// second time so that the contents of the section fail to read.
func openWithUnreadableSection(t *testing.T, path, section string) *elf.File {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	good, err := elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	sec := good.Section(section)
	if sec == nil {
		return nil
	}
	f, err := elf.NewFile(failAtReaderAt{r: bytes.NewReader(data), off: int64(sec.Offset), size: int64(sec.FileSize)})
	require.NoError(t, err)
	return f
}

// A string table that cannot be read is an error, as it is for the standard library, and not
// a symbol table without the symbols.
func TestFindExeSymbolsStringTableReadError(t *testing.T) {
	selfPath := filepath.Join(runtime.GOROOT(), "bin", "go")
	for _, tc := range []struct {
		name    string
		section string
		paths   []string
	}{
		{"symtab", ".strtab", []string{selfPath, os.Args[0]}},
		{"dynsym", ".dynstr", []string{"/bin/sh", "/bin/ls", "/usr/bin/env"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f *elf.File
			for _, path := range tc.paths {
				if f = openWithUnreadableSection(t, path, tc.section); f != nil {
					break
				}
			}
			if f == nil {
				t.Skip("no executable with a " + tc.section + " section found")
			}
			_, wantErr := referenceFindExeSymbols(t, f, []string{"runtime.mallocgc", "malloc"})
			require.Error(t, wantErr, "the standard library fails")

			_, err := FindExeSymbols(f, []string{"runtime.mallocgc", "malloc"})
			require.Error(t, err)
			assert.ErrorIs(t, err, errInjected)
		})
	}
}

// elfFixture writes a small ELF file with the symbols "sym_<i>" for i < count, to test the
// layouts the executables of the machine of the test do not have.
func elfFixture(t *testing.T, class elf.Class, order binary.ByteOrder, compressed bool, count int) []byte {
	t.Helper()
	strtab := []byte{0}
	var symtab bytes.Buffer
	write := func(v any) { require.NoError(t, binary.Write(&symtab, order, v)) }
	if class == elf.ELFCLASS64 {
		write(elf.Sym64{})
	} else {
		write(elf.Sym32{})
	}
	for i := range count {
		nameOff := uint32(len(strtab))
		strtab = append(strtab, []byte(fmt.Sprintf("sym_%d", i))...)
		strtab = append(strtab, 0)
		info := byte(elf.STB_GLOBAL<<4) | byte(elf.STT_FUNC)
		if class == elf.ELFCLASS64 {
			write(elf.Sym64{Name: nameOff, Info: info, Shndx: 1, Value: 0x1000 + uint64(i)*16, Size: 8})
		} else {
			write(elf.Sym32{Name: nameOff, Info: info, Shndx: 1, Value: 0x1000 + uint32(i)*16, Size: 8})
		}
	}
	shstrtab := []byte("\x00.symtab\x00.strtab\x00.shstrtab\x00")

	// contents of the sections as they are in the file
	pack := func(raw []byte) ([]byte, uint64) {
		if !compressed {
			return raw, 0
		}
		var b bytes.Buffer
		if class == elf.ELFCLASS64 {
			require.NoError(t, binary.Write(&b, order, elf.Chdr64{Type: uint32(elf.COMPRESS_ZLIB), Size: uint64(len(raw)), Addralign: 1}))
		} else {
			require.NoError(t, binary.Write(&b, order, elf.Chdr32{Type: uint32(elf.COMPRESS_ZLIB), Size: uint32(len(raw)), Addralign: 1}))
		}
		z := zlib.NewWriter(&b)
		_, err := z.Write(raw)
		require.NoError(t, err)
		require.NoError(t, z.Close())
		return b.Bytes(), uint64(elf.SHF_COMPRESSED)
	}
	symData, symFlags := pack(symtab.Bytes())
	strData, strFlags := pack(strtab)

	ehSize, shSize, symEnt := 64, 64, elf.Sym64Size
	if class == elf.ELFCLASS32 {
		ehSize, shSize, symEnt = 52, 40, elf.Sym32Size
	}
	symOff := ehSize
	strOff := symOff + len(symData)
	shstrOff := strOff + len(strData)
	shOff := shstrOff + len(shstrtab)

	var out bytes.Buffer
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB)}
	if order == binary.BigEndian {
		ident[5] = byte(elf.ELFDATA2MSB)
	}
	ident[6] = byte(elf.EV_CURRENT)
	put := func(v any) { require.NoError(t, binary.Write(&out, order, v)) }
	if class == elf.ELFCLASS64 {
		put(elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
			Shoff: uint64(shOff), Ehsize: uint16(ehSize), Shentsize: uint16(shSize), Shnum: 4, Shstrndx: 3})
	} else {
		put(elf.Header32{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_386), Version: uint32(elf.EV_CURRENT),
			Shoff: uint32(shOff), Ehsize: uint16(ehSize), Shentsize: uint16(shSize), Shnum: 4, Shstrndx: 3})
	}
	out.Write(symData)
	out.Write(strData)
	out.Write(shstrtab)
	section := func(name uint32, typ elf.SectionType, flags uint64, off, size int, link uint32, entsize int) {
		if class == elf.ELFCLASS64 {
			put(elf.Section64{Name: name, Type: uint32(typ), Flags: flags, Off: uint64(off), Size: uint64(size), Link: link, Addralign: 1, Entsize: uint64(entsize)})
		} else {
			put(elf.Section32{Name: name, Type: uint32(typ), Flags: uint32(flags), Off: uint32(off), Size: uint32(size), Link: link, Addralign: 1, Entsize: uint32(entsize)})
		}
	}
	section(0, elf.SHT_NULL, 0, 0, 0, 0, 0)
	section(1, elf.SHT_SYMTAB, symFlags, symOff, len(symData), 2, symEnt)
	section(9, elf.SHT_STRTAB, strFlags, strOff, len(strData), 0, 0)
	section(17, elf.SHT_STRTAB, 0, shstrOff, len(shstrtab), 0, 0)
	return out.Bytes()
}

// The streaming lookup returns what the standard library does for every layout of a symbol table.
func TestFindExeSymbolsELFFormats(t *testing.T) {
	for _, class := range []elf.Class{elf.ELFCLASS64, elf.ELFCLASS32} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			for _, compressed := range []bool{false, true} {
				name := fmt.Sprintf("%v/%v/compressed=%v", class, order, compressed)
				t.Run(name, func(t *testing.T) {
					// more entries than one chunk, so that the chunk boundary is crossed
					data := elfFixture(t, class, order, compressed, symChunkEntries*2+5)
					f, err := elf.NewFile(bytes.NewReader(data))
					require.NoError(t, err)
					names := []string{"sym_0", "sym_1023", "sym_1024", "sym_2052", "sym_9999"}
					want, wantErr := referenceFindExeSymbols(t, f, names)
					require.NoError(t, wantErr)
					require.Len(t, want, 4)
					got, err := FindExeSymbols(f, names)
					require.NoError(t, err)
					assert.Equal(t, want, got)
				})
			}
		}
	}
}

func TestForEachELFSymbolNoTable(t *testing.T) {
	f := openSelf(t)
	err := forEachELFSymbol(f, elf.SHT_SYMTAB+100, func(*elfSymbol) { t.Fatal("no symbol expected") })
	assert.ErrorIs(t, err, elf.ErrNoSymbols)
}

// The result for a name must not depend on the other names of the same lookup, as a lookup
// serves several groups of probes at once.
func TestFindExeSymbolsIndependentOfOtherNames(t *testing.T) {
	f := openSelf(t)

	only, err := FindExeSymbols(f, []string{"runtime.mallocgc"})
	require.NoError(t, err)
	require.Contains(t, only, "runtime.mallocgc")
	for _, names := range [][]string{
		{"runtime.mallocgc", "runtime.newobject", "no.such.symbol"},
		{"no.such.symbol", "runtime.newobject", "runtime.mallocgc", "runtime.mallocgc"},
	} {
		got, err := FindExeSymbols(f, names)
		require.NoError(t, err)
		assert.Equal(t, only["runtime.mallocgc"], got["runtime.mallocgc"], "names %v", names)
		assert.NotContains(t, got, "no.such.symbol")
	}
}

// countReads counts the reads of the file.
type countReads struct {
	r     io.ReaderAt
	reads int
}

func (c *countReads) ReadAt(p []byte, off int64) (int, error) {
	c.reads++
	return c.r.ReadAt(p, off)
}

// A lookup scans each table once, however many names it gets: the count of reads does not grow
// with the count of names.
func TestFindExeSymbolsOneScanForManyNames(t *testing.T) {
	data := elfFixture(t, elf.ELFCLASS64, binary.LittleEndian, false, symChunkEntries*3+7)
	reads := func(names []string) int {
		c := &countReads{r: bytes.NewReader(data)}
		f, err := elf.NewFile(c)
		require.NoError(t, err)
		c.reads = 0
		got, err := FindExeSymbols(f, names)
		require.NoError(t, err)
		assert.Len(t, got, len(names))
		return c.reads
	}

	var many []string
	for i := range 500 {
		many = append(many, fmt.Sprintf("sym_%d", i*6))
	}
	one := reads(many[:1])
	require.Positive(t, one)
	assert.Equal(t, one, reads(many))
}
