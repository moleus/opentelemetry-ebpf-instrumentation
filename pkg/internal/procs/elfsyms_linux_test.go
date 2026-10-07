//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"bytes"
	"debug/elf"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// referenceFindExeSymbols is the lookup as it was before the tables were streamed: it loads both
// tables with the standard library. The streaming lookup must return the same result.
func referenceFindExeSymbols(t testing.TB, f *elf.File, names, substrings []string, types ...elf.SymType) (map[string]Sym, map[string]Sym) {
	t.Helper()
	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}
	exact := map[string]Sym{}
	sub := map[string]Sym{}
	collect := func(syms []elf.Symbol) {
		for _, s := range syms {
			isWanted := false
			for _, ty := range types {
				isWanted = isWanted || ty == elf.ST_TYPE(s.Info)
			}
			if !isWanted {
				continue
			}
			for _, n := range names {
				if s.Name == n {
					exact[n] = resolveSymbol(f, s)
				}
			}
			for _, n := range substrings {
				if strings.Contains(s.Name, n) {
					sub[n] = resolveSymbol(f, s)
				}
			}
		}
	}
	syms, err := f.Symbols()
	if err == nil {
		collect(syms)
	}
	dyn, err := f.DynamicSymbols()
	if err == nil {
		collect(dyn)
	}
	return exact, sub
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
	substrings := []string{"TestFindExeSymbols", "runtime.mallocgc", "no.such.substring"}

	for _, types := range [][]elf.SymType{nil, {elf.STT_OBJECT}, {elf.STT_FUNC, elf.STT_OBJECT}} {
		wantExact, wantSub := referenceFindExeSymbols(t, f, names, substrings, types...)
		gotExact, gotSub, err := FindExeSymbolsByNameAndSubstring(f, names, substrings, types...)
		require.NoError(t, err)
		assert.Equal(t, wantExact, gotExact, "exact, types %v", types)
		assert.Equal(t, wantSub, gotSub, "substring, types %v", types)
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
		wantExact, wantSub := referenceFindExeSymbols(t, f, names, []string{"mem", "str"})
		gotExact, gotSub, err := FindExeSymbolsByNameAndSubstring(f, names, []string{"mem", "str"})
		_ = f.Close()
		require.NoError(t, err)
		assert.Equal(t, wantExact, gotExact, path)
		assert.Equal(t, wantSub, gotSub, path)
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
	oldBytes := measure(func() { referenceFindExeSymbols(t, f, names, nil) })
	newBytes := measure(func() {
		_, _, err := FindExeSymbolsByNameAndSubstring(f, names, nil)
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
}

func TestForEachELFSymbolNoTable(t *testing.T) {
	f := openSelf(t)
	err := forEachELFSymbol(f, elf.SHT_SYMTAB+100, func(*elfSymbol) { t.Fatal("no symbol expected") })
	assert.ErrorIs(t, err, elf.ErrNoSymbols)
}

// The result for a substring must not depend on the other substrings of the same lookup, as
// a lookup serves several groups of probes at once.
func TestFindExeSymbolsOverlappingSubstrings(t *testing.T) {
	f := openSelf(t)

	_, subA, err := FindExeSymbolsByNameAndSubstring(f, nil, []string{"runtime.mallocgc"})
	require.NoError(t, err)
	_, subB, err := FindExeSymbolsByNameAndSubstring(f, nil, []string{"mallocgc"})
	require.NoError(t, err)
	_, both1, err := FindExeSymbolsByNameAndSubstring(f, nil, []string{"runtime.mallocgc", "mallocgc"})
	require.NoError(t, err)
	_, both2, err := FindExeSymbolsByNameAndSubstring(f, nil, []string{"mallocgc", "runtime.mallocgc"})
	require.NoError(t, err)

	require.NotEmpty(t, subA)
	require.NotEmpty(t, subB)
	for _, both := range []map[string]Sym{both1, both2} {
		assert.Equal(t, subA["runtime.mallocgc"], both["runtime.mallocgc"])
		assert.Equal(t, subB["mallocgc"], both["mallocgc"])
	}
}
