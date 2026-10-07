// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/fastelf"
)

func FindProcLanguage(pid app.PID) svc.InstrumentableType {
	maps, err := FindLibMaps(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	// We first check for the languages as cheaply as possible when
	// know they link certain libraries that can tell us the language.
	for _, m := range maps {
		t := instrumentableFromModuleMapSharedLib(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	// We must find the language type from the binary first
	// before resorting to discovery by path or environment variables.
	// For example, a Go application can be called 'node' and we must
	// not identify this application as Node.js.
	filePath, err := resolveProcBinary(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	t := findLanguageFromElf(filePath)

	if t != svc.InstrumentableGeneric {
		return t
	}

	for _, m := range maps {
		t := instrumentableFromModuleMap(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	t = instrumentableFromPath(filePath)
	if t != svc.InstrumentableGeneric {
		return t
	}

	// Last resort to tell Generic from C++ (and maybe others in the future)
	for _, m := range maps {
		t := instrumentableLastResort(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	return svc.InstrumentableGeneric
}

func resolveProcBinary(pid app.PID) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	realPath, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to read process binary: %w", err)
	}

	return fmt.Sprintf("/proc/%d/root%s", pid, realPath), nil
}

func findLanguageFromElf(filePath string) (result svc.InstrumentableType) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("panic while parsing ELF file", "file", filePath, "panic", r)
			result = svc.InstrumentableGeneric
		}
	}()

	ctx, err := fastelf.NewElfContextFromFile(filePath)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	defer ctx.Close()

	if ctx.HasSection(".gopclntab") {
		return svc.InstrumentableGolang
	}

	return matchExeSymbols(ctx)
}

type symbolCollector struct {
	addresses map[string]Sym
	// names are the symbol names to look for. Each is also kept as bytes, to compare it with a name
	// that is read from the file without making a string of every name of the table.
	names   []string
	nameBuf [][]byte
	// matches appends to hits the index of each of the names that the symbol matches.
	matches func(symbol []byte, names []string, nameBuf [][]byte, hits []int) []int
}

func newSymbolCollector(
	addresses map[string]Sym,
	names []string,
	matches func([]byte, []string, [][]byte, []int) []int,
) symbolCollector {
	nameBuf := make([][]byte, len(names))
	for i, n := range names {
		nameBuf[i] = []byte(n)
	}
	return symbolCollector{addresses: addresses, names: names, nameBuf: nameBuf, matches: matches}
}

// collectSymbols reads the symbol table of type tableType and records the symbols that a
// collector matches. It does not load the table into memory, see forEachELFSymbol.
func collectSymbols(f *elf.File, tableType elf.SectionType, collectors []symbolCollector, types ...elf.SymType) error {
	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}
	var hits []int
	err := forEachELFSymbol(f, tableType, func(s *elfSymbol) {
		if !slices.Contains(types, elf.ST_TYPE(s.Info)) {
			return
		}

		name, ok := s.name()
		if !ok {
			return
		}

		var sym *Sym
		for _, collector := range collectors {
			hits = collector.matches(name, collector.names, collector.nameBuf, hits[:0])
			for _, hit := range hits {
				if sym == nil {
					resolvedSym := resolveSymbol(f, elf.Symbol{
						Name:  string(name),
						Info:  s.Info,
						Value: s.Value,
						Size:  s.Size,
					})
					sym = &resolvedSym
				}
				collector.addresses[collector.names[hit]] = *sym
			}
		}
	})
	if errors.Is(err, elf.ErrNoSymbols) {
		return nil
	}
	return err
}

func FindExeSymbols(f *elf.File, symbolNames []string, types ...elf.SymType) (map[string]Sym, error) {
	exactSyms, _, err := FindExeSymbolsByNameAndSubstring(f, symbolNames, nil, types...)
	return exactSyms, err
}

func FindExeSymbolsBySubstring(f *elf.File, symbolSubstrings []string, types ...elf.SymType) (map[string]Sym, error) {
	_, substringSyms, err := FindExeSymbolsByNameAndSubstring(f, nil, symbolSubstrings, types...)
	return substringSyms, err
}

func FindExeSymbolsByNameAndSubstring(f *elf.File, symbolNames, symbolSubstrings []string, types ...elf.SymType) (map[string]Sym, map[string]Sym, error) {
	exactAddresses := map[string]Sym{}
	substringAddresses := map[string]Sym{}
	collectors := []symbolCollector{
		newSymbolCollector(exactAddresses, symbolNames, exactSymbolMatch),
		newSymbolCollector(substringAddresses, symbolSubstrings, substringSymbolMatch),
	}

	// The symbol tables of a large C or C++ binary (a database server, a browser) hold hundreds of
	// thousands of symbols, and this function runs for each group of probes of a binary, so
	// the tables are streamed and not loaded: see forEachELFSymbol.
	if err := collectSymbols(f, elf.SHT_SYMTAB, collectors, types...); err != nil {
		return nil, nil, err
	}

	if err := collectSymbols(f, elf.SHT_DYNSYM, collectors, types...); err != nil {
		return nil, nil, err
	}

	return exactAddresses, substringAddresses, nil
}

func resolveSymbol(f *elf.File, s elf.Symbol) Sym {
	address := s.Value
	var p *elf.Prog

	// Loop over ELF segments.
	for _, prog := range f.Progs {
		// Skip uninteresting segments.
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
			address = s.Value - prog.Vaddr + prog.Off
			p = prog
			break
		}
	}

	return Sym{Name: s.Name, Off: address, Value: s.Value, Len: s.Size, Prog: p}
}

func exactSymbolMatch(symbolName []byte, names []string, _ [][]byte, hits []int) []int {
	for i, n := range names {
		if string(symbolName) == n {
			return append(hits, i)
		}
	}
	return hits
}

// substringSymbolMatch reports every substring that the name contains, so that the result for
// a substring does not depend on the other substrings that are looked up with it.
func substringSymbolMatch(symbolName []byte, _ []string, substringBytes [][]byte, hits []int) []int {
	for i, substring := range substringBytes {
		if bytes.Contains(symbolName, substring) {
			hits = append(hits, i)
		}
	}
	return hits
}

func matchExeSymbols(ctx *fastelf.ElfContext) svc.InstrumentableType {
	isRust := false

	for _, sec := range ctx.Sections {
		if sec == nil {
			continue
		}

		if sec.Type != fastelf.SHT_SYMTAB && sec.Type != fastelf.SHT_DYNSYM {
			continue
		}

		if int(sec.Link) >= len(ctx.Sections) {
			continue
		}

		strtab := ctx.Sections[sec.Link]

		strs, ok := ctx.SectionData(strtab)
		if !ok {
			continue
		}

		symOffset, symEntrySize, symCount, ok := ctx.SymbolTableBounds(sec)
		if !ok {
			continue
		}

		for i := range symCount {
			sym := fastelf.ReadStruct[fastelf.Elf64_Sym](ctx.Data, symOffset+i*symEntrySize)

			if sym == nil ||
				fastelf.SymType(sym.Info) != fastelf.STT_FUNC ||
				sym.Size == 0 ||
				sym.Value == 0 {
				continue
			}

			name := fastelf.GetCStringUnsafe(strs, sym.Name)

			t := instrumentableFromSymbolName(name)

			if t != svc.InstrumentableGeneric {
				if t == svc.InstrumentableRust {
					isRust = true
				} else {
					return t
				}
			}
		}
	}

	if isRust {
		return svc.InstrumentableRust
	}

	return svc.InstrumentableGeneric
}
