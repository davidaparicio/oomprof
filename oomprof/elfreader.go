// Copyright 2022-2025 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oomprof

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// SymbolInfo represents information about a symbol in an ELF file.
type SymbolInfo struct {
	Name    string
	Address uint64
}

// ELFReader is the interface for reading ELF files.
// This allows users to provide their own optimized implementation
// (e.g., using ebpf-profiler's pfelf) while oomprof provides a
// default implementation using debug/elf.
type ELFReader interface {
	// Open opens an ELF file for reading.
	Open(path string) (ELFFile, error)
}

// ELFFile represents an open ELF file.
type ELFFile interface {
	// Close closes the ELF file.
	Close() error

	// GetBuildID returns the build ID of the ELF file.
	GetBuildID() (string, error)

	// GoVersion returns the Go version the binary was built with.
	// Returns empty string if not a Go binary or version cannot be determined.
	GoVersion() (string, error)

	// LookupSymbol looks up a symbol by name and returns its address.
	// Returns an error if the symbol is not found.
	LookupSymbol(name string) (SymbolInfo, error)
}

// defaultELFReader is the default implementation using debug/elf.
type defaultELFReader struct{}

// DefaultELFReader returns the default ELF reader implementation using debug/elf.
func DefaultELFReader() ELFReader {
	return &defaultELFReader{}
}

func (r *defaultELFReader) Open(path string) (ELFFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	elfFile, err := elf.NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	return &defaultELFFile{
		file:    f,
		elfFile: elfFile,
	}, nil
}

// defaultELFFile implements ELFFile using debug/elf.
type defaultELFFile struct {
	file    *os.File
	elfFile *elf.File
}

func (f *defaultELFFile) Close() error {
	f.elfFile.Close()
	return f.file.Close()
}

func (f *defaultELFFile) GetBuildID() (string, error) {
	// Try to find build ID in notes sections
	for _, prog := range f.elfFile.Progs {
		if prog.Type != elf.PT_NOTE {
			continue
		}

		notes, err := readNotes(prog.Open(), f.elfFile.ByteOrder)
		if err != nil {
			continue
		}

		for _, note := range notes {
			if note.Type == 3 && note.Name == "GNU" { // NT_GNU_BUILD_ID = 3
				return fmt.Sprintf("%x", note.Desc), nil
			}
		}
	}

	// Try .note.go.buildid section for Go binaries
	if sec := f.elfFile.Section(".note.go.buildid"); sec != nil {
		data, err := sec.Data()
		if err == nil && len(data) > 16 {
			// Skip the note header (16 bytes) and read the build ID
			return string(data[16:]), nil
		}
	}

	return "", errors.New("build ID not found")
}

func (f *defaultELFFile) GoVersion() (string, error) {
	// Look for .go.buildinfo section (Go 1.18+)
	if sec := f.elfFile.Section(".go.buildinfo"); sec != nil {
		data, err := sec.Data()
		if err != nil {
			return "", err
		}

		// Parse buildinfo header
		if len(data) < 32 {
			return "", errors.New("buildinfo section too small")
		}

		// The buildinfo format has magic bytes and pointers
		// For simplicity, we'll look for the version string pattern
		versionData := string(data)
		if idx := strings.Index(versionData, "\xfa\xff\xff\xff\x00"); idx >= 0 && idx+5 < len(versionData) {
			// Read version length and string after the magic pattern
			remaining := versionData[idx+5:]
			if len(remaining) > 0 {
				versionLen := int(remaining[0])
				if len(remaining) > versionLen {
					version := remaining[1 : versionLen+1]
					if strings.HasPrefix(version, "go") {
						return version, nil
					}
				}
			}
		}
	}

	// Fallback: look for version in .rodata section (older Go versions)
	if sec := f.elfFile.Section(".rodata"); sec != nil {
		data, err := sec.Data()
		if err == nil {
			rodataStr := string(data)
			// Look for go version string pattern
			if idx := strings.Index(rodataStr, "go1."); idx >= 0 {
				// Extract version (e.g., "go1.20.5")
				end := idx + 4 // Start after "go1."
				for end < len(rodataStr) && (rodataStr[end] >= '0' && rodataStr[end] <= '9' || rodataStr[end] == '.') {
					end++
				}
				if end > idx+4 {
					return rodataStr[idx:end], nil
				}
			}
		}
	}

	return "", errors.New("Go version not found")
}

func (f *defaultELFFile) LookupSymbol(name string) (SymbolInfo, error) {
	symbols, err := f.elfFile.Symbols()
	if err != nil {
		// Try dynamic symbols if regular symbols fail
		symbols, err = f.elfFile.DynamicSymbols()
		if err != nil {
			return SymbolInfo{}, fmt.Errorf("failed to read symbols: %w", err)
		}
	}

	for _, sym := range symbols {
		if sym.Name == name {
			return SymbolInfo{
				Name:    sym.Name,
				Address: sym.Value,
			}, nil
		}
	}

	return SymbolInfo{}, fmt.Errorf("symbol %s not found", name)
}

// note represents an ELF note.
type note struct {
	Name string
	Type uint32
	Desc []byte
}

// readNotes reads ELF notes from a reader.
func readNotes(r io.Reader, order binary.ByteOrder) ([]note, error) {
	var notes []note

	for {
		var nameSize, descSize, noteType uint32

		// Read note header
		if err := binary.Read(r, order, &nameSize); err != nil {
			if err == io.EOF {
				break
			}
			return notes, err
		}
		if err := binary.Read(r, order, &descSize); err != nil {
			return notes, err
		}
		if err := binary.Read(r, order, &noteType); err != nil {
			return notes, err
		}

		// Read name (padded to 4 bytes)
		namePadded := (nameSize + 3) &^ 3
		nameBytes := make([]byte, namePadded)
		if _, err := io.ReadFull(r, nameBytes); err != nil {
			return notes, err
		}

		name := string(nameBytes[:nameSize])
		if nameSize > 0 && name[nameSize-1] == 0 {
			name = name[:nameSize-1]
		}

		// Read descriptor (padded to 4 bytes)
		descPadded := (descSize + 3) &^ 3
		desc := make([]byte, descPadded)
		if _, err := io.ReadFull(r, desc); err != nil {
			return notes, err
		}

		notes = append(notes, note{
			Name: name,
			Type: noteType,
			Desc: desc[:descSize],
		})
	}

	return notes, nil
}

// globalELFReader holds the current ELF reader implementation.
var globalELFReader ELFReader = DefaultELFReader()

// SetELFReader sets the global ELF reader implementation.
// This allows users to provide their own optimized implementation.
func SetELFReader(reader ELFReader) {
	globalELFReader = reader
}

// GetELFReader returns the current ELF reader implementation.
func GetELFReader() ELFReader {
	return globalELFReader
}