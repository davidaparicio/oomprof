// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Portions of this file are derived from Go's cmd/internal/buildid package.

package oomprof

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"io"
	"os"
)

var (
	elfGoNote  = []byte("Go\x00\x00")
	elfGNUNote = []byte("GNU\x00")
)

const (
	elfGoBuildIDTag = 4
	gnuBuildIDTag   = 3
)

// readBuildIDFromELF reads the build ID from an already-opened ELF binary.
// This is adapted from Go's cmd/internal/buildid package.
func readBuildIDFromELF(f *os.File, ef *elf.File) (string, error) {
	var gnu string
	for _, p := range ef.Progs {
		if p.Type != elf.PT_NOTE || p.Filesz < 16 {
			continue
		}

		// Read the note data from the segment
		_, err := f.Seek(int64(p.Off), io.SeekStart)
		if err != nil {
			return "", err
		}

		note := make([]byte, p.Filesz)
		_, err = io.ReadFull(f, note)
		if err != nil {
			return "", err
		}

		filesz := p.Filesz
		off := p.Off
		for filesz >= 16 {
			nameSize := ef.ByteOrder.Uint32(note)
			valSize := ef.ByteOrder.Uint32(note[4:])
			tag := ef.ByteOrder.Uint32(note[8:])
			nname := note[12:16]

			// Check for Go build ID
			if nameSize == 4 && 16+valSize <= uint32(len(note)) && tag == elfGoBuildIDTag && bytes.Equal(nname, elfGoNote) {
				return string(note[16 : 16+valSize]), nil
			}

			// Check for GNU build ID
			if nameSize == 4 && 16+valSize <= uint32(len(note)) && tag == gnuBuildIDTag && bytes.Equal(nname, elfGNUNote) {
				// GNU build IDs are binary data, encode as hex
				gnu = hex.EncodeToString(note[16 : 16+valSize])
			}

			nameSize = (nameSize + 3) &^ 3
			valSize = (valSize + 3) &^ 3
			notesz := uint64(12 + nameSize + valSize)
			if filesz <= notesz {
				break
			}
			off += notesz
			align := p.Align
			if align != 0 {
				alignedOff := (off + align - 1) &^ (align - 1)
				notesz += alignedOff - off
				off = alignedOff
			}
			filesz -= notesz
			note = note[notesz:]
		}
	}

	// If we didn't find a Go note, use a GNU note if available.
	// This is what gccgo uses.
	if gnu != "" {
		return gnu, nil
	}

	// No note. Treat as successful but build ID empty.
	return "", nil
}
