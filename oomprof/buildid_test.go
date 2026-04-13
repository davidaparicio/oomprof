package oomprof

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildELFWithNotes creates a minimal ELF file containing the given PT_NOTE data.
func buildELFWithNotes(t *testing.T, notes []byte) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "elf-*")
	require.NoError(t, err)
	defer f.Close()

	// Minimal ELF64 little-endian header.
	var hdr [64]byte
	copy(hdr[0:4], "\x7fELF")            // magic
	hdr[4] = 2                            // 64-bit
	hdr[5] = 1                            // little-endian
	hdr[6] = 1                            // ELF version
	binary.LittleEndian.PutUint16(hdr[16:], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(hdr[18:], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(hdr[20:], 1)  // EV_CURRENT
	binary.LittleEndian.PutUint16(hdr[52:], 64) // e_ehsize
	binary.LittleEndian.PutUint16(hdr[54:], 56) // e_phentsize

	// One program header (PT_NOTE) right after the ELF header.
	phOff := uint64(64)
	noteOff := phOff + 56
	binary.LittleEndian.PutUint64(hdr[32:], phOff) // e_phoff
	binary.LittleEndian.PutUint16(hdr[56:], 1)     // e_phnum

	// ELF64 program header: PT_NOTE.
	// Layout: p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8) p_memsz(8) p_align(8)
	var ph [56]byte
	binary.LittleEndian.PutUint32(ph[0:], uint32(elf.PT_NOTE))
	binary.LittleEndian.PutUint64(ph[8:], noteOff)             // p_offset
	binary.LittleEndian.PutUint64(ph[32:], uint64(len(notes))) // p_filesz
	binary.LittleEndian.PutUint64(ph[48:], 4)                  // p_align

	_, err = f.Write(hdr[:])
	require.NoError(t, err)
	_, err = f.Write(ph[:])
	require.NoError(t, err)
	_, err = f.Write(notes)
	require.NoError(t, err)

	return f.Name()
}

// makeNote builds an ELF note entry (little-endian, 4-byte aligned).
func makeNote(name []byte, desc []byte, noteType uint32) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(name)))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(desc)))
	_ = binary.Write(&buf, binary.LittleEndian, noteType)
	buf.Write(name)
	// Pad name to 4-byte alignment.
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}
	buf.Write(desc)
	// Pad desc to 4-byte alignment.
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func TestReadBuildID_GoNoteNulTrimmed(t *testing.T) {
	// Simulate a Go build ID note with a trailing NUL byte, which is how the
	// Go compiler stores them in ELF.
	goBuildID := "abcdef1234567890/xyz"
	goNoteValue := []byte(goBuildID + "\x00") // trailing NUL

	note := makeNote(elfGoNote, goNoteValue, elfGoBuildIDTag)
	path := buildELFWithNotes(t, note)

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	ef, err := elf.NewFile(f)
	require.NoError(t, err)
	defer ef.Close()

	got, err := readBuildIDFromELF(f, ef)
	require.NoError(t, err)
	require.Equal(t, goBuildID, got, "trailing NUL byte should be trimmed")
	require.NotContains(t, got, "\x00")
}

func TestReadBuildID_GNUNoteUnchanged(t *testing.T) {
	// GNU build IDs are binary and hex-encoded; they should not be affected.
	raw := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	note := makeNote(elfGNUNote, raw, gnuBuildIDTag)
	path := buildELFWithNotes(t, note)

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	ef, err := elf.NewFile(f)
	require.NoError(t, err)
	defer ef.Close()

	got, err := readBuildIDFromELF(f, ef)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(raw), got)
}
