package crypt

import (
	"encoding/binary"
	"hash/crc32"
)

// Checksum computes a 16-byte integrity checksum over the provided data.
// It uses CRC32 (IEEE polynomial) with four distinct prefix bytes to produce
// four independent 4-byte checksums, concatenated into a 16-byte output.
// This is NOT a cryptographic hash; it is a lightweight integrity check.
func Checksum(data []byte) [16]byte {
	var output [16]byte

	for i := 0; i < 4; i++ {
		h := crc32.NewIEEE()
		h.Write([]byte{byte(i)})
		h.Write(data)
		crc := h.Sum32()
		binary.BigEndian.PutUint32(output[i*4:(i+1)*4], crc)
	}

	return output
}
