package crypt

import (
	"hash/crc32"
)

// Distinct prefix bytes for the four CRC32 rounds to ensure independence.
var (
	checksum_prefix_1 = []byte{0xA1, 0xB2, 0xC3, 0xD4}
	checksum_prefix_2 = []byte{0xE5, 0xF6, 0x07, 0x18}
	checksum_prefix_3 = []byte{0x29, 0x3A, 0x4B, 0x5C}
	checksum_prefix_4 = []byte{0x6D, 0x7E, 0x8F, 0x90}
)

// checksum computes a 16-byte integrity checksum using four CRC32 (IEEE) rounds.
// This is used exclusively by the protocol package for envelope integrity verification.
func Checksum(data []byte) [16]byte {
	var out [16]byte

	// Round 1
	h1 := crc32.NewIEEE()
	h1.Write(checksum_prefix_1)
	h1.Write(data)
	sum1 := h1.Sum32()
	out[0] = byte(sum1 >> 24)
	out[1] = byte(sum1 >> 16)
	out[2] = byte(sum1 >> 8)
	out[3] = byte(sum1)

	// Round 2
	h2 := crc32.NewIEEE()
	h2.Write(checksum_prefix_2)
	h2.Write(data)
	sum2 := h2.Sum32()
	out[4] = byte(sum2 >> 24)
	out[5] = byte(sum2 >> 16)
	out[6] = byte(sum2 >> 8)
	out[7] = byte(sum2)

	// Round 3
	h3 := crc32.NewIEEE()
	h3.Write(checksum_prefix_3)
	h3.Write(data)
	sum3 := h3.Sum32()
	out[8] = byte(sum3 >> 24)
	out[9] = byte(sum3 >> 16)
	out[10] = byte(sum3 >> 8)
	out[11] = byte(sum3)

	// Round 4
	h4 := crc32.NewIEEE()
	h4.Write(checksum_prefix_4)
	h4.Write(data)
	sum4 := h4.Sum32()
	out[12] = byte(sum4 >> 24)
	out[13] = byte(sum4 >> 16)
	out[14] = byte(sum4 >> 8)
	out[15] = byte(sum4)

	return out
}
