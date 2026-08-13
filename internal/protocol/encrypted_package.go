package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// EncryptedPackage represents a serialized AEAD output containing a nonce, ciphertext, and tag.
type EncryptedPackage struct {
	Nonce      [12]byte
	Ciphertext []byte
	Tag        [16]byte
}

func (e *EncryptedPackage) MarshalBinary() ([]byte, error) {
	if e.Ciphertext == nil {
		return nil, errors.New("protocol: Ciphertext is nil")
	}
	ciphertext_length := uint64(len(e.Ciphertext))
	total_size := 12 + 8 + int(ciphertext_length) + 16 + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+12], e.Nonce[:])
	offset += 12

	binary.BigEndian.PutUint64(buf[offset:offset+8], ciphertext_length)
	offset += 8

	copy(buf[offset:offset+int(ciphertext_length)], e.Ciphertext)
	offset += int(ciphertext_length)

	copy(buf[offset:offset+16], e.Tag[:])
	offset += 16

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (e *EncryptedPackage) UnmarshalBinary(data []byte) error {
	const min_size = 12 + 8 + 16 + 16 // 52 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for EncryptedPackage")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	copy(e.Nonce[:], data[offset:offset+12])
	offset += 12

	ciphertext_length := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+int(ciphertext_length)+16 > payload_length {
		return errors.New("protocol: underflow reading Ciphertext and Tag")
	}

	e.Ciphertext = make([]byte, ciphertext_length)
	copy(e.Ciphertext, data[offset:offset+int(ciphertext_length)])
	offset += int(ciphertext_length)

	copy(e.Tag[:], data[offset:offset+16])
	offset += 16

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
