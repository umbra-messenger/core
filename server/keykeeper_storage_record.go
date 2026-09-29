package server

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// KeyKeeperStorageRecord is the server-side storage representation of a KeyKeeper record.
type KeyKeeperStorageRecord struct {
	RecordID            [16]byte
	DestinationUsername []byte
	KemCiphertext       []byte
	EncryptedPayload    []byte
	Timestamp           uint64
	IsPermanent         bool
}

func (k *KeyKeeperStorageRecord) MarshalBinary() ([]byte, error) {
	if k.DestinationUsername == nil || k.KemCiphertext == nil || k.EncryptedPayload == nil {
		return nil, errors.New("server: KeyKeeperStorageRecord contains nil slices")
	}

	dest_len := uint64(len(k.DestinationUsername))
	kem_len := uint64(len(k.KemCiphertext))
	enc_len := uint64(len(k.EncryptedPayload))

	// 16 (id) + 8 (len1) + d1 + 8 (len2) + d2 + 8 (len3) + d3 + 8 (ts) + 1 (bool) + 16 (checksum)
	total_size := 16 + 8 + int(dest_len) + 8 + int(kem_len) + 8 + int(enc_len) + 8 + 1 + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], k.RecordID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], dest_len)
	offset += 8
	copy(buf[offset:offset+int(dest_len)], k.DestinationUsername)
	offset += int(dest_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], kem_len)
	offset += 8
	copy(buf[offset:offset+int(kem_len)], k.KemCiphertext)
	offset += int(kem_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_len)
	offset += 8
	copy(buf[offset:offset+int(enc_len)], k.EncryptedPayload)
	offset += int(enc_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], k.Timestamp)
	offset += 8

	if k.IsPermanent {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperStorageRecord) UnmarshalBinary(data []byte) error {
	// Min size: 16 (id) + 8*3 (length prefixes) + 8 (ts) + 1 (bool) + 16 (checksum) = 65 bytes
	const min_size = 65
	if len(data) < min_size {
		return errors.New("server: data too short for KeyKeeperStorageRecord")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("server: checksum mismatch in KeyKeeperStorageRecord")
	}

	offset := 0

	copy(k.RecordID[:], data[offset:offset+16])
	offset += 16

	if offset+8 > payload_length {
		return errors.New("server: underflow reading DestinationUsername length")
	}
	dest_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if dest_len > uint64(payload_length-offset) {
		return errors.New("server: underflow reading DestinationUsername data")
	}
	k.DestinationUsername = make([]byte, int(dest_len))
	copy(k.DestinationUsername, data[offset:offset+int(dest_len)])
	offset += int(dest_len)

	if offset+8 > payload_length {
		return errors.New("server: underflow reading KemCiphertext length")
	}
	kem_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if kem_len > uint64(payload_length-offset) {
		return errors.New("server: underflow reading KemCiphertext data")
	}
	k.KemCiphertext = make([]byte, int(kem_len))
	copy(k.KemCiphertext, data[offset:offset+int(kem_len)])
	offset += int(kem_len)

	if offset+8 > payload_length {
		return errors.New("server: underflow reading EncryptedPayload length")
	}
	enc_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if enc_len > uint64(payload_length-offset) {
		return errors.New("server: underflow reading EncryptedPayload data")
	}
	k.EncryptedPayload = make([]byte, int(enc_len))
	copy(k.EncryptedPayload, data[offset:offset+int(enc_len)])
	offset += int(enc_len)

	if offset+8 > payload_length {
		return errors.New("server: underflow reading Timestamp")
	}
	k.Timestamp = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+1 > payload_length {
		return errors.New("server: underflow reading IsPermanent")
	}
	k.IsPermanent = data[offset] == 1
	offset += 1

	if offset != payload_length {
		return errors.New("server: unexpected trailing data in KeyKeeperStorageRecord")
	}

	return nil
}
