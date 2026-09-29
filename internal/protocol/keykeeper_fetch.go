package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// KeyKeeperRecord represents a single record returned by fetch operations.
type KeyKeeperRecord struct {
	RecordID         [16]byte
	KemCiphertext    []byte
	EncryptedPayload []byte
	Timestamp        uint64
}

// KeyKeeperFetchRequest is sent to retrieve all unclassified (non-permanent) records for a username.
type KeyKeeperFetchRequest struct {
	Username []byte
}

func (k *KeyKeeperFetchRequest) MarshalBinary() ([]byte, error) {
	if k.Username == nil {
		return nil, errors.New("protocol: KeyKeeperFetchRequest contains nil slices")
	}

	username_len := uint64(len(k.Username))

	// 1 (op) + 8 (len) + data + 16 (checksum)
	total_size := 1 + 8 + int(username_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_KEYKEEPER_FETCH
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], k.Username)
	offset += int(username_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperFetchRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (len) + 16 (checksum) = 25 bytes
	const min_size = 25
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperFetchRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperFetchRequest")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_FETCH {
		return errors.New("protocol: invalid App OpCode for KeyKeeperFetchRequest")
	}

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Username length")
	}
	username_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if username_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading Username data")
	}
	k.Username = make([]byte, int(username_len))
	copy(k.Username, data[offset:offset+int(username_len)])
	offset += int(username_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperFetchRequest")
	}

	return nil
}

// KeyKeeperFetchResponse returns an array of unclassified records.
type KeyKeeperFetchResponse struct {
	StatusCode uint8
	Records    []KeyKeeperRecord
}

func (k *KeyKeeperFetchResponse) MarshalBinary() ([]byte, error) {
	if k.Records == nil {
		k.Records = []KeyKeeperRecord{}
	}

	records_count := uint64(len(k.Records))
	records_data_size := 0
	for i := 0; i < len(k.Records); i++ {
		rec := &k.Records[i]
		if rec.KemCiphertext == nil || rec.EncryptedPayload == nil {
			return nil, errors.New("protocol: KeyKeeperRecord contains nil slices")
		}
		records_data_size += 16 + 8 + len(rec.KemCiphertext) + 8 + len(rec.EncryptedPayload) + 8
	}

	// 1 (op) + 1 (status) + 8 (count) + records_data_size + 16 (checksum)
	total_size := 1 + 1 + 8 + records_data_size + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_KEYKEEPER_FETCH
	offset += 1

	buf[offset] = k.StatusCode
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], records_count)
	offset += 8

	for i := 0; i < len(k.Records); i++ {
		rec := &k.Records[i]

		copy(buf[offset:offset+16], rec.RecordID[:])
		offset += 16

		kem_len := uint64(len(rec.KemCiphertext))
		binary.BigEndian.PutUint64(buf[offset:offset+8], kem_len)
		offset += 8
		copy(buf[offset:offset+int(kem_len)], rec.KemCiphertext)
		offset += int(kem_len)

		enc_len := uint64(len(rec.EncryptedPayload))
		binary.BigEndian.PutUint64(buf[offset:offset+8], enc_len)
		offset += 8
		copy(buf[offset:offset+int(enc_len)], rec.EncryptedPayload)
		offset += int(enc_len)

		binary.BigEndian.PutUint64(buf[offset:offset+8], rec.Timestamp)
		offset += 8
	}

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperFetchResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 1 (status) + 8 (count) + 16 (checksum) = 26 bytes
	const min_size = 26
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperFetchResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperFetchResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_FETCH {
		return errors.New("protocol: invalid App OpCode for KeyKeeperFetchResponse")
	}

	k.StatusCode = data[offset]
	offset += 1

	records_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	// Pre-allocation bound: each record needs at least 16 (id) + 8 + 8 + 8 (three length/timestamp fields) = 40 bytes.
	if records_count > uint64(payload_length-offset)/40 {
		return errors.New("protocol: KeyKeeperFetchResponse record count exceeds payload size")
	}

	k.Records = make([]KeyKeeperRecord, int(records_count))
	for i := uint64(0); i < records_count; i++ {
		rec := &k.Records[i]

		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading RecordID")
		}
		copy(rec.RecordID[:], data[offset:offset+16])
		offset += 16

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading KemCiphertext length")
		}
		kem_len := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		if kem_len > uint64(payload_length-offset) {
			return errors.New("protocol: underflow reading KemCiphertext data")
		}
		rec.KemCiphertext = make([]byte, int(kem_len))
		copy(rec.KemCiphertext, data[offset:offset+int(kem_len)])
		offset += int(kem_len)

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading EncryptedPayload length")
		}
		enc_len := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		if enc_len > uint64(payload_length-offset) {
			return errors.New("protocol: underflow reading EncryptedPayload data")
		}
		rec.EncryptedPayload = make([]byte, int(enc_len))
		copy(rec.EncryptedPayload, data[offset:offset+int(enc_len)])
		offset += int(enc_len)

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading Timestamp")
		}
		rec.Timestamp = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperFetchResponse")
	}

	return nil
}
