package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// KeyKeeperSubmitRecord is a single record within a batch submission.
type KeyKeeperSubmitRecord struct {
	DestinationUsername []byte
	KemCiphertext       []byte
	EncryptedPayload    []byte
}

// KeyKeeperSubmitRequest carries N records for batch submission.
type KeyKeeperSubmitRequest struct {
	Records []KeyKeeperSubmitRecord
}

func (k *KeyKeeperSubmitRequest) MarshalBinary() ([]byte, error) {
	if k.Records == nil {
		k.Records = []KeyKeeperSubmitRecord{}
	}

	records_count := uint64(len(k.Records))
	records_data_size := 0
	for i := 0; i < len(k.Records); i++ {
		rec := &k.Records[i]
		if rec.DestinationUsername == nil || rec.KemCiphertext == nil || rec.EncryptedPayload == nil {
			return nil, errors.New("protocol: KeyKeeperSubmitRecord contains nil slices")
		}
		// 8 (len1) + d1 + 8 (len2) + d2 + 8 (len3) + d3
		records_data_size += 8 + len(rec.DestinationUsername) + 8 + len(rec.KemCiphertext) + 8 + len(rec.EncryptedPayload)
	}

	// 1 (op) + 8 (count) + records_data + 16 (checksum)
	total_size := 1 + 8 + records_data_size + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_KEYKEEPER_SUBMIT
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], records_count)
	offset += 8

	for i := 0; i < len(k.Records); i++ {
		rec := &k.Records[i]

		dest_len := uint64(len(rec.DestinationUsername))
		binary.BigEndian.PutUint64(buf[offset:offset+8], dest_len)
		offset += 8
		copy(buf[offset:offset+int(dest_len)], rec.DestinationUsername)
		offset += int(dest_len)

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
	}

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperSubmitRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (count) + 16 (checksum) = 25 bytes
	const min_size = 25
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperSubmitRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperSubmitRequest")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_SUBMIT {
		return errors.New("protocol: invalid App OpCode for KeyKeeperSubmitRequest")
	}

	records_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	k.Records = make([]KeyKeeperSubmitRecord, records_count)
	for i := uint64(0); i < records_count; i++ {
		rec := &k.Records[i]

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading DestinationUsername length")
		}
		dest_len := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		if offset+int(dest_len) > payload_length {
			return errors.New("protocol: underflow reading DestinationUsername data")
		}
		rec.DestinationUsername = make([]byte, dest_len)
		copy(rec.DestinationUsername, data[offset:offset+int(dest_len)])
		offset += int(dest_len)

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading KemCiphertext length")
		}
		kem_len := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		if offset+int(kem_len) > payload_length {
			return errors.New("protocol: underflow reading KemCiphertext data")
		}
		rec.KemCiphertext = make([]byte, kem_len)
		copy(rec.KemCiphertext, data[offset:offset+int(kem_len)])
		offset += int(kem_len)

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading EncryptedPayload length")
		}
		enc_len := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		if offset+int(enc_len) > payload_length {
			return errors.New("protocol: underflow reading EncryptedPayload data")
		}
		rec.EncryptedPayload = make([]byte, enc_len)
		copy(rec.EncryptedPayload, data[offset:offset+int(enc_len)])
		offset += int(enc_len)
	}

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperSubmitRequest")
	}

	return nil
}

// KeyKeeperSubmitResponse returns the record IDs for all submitted records.
type KeyKeeperSubmitResponse struct {
	StatusCode uint8
	RecordIDs  [][16]byte
}

func (k *KeyKeeperSubmitResponse) MarshalBinary() ([]byte, error) {
	if k.RecordIDs == nil {
		k.RecordIDs = [][16]byte{}
	}

	ids_count := uint64(len(k.RecordIDs))

	// 1 (op) + 1 (status) + 8 (count) + count*16 + 16 (checksum)
	total_size := 1 + 1 + 8 + int(ids_count)*16 + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_KEYKEEPER_SUBMIT
	offset += 1

	buf[offset] = k.StatusCode
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], ids_count)
	offset += 8

	for i := 0; i < len(k.RecordIDs); i++ {
		copy(buf[offset:offset+16], k.RecordIDs[i][:])
		offset += 16
	}

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperSubmitResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 1 (status) + 8 (count) + 16 (checksum) = 26 bytes
	const min_size = 26
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperSubmitResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperSubmitResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_SUBMIT {
		return errors.New("protocol: invalid App OpCode for KeyKeeperSubmitResponse")
	}

	k.StatusCode = data[offset]
	offset += 1

	ids_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	k.RecordIDs = make([][16]byte, ids_count)
	for i := uint64(0); i < ids_count; i++ {
		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading RecordID data")
		}
		copy(k.RecordIDs[i][:], data[offset:offset+16])
		offset += 16
	}

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperSubmitResponse")
	}

	return nil
}
