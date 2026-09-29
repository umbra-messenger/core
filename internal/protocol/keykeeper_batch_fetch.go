package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// KeyKeeperBatchFetchRequest is sent to retrieve specific permanent records by their IDs.
type KeyKeeperBatchFetchRequest struct {
	Username  []byte
	RecordIDs [][16]byte
	Signature []byte
}

func (k *KeyKeeperBatchFetchRequest) MarshalBinary() ([]byte, error) {
	if k.Username == nil || k.Signature == nil {
		return nil, errors.New("protocol: KeyKeeperBatchFetchRequest contains nil slices")
	}
	if k.RecordIDs == nil {
		k.RecordIDs = [][16]byte{}
	}

	username_len := uint64(len(k.Username))
	ids_count := uint64(len(k.RecordIDs))
	sig_len := uint64(len(k.Signature))

	// 1 (op) + 8 (len1) + data1 + 8 (count) + count*16 + 8 (len3) + data3 + 16 (checksum)
	total_size := 1 + 8 + int(username_len) + 8 + int(ids_count)*16 + 8 + int(sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_KEYKEEPER_BATCH_FETCH
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], k.Username)
	offset += int(username_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], ids_count)
	offset += 8

	for i := 0; i < len(k.RecordIDs); i++ {
		copy(buf[offset:offset+16], k.RecordIDs[i][:])
		offset += 16
	}

	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_len)
	offset += 8
	copy(buf[offset:offset+int(sig_len)], k.Signature)
	offset += int(sig_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperBatchFetchRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (len1) + 8 (count) + 8 (len3) + 16 (checksum) = 41 bytes
	const min_size = 41
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperBatchFetchRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperBatchFetchRequest")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_BATCH_FETCH {
		return errors.New("protocol: invalid App OpCode for KeyKeeperBatchFetchRequest")
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

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading RecordIDs count")
	}
	ids_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if ids_count > uint64(payload_length-offset)/16 {
		return errors.New("protocol: KeyKeeperBatchFetchRequest record ID count exceeds payload size")
	}

	k.RecordIDs = make([][16]byte, int(ids_count))
	for i := uint64(0); i < ids_count; i++ {
		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading RecordID data")
		}
		copy(k.RecordIDs[i][:], data[offset:offset+16])
		offset += 16
	}

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if sig_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading Signature data")
	}
	k.Signature = make([]byte, int(sig_len))
	copy(k.Signature, data[offset:offset+int(sig_len)])
	offset += int(sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperBatchFetchRequest")
	}

	return nil
}

// KeyKeeperBatchFetchResponse returns the requested permanent records.
type KeyKeeperBatchFetchResponse struct {
	StatusCode uint8
	Records    []KeyKeeperRecord
}

func (k *KeyKeeperBatchFetchResponse) MarshalBinary() ([]byte, error) {
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

	total_size := 1 + 1 + 8 + records_data_size + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_KEYKEEPER_BATCH_FETCH
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

func (k *KeyKeeperBatchFetchResponse) UnmarshalBinary(data []byte) error {
	const min_size = 26
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperBatchFetchResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperBatchFetchResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_BATCH_FETCH {
		return errors.New("protocol: invalid App OpCode for KeyKeeperBatchFetchResponse")
	}

	k.StatusCode = data[offset]
	offset += 1

	records_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if records_count > uint64(payload_length-offset)/40 {
		return errors.New("protocol: KeyKeeperBatchFetchResponse record count exceeds payload size")
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
		return errors.New("protocol: unexpected trailing data in KeyKeeperBatchFetchResponse")
	}

	return nil
}
