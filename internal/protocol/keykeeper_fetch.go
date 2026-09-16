package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// KeyKeeperRecord represents a single record returned by fetch operations.
type KeyKeeperRecord struct {
	RecordID             [16]byte
	SenderExchangePubKey []byte
	EncryptedPayload     []byte
	Timestamp            uint64
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

	// 1. App OpCode
	buf[offset] = shared.APP_OP_KEYKEEPER_FETCH
	offset += 1

	// 2. Username
	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], k.Username)
	offset += int(username_len)

	// 3. Checksum
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

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_FETCH {
		return errors.New("protocol: invalid App OpCode for KeyKeeperFetchRequest")
	}

	// 2. Username
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Username length")
	}
	username_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(username_len) > payload_length {
		return errors.New("protocol: underflow reading Username data")
	}
	k.Username = make([]byte, username_len)
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
		if rec.SenderExchangePubKey == nil || rec.EncryptedPayload == nil {
			return nil, errors.New("protocol: KeyKeeperRecord contains nil slices")
		}
		// 16 (id) + 8 (len1) + data1 + 8 (len2) + data2 + 8 (timestamp)
		records_data_size += 16 + 8 + len(rec.SenderExchangePubKey) + 8 + len(rec.EncryptedPayload) + 8
	}

	// 1 (op) + 1 (status) + 8 (count) + records_data_size + 16 (checksum)
	total_size := 1 + 1 + 8 + records_data_size + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_KEYKEEPER_FETCH
	offset += 1

	// 2. StatusCode
	buf[offset] = k.StatusCode
	offset += 1

	// 3. Records Count
	binary.BigEndian.PutUint64(buf[offset:offset+8], records_count)
	offset += 8

	// 4. Records Data
	for i := 0; i < len(k.Records); i++ {
		rec := &k.Records[i]

		copy(buf[offset:offset+16], rec.RecordID[:])
		offset += 16

		sender_pub_len := uint64(len(rec.SenderExchangePubKey))
		binary.BigEndian.PutUint64(buf[offset:offset+8], sender_pub_len)
		offset += 8
		copy(buf[offset:offset+int(sender_pub_len)], rec.SenderExchangePubKey)
		offset += int(sender_pub_len)

		enc_payload_len := uint64(len(rec.EncryptedPayload))
		binary.BigEndian.PutUint64(buf[offset:offset+8], enc_payload_len)
		offset += 8
		copy(buf[offset:offset+int(enc_payload_len)], rec.EncryptedPayload)
		offset += int(enc_payload_len)

		binary.BigEndian.PutUint64(buf[offset:offset+8], rec.Timestamp)
		offset += 8
	}

	// 5. Checksum
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

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_FETCH {
		return errors.New("protocol: invalid App OpCode for KeyKeeperFetchResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	k.StatusCode = data[offset]
	offset += 1

	// 3. Records Count
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Records count")
	}
	records_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	k.Records = make([]KeyKeeperRecord, records_count)
	for i := uint64(0); i < records_count; i++ {
		rec := &k.Records[i]

		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading RecordID")
		}
		copy(rec.RecordID[:], data[offset:offset+16])
		offset += 16

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading SenderExchangePubKey length")
		}
		sender_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		if offset+int(sender_pub_len) > payload_length {
			return errors.New("protocol: underflow reading SenderExchangePubKey data")
		}
		rec.SenderExchangePubKey = make([]byte, sender_pub_len)
		copy(rec.SenderExchangePubKey, data[offset:offset+int(sender_pub_len)])
		offset += int(sender_pub_len)

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading EncryptedPayload length")
		}
		enc_payload_len := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		if offset+int(enc_payload_len) > payload_length {
			return errors.New("protocol: underflow reading EncryptedPayload data")
		}
		rec.EncryptedPayload = make([]byte, enc_payload_len)
		copy(rec.EncryptedPayload, data[offset:offset+int(enc_payload_len)])
		offset += int(enc_payload_len)

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
