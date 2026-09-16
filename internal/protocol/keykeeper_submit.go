package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// KeyKeeperSubmitRequest is sent to submit an encrypted record to a destination user.
type KeyKeeperSubmitRequest struct {
	DestinationUsername  []byte
	SenderExchangePubKey []byte
	EncryptedPayload     []byte
}

func (k *KeyKeeperSubmitRequest) MarshalBinary() ([]byte, error) {
	if k.DestinationUsername == nil || k.SenderExchangePubKey == nil || k.EncryptedPayload == nil {
		return nil, errors.New("protocol: KeyKeeperSubmitRequest contains nil slices")
	}

	dest_len := uint64(len(k.DestinationUsername))
	sender_pub_len := uint64(len(k.SenderExchangePubKey))
	enc_payload_len := uint64(len(k.EncryptedPayload))

	// 1 (op) + 8 (len1) + data1 + 8 (len2) + data2 + 8 (len3) + data3 + 16 (checksum)
	total_size := 1 + 8 + int(dest_len) + 8 + int(sender_pub_len) + 8 + int(enc_payload_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_KEYKEEPER_SUBMIT
	offset += 1

	// 2. DestinationUsername
	binary.BigEndian.PutUint64(buf[offset:offset+8], dest_len)
	offset += 8
	copy(buf[offset:offset+int(dest_len)], k.DestinationUsername)
	offset += int(dest_len)

	// 3. SenderExchangePubKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], sender_pub_len)
	offset += 8
	copy(buf[offset:offset+int(sender_pub_len)], k.SenderExchangePubKey)
	offset += int(sender_pub_len)

	// 4. EncryptedPayload
	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_payload_len)
	offset += 8
	copy(buf[offset:offset+int(enc_payload_len)], k.EncryptedPayload)
	offset += int(enc_payload_len)

	// 5. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperSubmitRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8*3 (lengths) + 16 (checksum) = 41 bytes
	const min_size = 1 + 24 + 16
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

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_SUBMIT {
		return errors.New("protocol: invalid App OpCode for KeyKeeperSubmitRequest")
	}

	// 2. DestinationUsername
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading DestinationUsername length")
	}
	dest_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(dest_len) > payload_length {
		return errors.New("protocol: underflow reading DestinationUsername data")
	}
	k.DestinationUsername = make([]byte, dest_len)
	copy(k.DestinationUsername, data[offset:offset+int(dest_len)])
	offset += int(dest_len)

	// 3. SenderExchangePubKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SenderExchangePubKey length")
	}
	sender_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(sender_pub_len) > payload_length {
		return errors.New("protocol: underflow reading SenderExchangePubKey data")
	}
	k.SenderExchangePubKey = make([]byte, sender_pub_len)
	copy(k.SenderExchangePubKey, data[offset:offset+int(sender_pub_len)])
	offset += int(sender_pub_len)

	// 4. EncryptedPayload
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedPayload length")
	}
	enc_payload_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(enc_payload_len) > payload_length {
		return errors.New("protocol: underflow reading EncryptedPayload data")
	}
	k.EncryptedPayload = make([]byte, enc_payload_len)
	copy(k.EncryptedPayload, data[offset:offset+int(enc_payload_len)])
	offset += int(enc_payload_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperSubmitRequest")
	}

	return nil
}

// KeyKeeperSubmitResponse returns the server-assigned RecordID for the submitted record.
type KeyKeeperSubmitResponse struct {
	StatusCode uint8
	RecordID   [16]byte
}

func (k *KeyKeeperSubmitResponse) MarshalBinary() ([]byte, error) {
	// 1 (op) + 1 (status) + 16 (record_id) + 16 (checksum) = 34 bytes
	total_size := 34
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_KEYKEEPER_SUBMIT
	offset += 1

	// 2. StatusCode
	buf[offset] = k.StatusCode
	offset += 1

	// 3. RecordID
	copy(buf[offset:offset+16], k.RecordID[:])
	offset += 16

	// 4. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperSubmitResponse) UnmarshalBinary(data []byte) error {
	const min_size = 34
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

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_SUBMIT {
		return errors.New("protocol: invalid App OpCode for KeyKeeperSubmitResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	k.StatusCode = data[offset]
	offset += 1

	// 3. RecordID
	if offset+16 > payload_length {
		return errors.New("protocol: underflow reading RecordID")
	}
	copy(k.RecordID[:], data[offset:offset+16])
	offset += 16

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperSubmitResponse")
	}

	return nil
}
