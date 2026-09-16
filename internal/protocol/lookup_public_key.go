package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// LookupPublicKeyRequest is sent to retrieve the public signing and exchange keys for a username.
type LookupPublicKeyRequest struct {
	Username []byte
}

func (l *LookupPublicKeyRequest) MarshalBinary() ([]byte, error) {
	if l.Username == nil {
		return nil, errors.New("protocol: LookupPublicKeyRequest contains nil slices")
	}

	username_len := uint64(len(l.Username))

	// 1 (op) + 8 (len) + data + 16 (checksum)
	total_size := 1 + 8 + int(username_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_LOOKUP_PUBLIC_KEY
	offset += 1

	// 2. Username
	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], l.Username)
	offset += int(username_len)

	// 3. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (l *LookupPublicKeyRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (len) + 16 (checksum) = 25 bytes
	const min_size = 1 + 8 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for LookupPublicKeyRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in LookupPublicKeyRequest")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_LOOKUP_PUBLIC_KEY {
		return errors.New("protocol: invalid App OpCode for LookupPublicKeyRequest")
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
	l.Username = make([]byte, username_len)
	copy(l.Username, data[offset:offset+int(username_len)])
	offset += int(username_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in LookupPublicKeyRequest")
	}

	return nil
}

// LookupPublicKeyResponse returns the public keys (or deterministic dummy keys).
type LookupPublicKeyResponse struct {
	StatusCode  uint8
	SigningPub  []byte
	ExchangePub []byte
}

func (l *LookupPublicKeyResponse) MarshalBinary() ([]byte, error) {
	if l.SigningPub == nil || l.ExchangePub == nil {
		return nil, errors.New("protocol: LookupPublicKeyResponse contains nil slices")
	}

	signing_pub_len := uint64(len(l.SigningPub))
	exchange_pub_len := uint64(len(l.ExchangePub))

	// 1 (op) + 1 (status) + 8 (len1) + data1 + 8 (len2) + data2 + 16 (checksum)
	total_size := 1 + 1 + 8 + int(signing_pub_len) + 8 + int(exchange_pub_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_LOOKUP_PUBLIC_KEY
	offset += 1

	// 2. StatusCode
	buf[offset] = l.StatusCode
	offset += 1

	// 3. SigningPub
	binary.BigEndian.PutUint64(buf[offset:offset+8], signing_pub_len)
	offset += 8
	copy(buf[offset:offset+int(signing_pub_len)], l.SigningPub)
	offset += int(signing_pub_len)

	// 4. ExchangePub
	binary.BigEndian.PutUint64(buf[offset:offset+8], exchange_pub_len)
	offset += 8
	copy(buf[offset:offset+int(exchange_pub_len)], l.ExchangePub)
	offset += int(exchange_pub_len)

	// 5. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (l *LookupPublicKeyResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 1 (status) + 8*2 (lengths) + 16 (checksum) = 34 bytes
	const min_size = 1 + 1 + 16 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for LookupPublicKeyResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in LookupPublicKeyResponse")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_LOOKUP_PUBLIC_KEY {
		return errors.New("protocol: invalid App OpCode for LookupPublicKeyResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	l.StatusCode = data[offset]
	offset += 1

	// 3. SigningPub
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SigningPub length")
	}
	signing_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(signing_pub_len) > payload_length {
		return errors.New("protocol: underflow reading SigningPub data")
	}
	l.SigningPub = make([]byte, signing_pub_len)
	copy(l.SigningPub, data[offset:offset+int(signing_pub_len)])
	offset += int(signing_pub_len)

	// 4. ExchangePub
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading ExchangePub length")
	}
	exchange_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(exchange_pub_len) > payload_length {
		return errors.New("protocol: underflow reading ExchangePub data")
	}
	l.ExchangePub = make([]byte, exchange_pub_len)
	copy(l.ExchangePub, data[offset:offset+int(exchange_pub_len)])
	offset += int(exchange_pub_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in LookupPublicKeyResponse")
	}

	return nil
}
