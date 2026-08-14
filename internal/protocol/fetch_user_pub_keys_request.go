package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// FetchUserPubKeysRequest represents a request to retrieve public keys for a username.
type FetchUserPubKeysRequest struct {
	Username []byte
}

func (f *FetchUserPubKeysRequest) MarshalBinary() ([]byte, error) {
	if f.Username == nil {
		return nil, errors.New("protocol: FetchUserPubKeysRequest Username cannot be nil")
	}
	len_user := uint64(len(f.Username))

	total_size := 8 + int(len_user) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_user)
	offset += 8
	copy(buf[offset:offset+int(len_user)], f.Username)
	offset += int(len_user)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (f *FetchUserPubKeysRequest) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 16 // 24 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for FetchUserPubKeysRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_user := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_user) > payload_length {
		return errors.New("protocol: underflow reading Username")
	}
	f.Username = make([]byte, len_user)
	copy(f.Username, data[offset:offset+int(len_user)])
	offset += int(len_user)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
