package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// CreateGroupRequest represents a request to create a new group.
type CreateGroupRequest struct {
	GroupID          [16]byte
	SigningPublicKey []byte
}

func (c *CreateGroupRequest) MarshalBinary() ([]byte, error) {
	if c.SigningPublicKey == nil {
		return nil, errors.New("protocol: CreateGroupRequest SigningPublicKey cannot be nil")
	}
	len_sign_pub := uint64(len(c.SigningPublicKey))

	total_size := 16 + 8 + int(len_sign_pub) + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], c.GroupID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sign_pub)
	offset += 8
	copy(buf[offset:offset+int(len_sign_pub)], c.SigningPublicKey)
	offset += int(len_sign_pub)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *CreateGroupRequest) UnmarshalBinary(data []byte) error {
	const min_size = 16 + 8 + 16 // 40 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for CreateGroupRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	copy(c.GroupID[:], data[offset:offset+16])
	offset += 16

	len_sign_pub := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sign_pub) > payload_length {
		return errors.New("protocol: underflow reading SigningPublicKey")
	}
	c.SigningPublicKey = make([]byte, len_sign_pub)
	copy(c.SigningPublicKey, data[offset:offset+int(len_sign_pub)])
	offset += int(len_sign_pub)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
