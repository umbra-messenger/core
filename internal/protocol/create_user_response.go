package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// CreateUserResponse represents the server's response to a user registration request.
type CreateUserResponse struct {
	Discriminator uint16
}

func (c *CreateUserResponse) MarshalBinary() ([]byte, error) {
	total_size := 2 + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint16(buf[offset:offset+2], c.Discriminator)
	offset += 2

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *CreateUserResponse) UnmarshalBinary(data []byte) error {
	const min_size = 2 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for CreateUserResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	c.Discriminator = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
