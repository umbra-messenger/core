package protocol

import (
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// CreateGroupResponse represents the server's confirmation of group creation.
type CreateGroupResponse struct {
	GroupID [16]byte
	Success bool
}

func (c *CreateGroupResponse) MarshalBinary() ([]byte, error) {
	total_size := 16 + 1 + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], c.GroupID[:])
	offset += 16

	if c.Success {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *CreateGroupResponse) UnmarshalBinary(data []byte) error {
	const min_size = 16 + 1 + 16 // 33 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for CreateGroupResponse")
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

	c.Success = data[offset] == 1
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
