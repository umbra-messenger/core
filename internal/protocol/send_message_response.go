package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// SendMessageResponse represents the server's confirmation of message storage.
type SendMessageResponse struct {
	GroupID   [16]byte
	Timestamp int64
	Success   bool
}

func (s *SendMessageResponse) MarshalBinary() ([]byte, error) {
	total_size := 16 + 8 + 1 + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], s.GroupID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(s.Timestamp))
	offset += 8

	if s.Success {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SendMessageResponse) UnmarshalBinary(data []byte) error {
	const min_size = 16 + 8 + 1 + 16 // 41 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for SendMessageResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	copy(s.GroupID[:], data[offset:offset+16])
	offset += 16

	s.Timestamp = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	s.Success = data[offset] == 1
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
