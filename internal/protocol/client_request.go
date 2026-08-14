package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// ClientRequest represents the application-level request envelope.
// It contains a RequestID for correlation, a type indicator, and the actual payload.
type ClientRequest struct {
	RequestID [16]byte
	Type      uint8
	Payload   []byte
}

func (c *ClientRequest) MarshalBinary() ([]byte, error) {
	if c.Payload == nil {
		return nil, errors.New("protocol: ClientRequest Payload cannot be nil")
	}
	len_payload := uint64(len(c.Payload))

	total_size := 16 + 1 + 8 + int(len_payload) + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], c.RequestID[:])
	offset += 16

	buf[offset] = c.Type
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_payload)
	offset += 8
	copy(buf[offset:offset+int(len_payload)], c.Payload)
	offset += int(len_payload)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *ClientRequest) UnmarshalBinary(data []byte) error {
	const min_size = 16 + 1 + 8 + 16 // 41 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for ClientRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	copy(c.RequestID[:], data[offset:offset+16])
	offset += 16

	c.Type = data[offset]
	offset += 1

	len_payload := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_payload) > payload_length {
		return errors.New("protocol: underflow reading Payload")
	}
	c.Payload = make([]byte, len_payload)
	copy(c.Payload, data[offset:offset+int(len_payload)])
	offset += int(len_payload)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
