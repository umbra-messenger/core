package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// ServerResponse represents the application-level response envelope.
// It echoes the RequestID for correlation, includes a type indicator, a payload, and optional events.
type ServerResponse struct {
	RequestID [16]byte
	Type      uint8
	Payload   []byte
	Events    []byte
}

func (s *ServerResponse) MarshalBinary() ([]byte, error) {
	if s.Payload == nil || s.Events == nil {
		return nil, errors.New("protocol: ServerResponse fields cannot be nil")
	}
	len_payload := uint64(len(s.Payload))
	len_events := uint64(len(s.Events))

	total_size := 16 + 1 + 8 + int(len_payload) + 8 + int(len_events) + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], s.RequestID[:])
	offset += 16

	buf[offset] = s.Type
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_payload)
	offset += 8
	copy(buf[offset:offset+int(len_payload)], s.Payload)
	offset += int(len_payload)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_events)
	offset += 8
	copy(buf[offset:offset+int(len_events)], s.Events)
	offset += int(len_events)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *ServerResponse) UnmarshalBinary(data []byte) error {
	const min_size = 16 + 1 + 8 + 8 + 16 // 49 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for ServerResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	copy(s.RequestID[:], data[offset:offset+16])
	offset += 16

	s.Type = data[offset]
	offset += 1

	len_payload := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_payload) > payload_length {
		return errors.New("protocol: underflow reading Payload")
	}
	s.Payload = make([]byte, len_payload)
	copy(s.Payload, data[offset:offset+int(len_payload)])
	offset += int(len_payload)

	len_events := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_events) > payload_length {
		return errors.New("protocol: underflow reading Events")
	}
	s.Events = make([]byte, len_events)
	copy(s.Events, data[offset:offset+int(len_events)])
	offset += int(len_events)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
