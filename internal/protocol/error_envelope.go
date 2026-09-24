package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

type ErrorEnvelope struct {
	ErrorCode uint16
}

func (e *ErrorEnvelope) MarshalBinary() ([]byte, error) {
	// 1 (type) + 2 (code) + 16 (checksum) = 19 bytes
	total_size := 19
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.MSG_ERROR
	offset += 1

	binary.BigEndian.PutUint16(buf[offset:offset+2], e.ErrorCode)
	offset += 2

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (e *ErrorEnvelope) UnmarshalBinary(data []byte) error {
	const min_size = 19
	if len(data) < min_size {
		return errors.New("protocol: data too short for ErrorEnvelope")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in ErrorEnvelope")
	}

	offset := 0

	msg_type := data[offset]
	offset += 1
	if msg_type != shared.MSG_ERROR {
		return errors.New("protocol: invalid MessageType for ErrorEnvelope")
	}

	e.ErrorCode = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in ErrorEnvelope")
	}

	return nil
}
