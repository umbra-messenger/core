package protocol

import (
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// DestroySessionRequest represents a request to terminate the current session.
type DestroySessionRequest struct {
	// No fields needed - the session context is implicit in the GeneralRequest
}

func (d *DestroySessionRequest) MarshalBinary() ([]byte, error) {
	total_size := 16
	buf := make([]byte, total_size)

	checksum := crypt.Checksum(buf[:0])
	copy(buf[0:16], checksum[:])

	return buf, nil
}

func (d *DestroySessionRequest) UnmarshalBinary(data []byte) error {
	const min_size = 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for DestroySessionRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	if payload_length != 0 {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
