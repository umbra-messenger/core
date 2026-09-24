package protocol

import (
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// VerificationResponse is the encrypted payload returned by the server upon successful handshake.
// It does NOT contain a MessageType or App OpCode, as it is strictly an inner payload.
type VerificationResponse struct {
	SessionID [16]byte
}

func (v *VerificationResponse) MarshalBinary() ([]byte, error) {
	// 16 (id) + 16 (checksum) = 32 bytes
	total_size := 32
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], v.SessionID[:])
	offset += 16

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (v *VerificationResponse) UnmarshalBinary(data []byte) error {
	const min_size = 32
	if len(data) < min_size {
		return errors.New("protocol: data too short for VerificationResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in VerificationResponse")
	}

	offset := 0

	copy(v.SessionID[:], data[offset:offset+16])
	offset += 16

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in VerificationResponse")
	}

	return nil
}
