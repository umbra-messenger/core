package protocol

import (
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// VerificationResponse is the server's notification of session establishment success or failure.
type VerificationResponse struct {
	// Status indicates the result of the verification. 0 = success, non-zero = error code.
	Status byte
}

func (v *VerificationResponse) MarshalBinary() ([]byte, error) {
	// 1 (type) + 1 (status) + 16 (checksum)
	total_size := 1 + 1 + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. MessageType (Wire-format)
	buf[offset] = shared.MSG_VERIFICATION_RES
	offset += 1

	// 2. Status
	buf[offset] = v.Status
	offset += 1

	// 3. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (v *VerificationResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (type) + 1 (status) + 16 (checksum) = 18 bytes
	const min_size = 18
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

	// 1. MessageType
	msg_type := data[offset]
	offset += 1
	if msg_type != shared.MSG_VERIFICATION_RES {
		return errors.New("protocol: invalid MessageType for VerificationResponse")
	}

	// 2. Status
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading Status")
	}
	v.Status = data[offset]
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in VerificationResponse")
	}

	return nil
}
