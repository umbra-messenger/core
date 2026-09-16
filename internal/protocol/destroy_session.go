package protocol

import (
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// DestroySessionRequest is sent to terminate the current session.
type DestroySessionRequest struct{}

func (d *DestroySessionRequest) MarshalBinary() ([]byte, error) {
	// 1 (op) + 16 (checksum) = 17 bytes
	total_size := 17
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_DESTROY_SESSION
	offset += 1

	// 2. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (d *DestroySessionRequest) UnmarshalBinary(data []byte) error {
	const min_size = 17
	if len(data) < min_size {
		return errors.New("protocol: data too short for DestroySessionRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in DestroySessionRequest")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_DESTROY_SESSION {
		return errors.New("protocol: invalid App OpCode for DestroySessionRequest")
	}

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in DestroySessionRequest")
	}

	return nil
}

// DestroySessionResponse acknowledges the session termination.
type DestroySessionResponse struct {
	StatusCode uint8
}

func (d *DestroySessionResponse) MarshalBinary() ([]byte, error) {
	// 1 (op) + 1 (status) + 16 (checksum) = 18 bytes
	total_size := 18
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_DESTROY_SESSION
	offset += 1

	// 2. StatusCode
	buf[offset] = d.StatusCode
	offset += 1

	// 3. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (d *DestroySessionResponse) UnmarshalBinary(data []byte) error {
	const min_size = 18
	if len(data) < min_size {
		return errors.New("protocol: data too short for DestroySessionResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in DestroySessionResponse")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_DESTROY_SESSION {
		return errors.New("protocol: invalid App OpCode for DestroySessionResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	d.StatusCode = data[offset]
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in DestroySessionResponse")
	}

	return nil
}
