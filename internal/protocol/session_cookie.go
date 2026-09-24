package protocol

import (
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

type SessionCookie struct {
	SessionMasterKey [32]byte
	SessionSymKey    [32]byte
	SessionToken     [32]byte
}

func (s *SessionCookie) MarshalBinary() ([]byte, error) {
	// 32 (master) + 32 (sym) + 32 (token) + 16 (checksum) = 112 bytes
	total_size := 112
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+32], s.SessionMasterKey[:])
	offset += 32

	copy(buf[offset:offset+32], s.SessionSymKey[:])
	offset += 32

	copy(buf[offset:offset+32], s.SessionToken[:])
	offset += 32

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SessionCookie) UnmarshalBinary(data []byte) error {
	const min_size = 112
	if len(data) < min_size {
		return errors.New("protocol: data too short for SessionCookie")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in SessionCookie")
	}

	offset := 0

	copy(s.SessionMasterKey[:], data[offset:offset+32])
	offset += 32

	copy(s.SessionSymKey[:], data[offset:offset+32])
	offset += 32

	copy(s.SessionToken[:], data[offset:offset+32])
	offset += 32

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in SessionCookie")
	}

	return nil
}
