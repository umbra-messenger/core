package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// LoginBrakeCookie is the AEAD-encrypted brake state sent to the client
// and returned in FetchUserKeyRequest. It is NOT routed (no MessageType).
type LoginBrakeCookie struct {
	LoginBrake []byte
	Version    uint64
}

func (l *LoginBrakeCookie) MarshalBinary() ([]byte, error) {
	if l.LoginBrake == nil {
		return nil, errors.New("protocol: LoginBrakeCookie contains nil LoginBrake")
	}

	brake_len := uint64(len(l.LoginBrake))

	// 8 (len) + brake + 8 (version) + 16 (checksum)
	total_size := 8 + int(brake_len) + 8 + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], brake_len)
	offset += 8
	copy(buf[offset:offset+int(brake_len)], l.LoginBrake)
	offset += int(brake_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], l.Version)
	offset += 8

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (l *LoginBrakeCookie) UnmarshalBinary(data []byte) error {
	// Min size: 8 (len) + 8 (version) + 16 (checksum) = 32 bytes
	const min_size = 32
	if len(data) < min_size {
		return errors.New("protocol: data too short for LoginBrakeCookie")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in LoginBrakeCookie")
	}

	offset := 0

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading LoginBrake length")
	}
	brake_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if brake_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading LoginBrake data")
	}
	l.LoginBrake = make([]byte, int(brake_len))
	copy(l.LoginBrake, data[offset:offset+int(brake_len)])
	offset += int(brake_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Version")
	}
	l.Version = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in LoginBrakeCookie")
	}

	return nil
}
