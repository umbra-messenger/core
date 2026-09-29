package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// VerificationResponse is the encrypted inner payload returned upon successful handshake.
// It does NOT contain a MessageType or App OpCode.
type VerificationResponse struct {
	SessionID        [16]byte
	LoginBrake       []byte
	LoginBrakeCookie []byte
}

func (v *VerificationResponse) MarshalBinary() ([]byte, error) {
	if v.LoginBrake == nil || v.LoginBrakeCookie == nil {
		return nil, errors.New("protocol: VerificationResponse contains nil slices")
	}

	brake_len := uint64(len(v.LoginBrake))
	cookie_len := uint64(len(v.LoginBrakeCookie))

	// 16 (id) + 8 (len1) + brake + 8 (len2) + cookie + 16 (checksum)
	total_size := 16 + 8 + int(brake_len) + 8 + int(cookie_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], v.SessionID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], brake_len)
	offset += 8
	copy(buf[offset:offset+int(brake_len)], v.LoginBrake)
	offset += int(brake_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], cookie_len)
	offset += 8
	copy(buf[offset:offset+int(cookie_len)], v.LoginBrakeCookie)
	offset += int(cookie_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (v *VerificationResponse) UnmarshalBinary(data []byte) error {
	// Min size: 16 (id) + 8 (len1) + 8 (len2) + 16 (checksum) = 48 bytes
	const min_size = 48
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

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading LoginBrake length")
	}
	brake_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if brake_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading LoginBrake data")
	}
	v.LoginBrake = make([]byte, int(brake_len))
	copy(v.LoginBrake, data[offset:offset+int(brake_len)])
	offset += int(brake_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading LoginBrakeCookie length")
	}
	cookie_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if cookie_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading LoginBrakeCookie data")
	}
	v.LoginBrakeCookie = make([]byte, int(cookie_len))
	copy(v.LoginBrakeCookie, data[offset:offset+int(cookie_len)])
	offset += int(cookie_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in VerificationResponse")
	}

	return nil
}
