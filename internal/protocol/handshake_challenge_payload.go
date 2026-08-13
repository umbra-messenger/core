package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// HandshakeChallengePayload represents the inner plaintext encrypted with the shared secret.
type HandshakeChallengePayload struct {
	EncryptedSessionToken []byte
	HashedRandomKey       []byte
}

func (p *HandshakeChallengePayload) MarshalBinary() ([]byte, error) {
	if p.EncryptedSessionToken == nil || p.HashedRandomKey == nil {
		return nil, errors.New("protocol: HandshakeChallengePayload fields cannot be nil")
	}
	len_token := uint64(len(p.EncryptedSessionToken))
	len_hash := uint64(len(p.HashedRandomKey))

	total_size := 8 + int(len_token) + 8 + int(len_hash) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_token)
	offset += 8
	copy(buf[offset:offset+int(len_token)], p.EncryptedSessionToken)
	offset += int(len_token)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_hash)
	offset += 8
	copy(buf[offset:offset+int(len_hash)], p.HashedRandomKey)
	offset += int(len_hash)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (p *HandshakeChallengePayload) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 8 + 16 // 32 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for HandshakeChallengePayload")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_token := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_token) > payload_length {
		return errors.New("protocol: underflow reading EncryptedSessionToken")
	}
	p.EncryptedSessionToken = make([]byte, len_token)
	copy(p.EncryptedSessionToken, data[offset:offset+int(len_token)])
	offset += int(len_token)

	len_hash := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_hash) > payload_length {
		return errors.New("protocol: underflow reading HashedRandomKey")
	}
	p.HashedRandomKey = make([]byte, len_hash)
	copy(p.HashedRandomKey, data[offset:offset+int(len_hash)])
	offset += int(len_hash)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
