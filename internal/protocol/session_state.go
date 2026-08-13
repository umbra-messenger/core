package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// SessionState represents the persistent state of a session stored by the server.
type SessionState struct {
	ClientExchangePublicKey []byte
	ClientSigningPublicKey  []byte
	ServerMasterKey         [32]byte
	SessionToken            []byte
}

func (s *SessionState) MarshalBinary() ([]byte, error) {
	if s.ClientExchangePublicKey == nil || s.ClientSigningPublicKey == nil || s.SessionToken == nil {
		return nil, errors.New("protocol: SessionState slice fields cannot be nil")
	}
	len_client_exch := uint64(len(s.ClientExchangePublicKey))
	len_client_sign := uint64(len(s.ClientSigningPublicKey))
	len_token := uint64(len(s.SessionToken))

	total_size := 8 + int(len_client_exch) + 8 + int(len_client_sign) + 32 + 8 + int(len_token) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_client_exch)
	offset += 8
	copy(buf[offset:offset+int(len_client_exch)], s.ClientExchangePublicKey)
	offset += int(len_client_exch)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_client_sign)
	offset += 8
	copy(buf[offset:offset+int(len_client_sign)], s.ClientSigningPublicKey)
	offset += int(len_client_sign)

	copy(buf[offset:offset+32], s.ServerMasterKey[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_token)
	offset += 8
	copy(buf[offset:offset+int(len_token)], s.SessionToken)
	offset += int(len_token)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SessionState) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 8 + 32 + 8 + 16 // 64 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for SessionState")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_client_exch := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_client_exch) > payload_length {
		return errors.New("protocol: underflow reading ClientExchangePublicKey")
	}
	s.ClientExchangePublicKey = make([]byte, len_client_exch)
	copy(s.ClientExchangePublicKey, data[offset:offset+int(len_client_exch)])
	offset += int(len_client_exch)

	len_client_sign := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_client_sign) > payload_length {
		return errors.New("protocol: underflow reading ClientSigningPublicKey")
	}
	s.ClientSigningPublicKey = make([]byte, len_client_sign)
	copy(s.ClientSigningPublicKey, data[offset:offset+int(len_client_sign)])
	offset += int(len_client_sign)

	if offset+32 > payload_length {
		return errors.New("protocol: underflow reading ServerMasterKey")
	}
	copy(s.ServerMasterKey[:], data[offset:offset+32])
	offset += 32

	len_token := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_token) > payload_length {
		return errors.New("protocol: underflow reading SessionToken")
	}
	s.SessionToken = make([]byte, len_token)
	copy(s.SessionToken, data[offset:offset+int(len_token)])
	offset += int(len_token)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
