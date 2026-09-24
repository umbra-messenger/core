package server

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// SessionState is the internal server-side representation of an active session.
// It is serialized and stored in the Host's Storage interface.
type SessionState struct {
	SessionSymKey        [32]byte
	ServerSigningPrivKey []byte
	ClientSigningPubKey  []byte
	HighestSeenNonce     uint64
	IsEstablished        bool
}

func (s *SessionState) MarshalBinary() ([]byte, error) {
	if s.ServerSigningPrivKey == nil || s.ClientSigningPubKey == nil {
		return nil, errors.New("server: SessionState contains nil slices")
	}

	priv_len := uint64(len(s.ServerSigningPrivKey))
	pub_len := uint64(len(s.ClientSigningPubKey))

	// 32 (sym) + 8 (len1) + d1 + 8 (len2) + d2 + 8 (nonce) + 1 (bool) + 16 (checksum)
	total_size := 32 + 8 + int(priv_len) + 8 + int(pub_len) + 8 + 1 + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+32], s.SessionSymKey[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:offset+8], priv_len)
	offset += 8
	copy(buf[offset:offset+int(priv_len)], s.ServerSigningPrivKey)
	offset += int(priv_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], pub_len)
	offset += 8
	copy(buf[offset:offset+int(pub_len)], s.ClientSigningPubKey)
	offset += int(pub_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], s.HighestSeenNonce)
	offset += 8

	if s.IsEstablished {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SessionState) UnmarshalBinary(data []byte) error {
	// Min size: 32 + 8*2 + 8 + 1 + 16 = 73 bytes
	const min_size = 73
	if len(data) < min_size {
		return errors.New("server: data too short for SessionState")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("server: checksum mismatch in SessionState")
	}

	offset := 0

	copy(s.SessionSymKey[:], data[offset:offset+32])
	offset += 32

	priv_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(priv_len) > payload_length {
		return errors.New("server: underflow reading ServerSigningPrivKey")
	}
	s.ServerSigningPrivKey = make([]byte, priv_len)
	copy(s.ServerSigningPrivKey, data[offset:offset+int(priv_len)])
	offset += int(priv_len)

	pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(pub_len) > payload_length {
		return errors.New("server: underflow reading ClientSigningPubKey")
	}
	s.ClientSigningPubKey = make([]byte, pub_len)
	copy(s.ClientSigningPubKey, data[offset:offset+int(pub_len)])
	offset += int(pub_len)

	s.HighestSeenNonce = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	s.IsEstablished = data[offset] == 1
	offset += 1

	if offset != payload_length {
		return errors.New("server: unexpected trailing data in SessionState")
	}

	return nil
}
