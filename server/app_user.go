package server

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

func contains_uint16(slice []uint16, val uint16) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func (s *Server) handle_app_create_user(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.CreateUserRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Verify Proof-of-Work (HashPassword with session_sym_key as salt)
	nonce_bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce_bytes, req.Nonce)

	pow_output, err := s.crypt.HashPassword(
		shared.CTX_USER_REGISTRATION_POW,
		nonce_bytes,
		session_state.SessionSymKey[:],
		32,
	)
	if err != nil {
		return nil, err
	}

	// Check difficulty: first 6 bits must be zero
	// 0x3F = 00111111 in binary, masks the bottom 6 bits
	pow_mask := uint8(0xFF) >> (8 - shared.USER_REGISTRATION_POW_DIFFICULTY_BITS)
	if pow_output[0]&pow_mask != 0x00 {
		return nil, errors.New("insufficient pow difficulty")
	}

	// 2. Verify Authentication Signature
	// Signature covers: username || encrypted_master_key || signing_pub || exchange_pub || nonce
	auth_payload_len := len(req.Username) + len(req.EncryptedMasterKey) + len(req.SigningPub) + len(req.ExchangePub) + 8
	auth_payload := make([]byte, auth_payload_len)
	offset := 0

	copy(auth_payload[offset:], req.Username)
	offset += len(req.Username)

	copy(auth_payload[offset:], req.EncryptedMasterKey)
	offset += len(req.EncryptedMasterKey)

	copy(auth_payload[offset:], req.SigningPub)
	offset += len(req.SigningPub)

	copy(auth_payload[offset:], req.ExchangePub)
	offset += len(req.ExchangePub)

	binary.BigEndian.PutUint64(auth_payload[offset:], req.Nonce)

	is_valid, err := s.crypt.Verify(shared.CTX_USER_REGISTRATION, auth_payload, req.Signature, req.SigningPub)
	if err != nil || !is_valid {
		return nil, errors.New("invalid registration signature")
	}

	// 3. Generate Unique Discriminator
	var full_username []byte
	found := false
	tried := make([]uint16, 0, shared.USERNAME_DISCRIMINATOR_MAX_TRIES)

	for i := 0; i < shared.USERNAME_DISCRIMINATOR_MAX_TRIES; i++ {
		var disc uint16
		for {
			var disc_bytes [2]byte
			if err := s.crypt.Rand(disc_bytes[:]); err != nil {
				return nil, err
			}
			disc = binary.BigEndian.Uint16(disc_bytes[:]) % 10000

			if !contains_uint16(tried, disc) {
				tried = append(tried, disc)
				break
			}
		}

		disc_str := fmt.Sprintf("%04d", disc)
		full_username = make([]byte, len(req.Username)+1+4)
		copy(full_username, req.Username)
		full_username[len(req.Username)] = '#'
		copy(full_username[len(req.Username)+1:], disc_str)

		_, err := s.storage.Retrieve(shared.STORE_CTX_USER_KEY, full_username)
		if err != nil {
			found = true
			break
		}
	}

	if !found {
		return nil, errors.New("username capacity full")
	}

	// 4. Store User Record
	record := &UserRecord{
		EncryptedMasterKey: req.EncryptedMasterKey,
		SigningPub:         req.SigningPub,
		ExchangePub:        req.ExchangePub,
	}
	record_bytes, err := record.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if err := s.storage.Store(shared.STORE_CTX_USER_KEY, full_username, record_bytes); err != nil {
		return nil, err
	}

	// 5. Build Response
	res := &protocol.CreateUserResponse{
		StatusCode:       0,
		AssignedUsername: full_username,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_fetch_user_key(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.FetchUserKeyRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_USER_KEY, req.Username)
	if err == nil {
		record := &UserRecord{}
		if err := record.UnmarshalBinary(record_bytes); err == nil {
			res := &protocol.FetchUserKeyResponse{
				StatusCode:         0,
				EncryptedMasterKey: record.EncryptedMasterKey,
			}
			return res.MarshalBinary()
		}
	}

	// Deterministic Dummy
	dummy_input := make([]byte, len(s.dummy_salt)+len(req.Username))
	copy(dummy_input, s.dummy_salt[:])
	copy(dummy_input[len(s.dummy_salt):], req.Username)

	dummy_key, err := s.crypt.Hash(shared.CTX_DUMMY_USER_KEY, dummy_input, 32)
	if err != nil {
		return nil, err
	}

	res := &protocol.FetchUserKeyResponse{
		StatusCode:         0,
		EncryptedMasterKey: dummy_key,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_lookup_public_key(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.LookupPublicKeyRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_USER_KEY, req.Username)
	if err == nil {
		record := &UserRecord{}
		if err := record.UnmarshalBinary(record_bytes); err == nil {
			res := &protocol.LookupPublicKeyResponse{
				StatusCode:  0,
				SigningPub:  record.SigningPub,
				ExchangePub: record.ExchangePub,
			}
			return res.MarshalBinary()
		}
	}

	// Deterministic Dummies
	dummy_input := make([]byte, len(s.dummy_salt)+len(req.Username))
	copy(dummy_input, s.dummy_salt[:])
	copy(dummy_input[len(s.dummy_salt):], req.Username)

	dummy_sig, err := s.crypt.Hash(shared.CTX_DUMMY_PUB_KEY, dummy_input, 32)
	if err != nil {
		return nil, err
	}
	dummy_ex, err := s.crypt.Hash(shared.CTX_DUMMY_PUB_KEY, dummy_input, 32)
	if err != nil {
		return nil, err
	}

	res := &protocol.LookupPublicKeyResponse{
		StatusCode:  0,
		SigningPub:  dummy_sig,
		ExchangePub: dummy_ex,
	}
	return res.MarshalBinary()
}
