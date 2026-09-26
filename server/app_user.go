package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

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

	// Check difficulty: last N bits of first byte must be zero
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

	for range shared.USERNAME_DISCRIMINATOR_MAX_TRIES {
		var disc uint16
		for {
			var disc_bytes [2]byte
			if err := s.crypt.Rand(disc_bytes[:]); err != nil {
				return nil, err
			}
			disc = binary.BigEndian.Uint16(disc_bytes[:]) % 10000

			if !slices.Contains(tried, disc) {
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
		StatusCode:       shared.APP_STATUS_SUCCESS,
		AssignedUsername: full_username,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_fetch_user_key(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.FetchUserKeyRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	current_time := s.time_func()

	// 1. Decrypt Login Brake Cookie
	brake_cookie, err := s.decrypt_login_brake_cookie(req.LoginBrakeCookie)
	if err != nil {
		// Invalid cookie: rotate and return new brake
		return s.rotate_login_brake_response(session_id, session_state)
	}

	// 2. Timestamp Kindness Check
	// If enough time has passed since the last brake was issued, skip PoW verification.
	if current_time > session_state.LoginBrakeTimestamp+shared.LOGIN_BRAKE_SKIP_THRESHOLD_SECONDS {
		return s.fetch_user_key_with_new_brake(session_id, session_state, req.Username)
	}

	// 3. Version Monotonicity Check
	if brake_cookie.Version <= session_state.LoginBrakeVersion {
		return s.rotate_login_brake_response(session_id, session_state)
	}

	// 4. Verify Lightweight PoW
	// Hash(Username || LoginBrake || Nonce) must have last N bits of first byte zero.

	pow_input := make([]byte, len(req.Username)+len(brake_cookie.LoginBrake)+8)
	pow_offset := 0
	copy(pow_input[pow_offset:], req.Username)
	pow_offset += len(req.Username)
	copy(pow_input[pow_offset:], brake_cookie.LoginBrake)
	pow_offset += len(brake_cookie.LoginBrake)
	binary.BigEndian.PutUint64(pow_input[pow_offset:], req.Nonce)

	pow_output, err := s.crypt.Hash(shared.CTX_LOGIN_BRAKE_POW, pow_input, 32)
	if err != nil {
		return nil, err
	}

	pow_mask := uint8(0xFF) >> (8 - shared.LOGIN_BRAKE_POW_DIFFICULTY_BITS)
	if pow_output[0]&pow_mask != 0x00 {
		return s.rotate_login_brake_response(session_id, session_state)
	}

	// 5. PoW Passed — Update session and fetch key
	session_state.LoginBrakeVersion = brake_cookie.Version
	return s.fetch_user_key_with_new_brake(session_id, session_state, req.Username)
}

// fetch_user_key_with_new_brake fetches the user key (or dummy), generates a new brake,
// updates the session, and returns the response.
func (s *Server) fetch_user_key_with_new_brake(session_id [16]byte, session_state *SessionState, username []byte) ([]byte, error) {
	// Timing-constant: always compute dummy
	dummy_input := make([]byte, len(s.dummy_salt)+len(username))
	copy(dummy_input, s.dummy_salt[:])
	copy(dummy_input[len(s.dummy_salt):], username)

	dummy_key, err := s.crypt.Hash(shared.CTX_DUMMY_USER_KEY, dummy_input, 32)
	if err != nil {
		return nil, err
	}

	// Attempt real fetch
	result_key := dummy_key
	record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_USER_KEY, username)
	if err == nil {
		record := &UserRecord{}
		if record.UnmarshalBinary(record_bytes) == nil {
			result_key = record.EncryptedMasterKey
		}
	}

	// Generate new brake for next request
	new_version := session_state.LoginBrakeVersion + 1
	new_brake, new_cookie, new_timestamp, err := s.generate_login_brake(new_version)
	if err != nil {
		return nil, err
	}

	// Update session
	session_state.LoginBrakeVersion = new_version
	session_state.LoginBrakeTimestamp = new_timestamp
	if err := s.store_session_state(session_id, session_state); err != nil {
		return nil, err
	}

	res := &protocol.FetchUserKeyResponse{
		StatusCode:         shared.APP_STATUS_SUCCESS,
		EncryptedMasterKey: result_key,
		LoginBrake:         new_brake,
		LoginBrakeCookie:   new_cookie,
	}
	return res.MarshalBinary()
}

// rotate_login_brake_response generates a new brake WITHOUT incrementing the session version,
// updates the timestamp, and returns a rotation-status response.
func (s *Server) rotate_login_brake_response(session_id [16]byte, session_state *SessionState) ([]byte, error) {
	new_version := session_state.LoginBrakeVersion + 1
	new_brake, new_cookie, new_timestamp, err := s.generate_login_brake(new_version)
	if err != nil {
		return nil, err
	}

	// Update session timestamp but NOT version (version updates only on successful processing)
	session_state.LoginBrakeTimestamp = new_timestamp
	if err := s.store_session_state(session_id, session_state); err != nil {
		return nil, err
	}

	// Return empty key with rotation status
	res := &protocol.FetchUserKeyResponse{
		StatusCode:         shared.APP_STATUS_BRAKE_ROTATE,
		EncryptedMasterKey: []byte{},
		LoginBrake:         new_brake,
		LoginBrakeCookie:   new_cookie,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_lookup_public_key(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.LookupPublicKeyRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// Timing-constant: always compute dummies
	dummy_input := make([]byte, len(s.dummy_salt)+len(req.Username))
	copy(dummy_input, s.dummy_salt[:])
	copy(dummy_input[len(s.dummy_salt):], req.Username)

	dummy_sig, err := s.crypt.Hash(shared.CTX_DUMMY_PUB_KEY, dummy_input, 32)
	if err != nil {
		return nil, err
	}

	// Derive a second dummy by hashing the first dummy (domain separation via chaining)
	dummy_ex, err := s.crypt.Hash(shared.CTX_DUMMY_PUB_KEY, dummy_sig, 32)
	if err != nil {
		return nil, err
	}

	result_sig := dummy_sig
	result_ex := dummy_ex

	// Attempt real fetch
	record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_USER_KEY, req.Username)
	if err == nil {
		record := &UserRecord{}
		if record.UnmarshalBinary(record_bytes) == nil {
			result_sig = record.SigningPub
			result_ex = record.ExchangePub
		}
	}

	res := &protocol.LookupPublicKeyResponse{
		StatusCode:  shared.APP_STATUS_SUCCESS,
		SigningPub:  result_sig,
		ExchangePub: result_ex,
	}
	return res.MarshalBinary()
}
