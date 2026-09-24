package server

import (
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

func (s *Server) handle_handshake_init(data []byte) []byte {
	req := &protocol.HandshakeInit{}
	if err := req.UnmarshalBinary(data); err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_PROTOCOL)
	}

	// 1. Verify Client's Initial Signature
	is_valid, err := s.crypt.Verify(shared.CTX_HANDSHAKE_INIT_SIG, req.ExchangePublicKey, req.ExchangeKeySignature, req.SigningPublicKey)
	if err != nil || !is_valid {
		return s.build_error_response(shared.ERR_CODE_INVALID_SIGNATURE)
	}

	// 2. Generate Server Session State
	var session_master_key [shared.MASTER_KEY_LEN]byte
	if err := s.crypt.Rand(session_master_key[:]); err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	server_signing_pub, server_signing_priv, err := s.crypt.DeriveSigningKeyPair(shared.CTX_SERVER_SESSION_SIGNING, session_master_key)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// 3. KEM Encapsulation
	kem_ciphertext, shared_secret, err := s.crypt.Encapsulate(shared.CTX_KEM_ENCAPSULATE, req.ExchangePublicKey)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_KEY)
	}

	session_sym_key, err := s.crypt.Hash(shared.CTX_SESSION_KEY_DERIV, shared_secret, 32)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// 4. Generate Puzzle & Token
	var session_token [shared.SESSION_TOKEN_LEN]byte
	if err := s.crypt.Rand(session_token[:]); err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	var challenge_bytes [3]byte
	if err := s.crypt.Rand(challenge_bytes[:]); err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}
	challenge_bytes[0] &= 0x0F // Mask to 20 bits

	session_puzzle, err := s.crypt.Hash(shared.CTX_PUZZLE_HASH, challenge_bytes[:], 32)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// Use session_sym_key as the high-entropy salt for the slow HashPassword
	puzzle_key, err := s.crypt.HashPassword(shared.CTX_PUZZLE_KEY_DERIV, challenge_bytes[:], session_sym_key, 32)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// Encrypt Token with Puzzle Key
	nonce_token, ct_token, tag_token, err := s.crypt.EncryptFull(shared.CTX_AEAD_PUZZLE_TOKEN, session_token[:], puzzle_key, nil)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	enc_token_pkg := &protocol.EncryptedPackage{Nonce: nonce_token, Ciphertext: ct_token, Tag: tag_token}
	enc_token_bytes, err := enc_token_pkg.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// Pack and Encrypt Puzzle Payload with Session Symmetric Key
	puzzle_payload := make([]byte, len(enc_token_bytes)+len(session_puzzle))
	copy(puzzle_payload, enc_token_bytes)
	copy(puzzle_payload[len(enc_token_bytes):], session_puzzle)

	nonce_puzzle, ct_puzzle, tag_puzzle, err := s.crypt.EncryptFull(shared.CTX_AEAD_SESSION_PUZZLE, puzzle_payload, session_sym_key, nil)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	enc_puzzle_pkg := &protocol.EncryptedPackage{Nonce: nonce_puzzle, Ciphertext: ct_puzzle, Tag: tag_puzzle}
	enc_puzzle_bytes, err := enc_puzzle_pkg.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// 5. Build and Encrypt Session Cookie (No session_id yet)
	cookie := &protocol.SessionCookie{
		SessionMasterKey: session_master_key,
		SessionSymKey:    [32]byte(session_sym_key),
		SessionToken:     session_token,
	}
	cookie_bytes, err := cookie.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	nonce_cookie, ct_cookie, tag_cookie, err := s.crypt.EncryptFull(shared.CTX_SERVER_COOKIE, cookie_bytes, s.cookie_key[:], nil)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	enc_cookie_pkg := &protocol.EncryptedPackage{Nonce: nonce_cookie, Ciphertext: ct_cookie, Tag: tag_cookie}
	enc_cookie_bytes, err := enc_cookie_pkg.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// 6. Build HandshakeChallenge
	challenge := &protocol.HandshakeChallenge{
		KemCiphertext:          kem_ciphertext,
		SessionSigningPubKey:   server_signing_pub,
		EncryptedSessionPuzzle: enc_puzzle_bytes,
		SessionCookie:          enc_cookie_bytes,
		Signature:              []byte{},
	}

	temp_buf, err := challenge.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	payload_to_sign := temp_buf[:len(temp_buf)-shared.CHECKSUM_LEN]
	sig, err := s.crypt.Sign(shared.CTX_SERVER_SESSION_SIGNING, payload_to_sign, server_signing_priv)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	challenge.Signature = sig
	final_response, err := challenge.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	return final_response
}
