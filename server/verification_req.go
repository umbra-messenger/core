package server

import (
	"crypto/subtle"

	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

func (s *Server) handle_verification_req(data []byte) []byte {
	req := &protocol.VerificationRequest{}
	if err := req.UnmarshalBinary(data); err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_PROTOCOL)
	}

	// 1. Decrypt SessionCookie
	cookie_pkg := &protocol.EncryptedPackage{}
	if err := cookie_pkg.UnmarshalBinary(req.SessionCookie); err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_PROTOCOL)
	}

	cookie_bytes, err := s.crypt.DecryptFull(shared.CTX_SERVER_COOKIE, cookie_pkg.Ciphertext, s.cookie_key[:], nil, cookie_pkg.Tag, cookie_pkg.Nonce, true)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_PROTOCOL)
	}

	cookie := &protocol.SessionCookie{}
	if err := cookie.UnmarshalBinary(cookie_bytes); err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// 2. Verify Session Token (PoW)
	token_pkg := &protocol.EncryptedPackage{}
	if err := token_pkg.UnmarshalBinary(req.SessionTokenFound); err != nil {
		return s.build_error_response(shared.ERR_CODE_PUZZLE_UNSOLVED)
	}

	decrypted_token, err := s.crypt.DecryptFull(shared.CTX_AEAD_PUZZLE_TOKEN, token_pkg.Ciphertext, cookie.SessionSymKey[:], nil, token_pkg.Tag, token_pkg.Nonce, true)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_PUZZLE_UNSOLVED)
	}

	if len(decrypted_token) != shared.SESSION_TOKEN_LEN || subtle.ConstantTimeCompare(decrypted_token, cookie.SessionToken[:]) != 1 {
		return s.build_error_response(shared.ERR_CODE_PUZZLE_UNSOLVED)
	}

	// 3. Accept Client's Session Signing PubKey
	client_signing_pub := req.SessionSigningPubKey

	// 4. Generate Session ID and Establish Session in Storage
	var session_id [shared.SESSION_ID_LEN]byte
	if err := s.crypt.Rand(session_id[:]); err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	_, server_signing_priv, err := s.crypt.DeriveSigningKeyPair(shared.CTX_SERVER_SESSION_SIGNING, cookie.SessionMasterKey)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	session_state := &SessionState{
		SessionSymKey:        cookie.SessionSymKey,
		ServerSigningPrivKey: server_signing_priv,
		ClientSigningPubKey:  client_signing_pub,
		HighestSeenNonce:     0,
		IsEstablished:        true,
	}

	state_bytes, err := session_state.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	err = s.storage.Store(shared.STORE_CTX_SESSION_KEY, session_id[:], state_bytes)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// 5. Build VerificationResponse containing the new Session ID
	ver_res := &protocol.VerificationResponse{SessionID: session_id}
	ver_res_bytes, err := ver_res.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// Encrypt the VerificationResponse with session_sym_key
	nonce_res, ct_res, tag_res, err := s.crypt.EncryptFull(shared.CTX_AEAD_VERIFICATION_RESP, ver_res_bytes, cookie.SessionSymKey[:], nil)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	enc_pkg := &protocol.EncryptedPackage{Nonce: nonce_res, Ciphertext: ct_res, Tag: tag_res}
	enc_payload_bytes, err := enc_pkg.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// Sign the encrypted payload with Server's Private Key
	sig, err := s.crypt.Sign(shared.CTX_SERVER_SESSION_SIGNING, enc_payload_bytes, server_signing_priv)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// Wrap in GeneralResponse envelope
	res := &protocol.GeneralResponse{
		EncryptedPayload: enc_payload_bytes,
		Signature:        sig,
	}

	final_response, err := res.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	return final_response
}
