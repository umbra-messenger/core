package server

import (
	"encoding/binary"

	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

func (s *Server) handle_general_req(data []byte) []byte {
	req := &protocol.GeneralRequest{}
	if err := req.UnmarshalBinary(data); err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_PROTOCOL)
	}

	// 1. Retrieve Session State
	state_bytes, err := s.storage.Retrieve(shared.STORE_CTX_SESSION_KEY, req.SessionID[:])
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_SESSION)
	}

	session_state := &SessionState{}
	if err := session_state.UnmarshalBinary(state_bytes); err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_SESSION)
	}

	if !session_state.IsEstablished {
		return s.build_error_response(shared.ERR_CODE_INVALID_SESSION)
	}

	// 2. Verify Monotonic Nonce
	if req.Nonce <= session_state.HighestSeenNonce {
		return s.build_error_response(shared.ERR_CODE_REPLAY_ATTACK)
	}

	// 3. Verify Client Signature
	// Signature covers: SessionID || Nonce || EncryptedPayload
	sig_payload := make([]byte, 16+8+len(req.EncryptedPayload))
	copy(sig_payload[0:16], req.SessionID[:])
	binary.BigEndian.PutUint64(sig_payload[16:24], req.Nonce)
	copy(sig_payload[24:], req.EncryptedPayload)

	is_valid, err := s.crypt.Verify(shared.CTX_CLIENT_SESSION_SIGNING, sig_payload, req.Signature, session_state.ClientSigningPubKey)
	if err != nil || !is_valid {
		return s.build_error_response(shared.ERR_CODE_INVALID_SIGNATURE)
	}

	// 4. Decrypt EncryptedPayload
	enc_pkg := &protocol.EncryptedPackage{}
	if err := enc_pkg.UnmarshalBinary(req.EncryptedPayload); err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_PROTOCOL)
	}

	app_payload, err := s.crypt.DecryptFull(shared.CTX_AEAD_GENERAL_PAYLOAD, enc_pkg.Ciphertext, session_state.SessionSymKey[:], nil, enc_pkg.Tag, enc_pkg.Nonce, true)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INVALID_PROTOCOL)
	}

	if len(app_payload) == 0 {
		return s.build_error_response(shared.ERR_CODE_INSUFFICIENT_DATA)
	}

	// 5. Burn Nonce (Update Storage)
	// We update the nonce AFTER successful decryption to prevent an attacker
	// from exhausting the client's nonce space with invalid signatures.
	session_state.HighestSeenNonce = req.Nonce
	updated_state_bytes, err := session_state.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}
	if err := s.storage.Store(shared.STORE_CTX_SESSION_KEY, req.SessionID[:], updated_state_bytes); err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// 6. Route Application Payload
	app_opcode := app_payload[0]
	app_response_payload, err := s.dispatch_app_request(req.SessionID, session_state, app_opcode, app_payload)
	if err != nil {
		// For now, unimplemented or unknown opcodes return UNKNOWN_MSG_TYPE
		return s.build_error_response(shared.ERR_CODE_UNKNOWN_MSG_TYPE)
	}

	// 7. Build GeneralResponse
	// Encrypt app response payload
	nonce_res, ct_res, tag_res, err := s.crypt.EncryptFull(shared.CTX_AEAD_GENERAL_PAYLOAD, app_response_payload, session_state.SessionSymKey[:], nil)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	res_enc_pkg := &protocol.EncryptedPackage{Nonce: nonce_res, Ciphertext: ct_res, Tag: tag_res}
	res_enc_bytes, err := res_enc_pkg.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	// Sign response payload with Server's Private Key
	sig, err := s.crypt.Sign(shared.CTX_SERVER_SESSION_SIGNING, res_enc_bytes, session_state.ServerSigningPrivKey)
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	res := &protocol.GeneralResponse{
		EncryptedPayload: res_enc_bytes,
		Signature:        sig,
	}

	final_response, err := res.MarshalBinary()
	if err != nil {
		return s.build_error_response(shared.ERR_CODE_INTERNAL_SERVER)
	}

	return final_response
}
