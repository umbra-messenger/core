package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

// Run executes the client-side state machine for a single session.
func Run(transport shared.Transport, storage shared.Storage, crypto crypt.CryptoSuite) error {
	if transport == nil || storage == nil || crypto == nil {
		return errors.New("client: injected dependencies cannot be nil")
	}

	// 1. Generate client master key
	var client_master_key [32]byte
	if err := crypto.Rand(client_master_key[:]); err != nil {
		return fmt.Errorf("client: failed to generate master key: %w", err)
	}

	// 2. Derive keys
	client_exch_pub, client_exch_priv, err := crypto.DeriveExchangeKeyPair(shared.CTX_EXCHANGE_KEY_DERIV, client_master_key)
	if err != nil {
		return fmt.Errorf("client: failed to derive exchange keys: %w", err)
	}
	client_sign_pub, client_sign_priv, err := crypto.DeriveSigningKeyPair(shared.CTX_SIGNING_KEY_DERIV, client_master_key)
	if err != nil {
		return fmt.Errorf("client: failed to derive signing keys: %w", err)
	}

	// 3. Sign exchange pub
	exch_sig, err := crypto.Sign(shared.CTX_HANDSHAKE_INIT_SIG, client_exch_pub, client_sign_priv)
	if err != nil {
		return fmt.Errorf("client: failed to sign exchange key: %w", err)
	}

	// 4. Send HandshakeInit
	init_msg := protocol.HandshakeInit{
		ExchangePublicKey:    client_exch_pub,
		SigningPublicKey:     client_sign_pub,
		ExchangeKeySignature: exch_sig,
	}
	init_bytes, err := init_msg.MarshalBinary()
	if err != nil {
		return fmt.Errorf("client: failed to marshal HandshakeInit: %w", err)
	}
	if err := transport.Send(init_bytes); err != nil {
		return fmt.Errorf("client: failed to send HandshakeInit: %w", err)
	}

	// 5. Receive HandshakeChallenge
	chall_data, err := transport.Receive()
	if err != nil {
		return fmt.Errorf("client: failed to receive HandshakeChallenge: %w", err)
	}
	var challenge protocol.HandshakeChallenge
	if err := challenge.UnmarshalBinary(chall_data); err != nil {
		return fmt.Errorf("client: failed to unmarshal HandshakeChallenge: %w", err)
	}

	// 6. Verify server signature
	sig_data := make([]byte, 0, len(challenge.SessionID)+len(challenge.ExchangePublicKey)+len(challenge.SigningPublicKey)+len(challenge.EncryptedPayload))
	sig_data = append(sig_data, challenge.SessionID...)
	sig_data = append(sig_data, challenge.ExchangePublicKey...)
	sig_data = append(sig_data, challenge.SigningPublicKey...)
	sig_data = append(sig_data, challenge.EncryptedPayload...)

	is_valid, err := crypto.Verify(shared.CTX_HANDSHAKE_CHALLENGE_SIG, sig_data, challenge.Signature, challenge.SigningPublicKey)
	if err != nil {
		return fmt.Errorf("client: crypto verify failed: %w", err)
	}
	if !is_valid {
		return errors.New("client: invalid challenge signature")
	}

	// 7. Derive shared secret
	shared_secret, err := crypto.DeriveSharedSecret(shared.CTX_SHARED_SECRET_DERIV, client_exch_priv, challenge.ExchangePublicKey)
	if err != nil {
		return fmt.Errorf("client: failed to derive shared secret: %w", err)
	}

	// 8. Decrypt outer payload
	var outer_ep protocol.EncryptedPackage
	if err := outer_ep.UnmarshalBinary(challenge.EncryptedPayload); err != nil {
		return fmt.Errorf("client: failed to unmarshal outer package: %w", err)
	}
	payload_bytes, err := crypto.DecryptFull(shared.CTX_CHALLENGE_PAYLOAD_CRYPTO, outer_ep.Ciphertext, outer_ep.Tag, outer_ep.Nonce, shared_secret, false)
	if err != nil {
		return fmt.Errorf("client: failed to decrypt outer payload: %w", err)
	}

	// 9. Unmarshal HandshakeChallengePayload
	var inner_payload protocol.HandshakeChallengePayload
	if err := inner_payload.UnmarshalBinary(payload_bytes); err != nil {
		return fmt.Errorf("client: failed to unmarshal inner payload: %w", err)
	}

	// 10. Brute force
	var puzzle_int_bytes [8]byte
	found := false
	for i := uint64(0); i <= 0x000FFFFF; i++ {
		binary.BigEndian.PutUint64(puzzle_int_bytes[:], i)
		h, err := crypto.Hash(shared.CTX_PUZZLE_HASH, puzzle_int_bytes[:], 32)
		if err != nil {
			return fmt.Errorf("client: hash failed during brute force: %w", err)
		}
		if bytes.Equal(h, inner_payload.HashedRandomKey) {
			found = true
			break
		}
	}
	if !found {
		return errors.New("client: failed to solve brute-force puzzle")
	}

	// 11. Decrypt session token
	puzzle_key, err := crypto.HashPassword(shared.CTX_PUZZLE_KEY_DERIV, puzzle_int_bytes[:], challenge.SessionID, 32)
	if err != nil {
		return fmt.Errorf("client: failed to derive puzzle key: %w", err)
	}
	var token_ep protocol.EncryptedPackage
	if err := token_ep.UnmarshalBinary(inner_payload.EncryptedSessionToken); err != nil {
		return fmt.Errorf("client: failed to unmarshal token package: %w", err)
	}
	session_token, err := crypto.DecryptFull(shared.CTX_SESSION_TOKEN_CRYPTO, token_ep.Ciphertext, token_ep.Tag, token_ep.Nonce, puzzle_key, false)
	if err != nil {
		return fmt.Errorf("client: failed to decrypt session token: %w", err)
	}

	// Derive session symmetric key for future requests
	session_sym_key, err := crypto.Hash(shared.CTX_SESSION_KEY_DERIV, shared_secret, 32)
	if err != nil {
		return fmt.Errorf("client: failed to derive session symmetric key: %w", err)
	}

	// 12. Send Verification Request
	nonce := make([]byte, 16)
	if err := crypto.Rand(nonce); err != nil {
		return fmt.Errorf("client: failed to generate nonce: %w", err)
	}
	empty_payload := []byte{}

	req_sig_data := make([]byte, 0, len(challenge.SessionID)+len(session_token)+len(nonce))
	req_sig_data = append(req_sig_data, challenge.SessionID...)
	req_sig_data = append(req_sig_data, session_token...)
	req_sig_data = append(req_sig_data, nonce...)

	req_sig, err := crypto.Sign(shared.CTX_GENERAL_REQUEST_SIG, req_sig_data, client_sign_priv)
	if err != nil {
		return fmt.Errorf("client: failed to sign verification request: %w", err)
	}

	req := protocol.GeneralRequest{
		SessionID:        challenge.SessionID,
		SessionToken:     session_token,
		Nonce:            nonce,
		EncryptedPayload: empty_payload,
		Signature:        req_sig,
	}
	req_bytes, err := req.MarshalBinary()
	if err != nil {
		return fmt.Errorf("client: failed to marshal verification request: %w", err)
	}
	if err := transport.Send(req_bytes); err != nil {
		return fmt.Errorf("client: failed to send verification request: %w", err)
	}

	// 13. Receive GeneralResponse
	resp_data, err := transport.Receive()
	if err != nil {
		return fmt.Errorf("client: failed to receive verification response: %w", err)
	}
	var resp protocol.GeneralResponse
	if err := resp.UnmarshalBinary(resp_data); err != nil {
		return fmt.Errorf("client: failed to unmarshal verification response: %w", err)
	}

	resp_sig_data := resp.EncryptedPayload
	is_valid_resp, err := crypto.Verify(shared.CTX_GENERAL_RESPONSE_SIG, resp_sig_data, resp.Signature, challenge.SigningPublicKey)
	if err != nil {
		return fmt.Errorf("client: crypto verify failed on response: %w", err)
	}
	if !is_valid_resp {
		return errors.New("client: invalid response signature")
	}

	// 14. General Request Loop
	_ = session_sym_key
	_ = client_sign_priv

	return nil
}
