package server

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

const (
	CTX_SERVER_EXCHANGE    = "server_exchange"
	CTX_SERVER_SIGNING     = "server_signing"
	CTX_PUZZLE_KEY_DERIV   = "puzzle_key_derivation"
	CTX_TOKEN_ENCRYPTION   = "session_token_encryption"
	CTX_CHALLENGE_HASH     = "handshake_challenge"
	CTX_SHARED_SECRET      = "shared_secret_derivation"
	CTX_PAYLOAD_ENCRYPTION = "challenge_payload_encryption"
	CTX_STORAGE_ENCRYPTION = "session_state_storage"
	CTX_INIT_VERIFY        = "handshake_init_verify"
	CTX_CHALLENGE_SIGN     = "handshake_challenge_sign"
)

// Handle initiates the server-side handshake and session loop for a single connected client.
func Handle(transport shared.Transport, storage shared.Storage, crypto crypt.CryptoSuite) error {
	if transport == nil || storage == nil || crypto == nil {
		return errors.New("server: injected dependencies cannot be nil")
	}

	// 1. Receive HandshakeInit
	init_data, err := transport.Receive()
	if err != nil {
		return fmt.Errorf("server: failed to receive HandshakeInit: %w", err)
	}

	var init_msg protocol.HandshakeInit
	if err := init_msg.UnmarshalBinary(init_data); err != nil {
		return fmt.Errorf("server: failed to unmarshal HandshakeInit: %w", err)
	}

	// 2. Verify Client's Exchange Key Signature
	is_valid, err := crypto.Verify(CTX_INIT_VERIFY, init_msg.ExchangePublicKey, init_msg.ExchangeKeySignature, init_msg.SigningPublicKey)
	if err != nil {
		return fmt.Errorf("server: crypto verify failed: %w", err)
	}
	if !is_valid {
		return errors.New("server: invalid exchange key signature")
	}

	// 3. Generate Server Session Master Key
	var server_master_key [32]byte
	if err := crypto.Rand(server_master_key[:]); err != nil {
		return fmt.Errorf("server: failed to generate master key: %w", err)
	}

	// 4. Derive Server Keys
	server_exchange_pub, server_exchange_priv, err := crypto.DeriveExchangeKeyPair(CTX_SERVER_EXCHANGE, server_master_key)
	if err != nil {
		return fmt.Errorf("server: failed to derive exchange keys: %w", err)
	}

	server_signing_pub, server_signing_priv, err := crypto.DeriveSigningKeyPair(CTX_SERVER_SIGNING, server_master_key)
	if err != nil {
		return fmt.Errorf("server: failed to derive signing keys: %w", err)
	}

	// 5. Derive Shared Secret
	shared_secret, err := crypto.DeriveSharedSecret(CTX_SHARED_SECRET, server_exchange_priv, init_msg.ExchangePublicKey)
	if err != nil {
		return fmt.Errorf("server: failed to derive shared secret: %w", err)
	}

	// 6. Generate Session Variables
	session_id := make([]byte, 16)
	if err := crypto.Rand(session_id); err != nil {
		return fmt.Errorf("server: failed to generate session_id: %w", err)
	}

	session_token := make([]byte, 32)
	if err := crypto.Rand(session_token); err != nil {
		return fmt.Errorf("server: failed to generate session_token: %w", err)
	}

	rand_bytes := make([]byte, 4)
	if err := crypto.Rand(rand_bytes); err != nil {
		return fmt.Errorf("server: failed to generate puzzle entropy: %w", err)
	}
	puzzle_int := binary.BigEndian.Uint32(rand_bytes) & 0x000FFFFF
	puzzle_int_bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(puzzle_int_bytes, uint64(puzzle_int))

	// 7. Create Puzzle Key and Encrypt Token
	puzzle_key, err := crypto.HashPassword(CTX_PUZZLE_KEY_DERIV, puzzle_int_bytes, session_id, 32)
	if err != nil {
		return fmt.Errorf("server: failed to derive puzzle key: %w", err)
	}

	nonce1, ct1, tag1, err := crypto.EncryptFull(CTX_TOKEN_ENCRYPTION, session_token, puzzle_key)
	if err != nil {
		return fmt.Errorf("server: failed to encrypt session token: %w", err)
	}

	token_ep := protocol.EncryptedPackage{Nonce: nonce1, Ciphertext: ct1, Tag: tag1}
	token_ep_bytes, err := token_ep.MarshalBinary()
	if err != nil {
		return fmt.Errorf("server: failed to marshal token package: %w", err)
	}

	// 8. Hash Puzzle Integer
	hashed_random_key, err := crypto.Hash(CTX_CHALLENGE_HASH, puzzle_int_bytes, 32)
	if err != nil {
		return fmt.Errorf("server: failed to hash puzzle integer: %w", err)
	}

	// 9. Create and Encrypt Challenge Payload
	payload := protocol.HandshakeChallengePayload{
		EncryptedSessionToken: token_ep_bytes,
		HashedRandomKey:       hashed_random_key,
	}
	payload_bytes, err := payload.MarshalBinary()
	if err != nil {
		return fmt.Errorf("server: failed to marshal challenge payload: %w", err)
	}

	nonce2, ct2, tag2, err := crypto.EncryptFull(CTX_PAYLOAD_ENCRYPTION, payload_bytes, shared_secret)
	if err != nil {
		return fmt.Errorf("server: failed to encrypt challenge payload: %w", err)
	}

	outer_ep := protocol.EncryptedPackage{Nonce: nonce2, Ciphertext: ct2, Tag: tag2}
	outer_ep_bytes, err := outer_ep.MarshalBinary()
	if err != nil {
		return fmt.Errorf("server: failed to marshal outer package: %w", err)
	}

	// 10. Sign the Challenge Data
	sig_data := make([]byte, 0, len(session_id)+len(server_exchange_pub)+len(server_signing_pub)+len(outer_ep_bytes))
	sig_data = append(sig_data, session_id...)
	sig_data = append(sig_data, server_exchange_pub...)
	sig_data = append(sig_data, server_signing_pub...)
	sig_data = append(sig_data, outer_ep_bytes...)

	signature, err := crypto.Sign(CTX_CHALLENGE_SIGN, sig_data, server_signing_priv)
	if err != nil {
		return fmt.Errorf("server: failed to sign challenge: %w", err)
	}

	// 11. Build and Send HandshakeChallenge
	challenge := protocol.HandshakeChallenge{
		SessionID:         session_id,
		ExchangePublicKey: server_exchange_pub,
		SigningPublicKey:  server_signing_pub,
		EncryptedPayload:  outer_ep_bytes,
		Signature:         signature,
	}

	challenge_bytes, err := challenge.MarshalBinary()
	if err != nil {
		return fmt.Errorf("server: failed to marshal HandshakeChallenge: %w", err)
	}

	if err := transport.Send(challenge_bytes); err != nil {
		return fmt.Errorf("server: failed to send HandshakeChallenge: %w", err)
	}

	// 12. Store Session State
	state := protocol.SessionState{
		ClientExchangePublicKey: init_msg.ExchangePublicKey,
		ClientSigningPublicKey:  init_msg.SigningPublicKey,
		ServerMasterKey:         server_master_key,
		SessionToken:            session_token,
	}
	state_bytes, err := state.MarshalBinary()
	if err != nil {
		return fmt.Errorf("server: failed to marshal session state: %w", err)
	}

	if !storage.IsSafe() {
		temp_key := storage.GetTempKey()
		nonce3, ct3, tag3, err := crypto.EncryptFull(CTX_STORAGE_ENCRYPTION, state_bytes, temp_key)
		if err != nil {
			return fmt.Errorf("server: failed to encrypt state for storage: %w", err)
		}
		ep := protocol.EncryptedPackage{Nonce: nonce3, Ciphertext: ct3, Tag: tag3}
		state_bytes, err = ep.MarshalBinary()
		if err != nil {
			return fmt.Errorf("server: failed to marshal encrypted state: %w", err)
		}
	}

	if err := storage.Store(shared.STORE_CTX_SESSION_KEY, string(session_id), state_bytes); err != nil {
		return fmt.Errorf("server: failed to store session state: %w", err)
	}

	return nil
}
