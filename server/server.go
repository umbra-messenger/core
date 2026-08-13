package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

const (
	CTX_STORAGE_CRYPTO = "session_state_storage"
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
	is_valid, err := crypto.Verify(shared.CTX_HANDSHAKE_INIT_SIG, init_msg.ExchangePublicKey, init_msg.ExchangeKeySignature, init_msg.SigningPublicKey)
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
	server_exchange_pub, server_exchange_priv, err := crypto.DeriveExchangeKeyPair(shared.CTX_EXCHANGE_KEY_DERIV, server_master_key)
	if err != nil {
		return fmt.Errorf("server: failed to derive exchange keys: %w", err)
	}

	server_signing_pub, server_signing_priv, err := crypto.DeriveSigningKeyPair(shared.CTX_SIGNING_KEY_DERIV, server_master_key)
	if err != nil {
		return fmt.Errorf("server: failed to derive signing keys: %w", err)
	}

	// 5. Derive Shared Secret
	shared_secret, err := crypto.DeriveSharedSecret(shared.CTX_SHARED_SECRET_DERIV, server_exchange_priv, init_msg.ExchangePublicKey)
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
	puzzle_key, err := crypto.HashPassword(shared.CTX_PUZZLE_KEY_DERIV, puzzle_int_bytes, session_id, 32)
	if err != nil {
		return fmt.Errorf("server: failed to derive puzzle key: %w", err)
	}

	nonce1, ct1, tag1, err := crypto.EncryptFull(shared.CTX_SESSION_TOKEN_CRYPTO, session_token, puzzle_key)
	if err != nil {
		return fmt.Errorf("server: failed to encrypt session token: %w", err)
	}

	token_ep := protocol.EncryptedPackage{Nonce: nonce1, Ciphertext: ct1, Tag: tag1}
	token_ep_bytes, err := token_ep.MarshalBinary()
	if err != nil {
		return fmt.Errorf("server: failed to marshal token package: %w", err)
	}

	// 8. Hash Puzzle Integer
	hashed_random_key, err := crypto.Hash(shared.CTX_PUZZLE_HASH, puzzle_int_bytes, 32)
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

	nonce2, ct2, tag2, err := crypto.EncryptFull(shared.CTX_CHALLENGE_PAYLOAD_CRYPTO, payload_bytes, shared_secret)
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

	signature, err := crypto.Sign(shared.CTX_HANDSHAKE_CHALLENGE_SIG, sig_data, server_signing_priv)
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

	// 12. Store Initial Session State (IsEstablished = false)
	state := protocol.SessionState{
		ClientExchangePublicKey: init_msg.ExchangePublicKey,
		ClientSigningPublicKey:  init_msg.SigningPublicKey,
		ServerMasterKey:         server_master_key,
		SessionToken:            session_token,
		IsEstablished:           false,
	}

	if err := saveState(storage, crypto, state, session_id); err != nil {
		return err
	}

	// Derive session symmetric key for future requests
	session_sym_key, err := crypto.Hash(shared.CTX_SESSION_KEY_DERIV, shared_secret, 32)
	if err != nil {
		return fmt.Errorf("server: failed to derive session symmetric key: %w", err)
	}

	// 13. Main Request/Response Loop
	for {
		req_data, err := transport.Receive()
		if err != nil {
			return fmt.Errorf("server: failed to receive request: %w", err)
		}

		var req protocol.GeneralRequest
		if err := req.UnmarshalBinary(req_data); err != nil {
			return fmt.Errorf("server: failed to unmarshal request: %w", err)
		}

		// Load Session State
		state, err := loadState(storage, crypto, req.SessionID)
		if err != nil {
			return fmt.Errorf("server: session load failed: %w", err)
		}

		// Verify Request Signature
		req_sig_data := make([]byte, 0, len(req.SessionID)+len(req.SessionToken)+len(req.Nonce)+len(req.EncryptedPayload))
		req_sig_data = append(req_sig_data, req.SessionID...)
		req_sig_data = append(req_sig_data, req.SessionToken...)
		req_sig_data = append(req_sig_data, req.Nonce...)
		req_sig_data = append(req_sig_data, req.EncryptedPayload...)

		is_valid, err := crypto.Verify(shared.CTX_GENERAL_REQUEST_SIG, req_sig_data, req.Signature, state.ClientSigningPublicKey)
		if err != nil {
			return fmt.Errorf("server: crypto verify failed: %w", err)
		}
		if !is_valid {
			_ = storage.Delete(shared.STORE_CTX_SESSION_KEY, string(req.SessionID))
			return errors.New("server: invalid request signature")
		}

		// Check Nonce Replay via Storage
		nonce_key := string(req.SessionID) + "_" + string(req.Nonce)
		_, err = storage.Retrieve(shared.STORE_CTX_NONCE, nonce_key)
		if err == nil {
			_ = storage.Delete(shared.STORE_CTX_SESSION_KEY, string(req.SessionID))
			return errors.New("server: nonce replay detected")
		}
		// Store nonce
		_ = storage.Store(shared.STORE_CTX_NONCE, nonce_key, []byte{1})

		is_verification := len(req.EncryptedPayload) == 0

		if is_verification {
			if state.IsEstablished {
				_ = storage.Delete(shared.STORE_CTX_SESSION_KEY, string(req.SessionID))
				return errors.New("server: verification request on established session")
			}

			if !bytes.Equal(req.SessionToken, state.SessionToken) {
				_ = storage.Delete(shared.STORE_CTX_SESSION_KEY, string(req.SessionID))
				return errors.New("server: invalid session token during verification")
			}

			// Success: Update State
			state.IsEstablished = true
			if err := saveState(storage, crypto, state, req.SessionID); err != nil {
				return err
			}

			// Send Success Response (Empty payload, signed)
			resp := protocol.GeneralResponse{
				EncryptedPayload: []byte{},
			}
			resp.Signature, err = crypto.Sign(shared.CTX_GENERAL_RESPONSE_SIG, resp.EncryptedPayload, server_signing_priv)
			if err != nil {
				return fmt.Errorf("server: failed to sign response: %w", err)
			}

			resp_bytes, err := resp.MarshalBinary()
			if err != nil {
				return fmt.Errorf("server: failed to marshal response: %w", err)
			}
			if err := transport.Send(resp_bytes); err != nil {
				return fmt.Errorf("server: failed to send response: %w", err)
			}
			continue
		}

		// Normal Request Processing
		if !state.IsEstablished {
			_ = storage.Delete(shared.STORE_CTX_SESSION_KEY, string(req.SessionID))
			return errors.New("server: normal request on unestablished session")
		}

		// Decrypt payload
		var req_ep protocol.EncryptedPackage
		if err := req_ep.UnmarshalBinary(req.EncryptedPayload); err != nil {
			return fmt.Errorf("server: failed to unmarshal request payload: %w", err)
		}

		plaintext, err := crypto.DecryptFull(shared.CTX_GENERAL_REQUEST_CRYPTO, req_ep.Ciphertext, req_ep.Tag, req_ep.Nonce, session_sym_key, false)
		if err != nil {
			return fmt.Errorf("server: failed to decrypt request payload: %w", err)
		}

		// TODO: Process plaintext application logic here
		_ = plaintext

		// Build Response
		resp_plain := []byte("OK")
		nonce_resp, ct_resp, tag_resp, err := crypto.EncryptFull(shared.CTX_GENERAL_RESPONSE_CRYPTO, resp_plain, session_sym_key)
		if err != nil {
			return fmt.Errorf("server: failed to encrypt response payload: %w", err)
		}

		resp_ep := protocol.EncryptedPackage{Nonce: nonce_resp, Ciphertext: ct_resp, Tag: tag_resp}
		resp_ep_bytes, err := resp_ep.MarshalBinary()
		if err != nil {
			return fmt.Errorf("server: failed to marshal response payload: %w", err)
		}

		resp := protocol.GeneralResponse{
			EncryptedPayload: resp_ep_bytes,
		}
		resp.Signature, err = crypto.Sign(shared.CTX_GENERAL_RESPONSE_SIG, resp.EncryptedPayload, server_signing_priv)
		if err != nil {
			return fmt.Errorf("server: failed to sign response: %w", err)
		}

		resp_bytes, err := resp.MarshalBinary()
		if err != nil {
			return fmt.Errorf("server: failed to marshal response: %w", err)
		}
		if err := transport.Send(resp_bytes); err != nil {
			return fmt.Errorf("server: failed to send response: %w", err)
		}
	}
}

// saveState marshals and securely stores the SessionState.
func saveState(storage shared.Storage, crypto crypt.CryptoSuite, state protocol.SessionState, session_id []byte) error {
	state_bytes, err := state.MarshalBinary()
	if err != nil {
		return fmt.Errorf("server: failed to marshal session state: %w", err)
	}

	if !storage.IsSafe() {
		temp_key := storage.GetTempKey()
		nonce, ct, tag, err := crypto.EncryptFull(CTX_STORAGE_CRYPTO, state_bytes, temp_key)
		if err != nil {
			return fmt.Errorf("server: failed to encrypt state for storage: %w", err)
		}
		ep := protocol.EncryptedPackage{Nonce: nonce, Ciphertext: ct, Tag: tag}
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

// loadState retrieves and decrypts the SessionState from storage.
func loadState(storage shared.Storage, crypto crypt.CryptoSuite, session_id []byte) (protocol.SessionState, error) {
	var state protocol.SessionState

	state_bytes, err := storage.Retrieve(shared.STORE_CTX_SESSION_KEY, string(session_id))
	if err != nil {
		return state, fmt.Errorf("session not found or retrieve failed: %w", err)
	}

	if !storage.IsSafe() {
		temp_key := storage.GetTempKey()
		var ep protocol.EncryptedPackage
		if err := ep.UnmarshalBinary(state_bytes); err != nil {
			return state, fmt.Errorf("failed to unmarshal encrypted state: %w", err)
		}
		state_bytes, err = crypto.DecryptFull(CTX_STORAGE_CRYPTO, ep.Ciphertext, ep.Tag, ep.Nonce, temp_key, false)
		if err != nil {
			return state, fmt.Errorf("failed to decrypt state: %w", err)
		}
	}

	if err := state.UnmarshalBinary(state_bytes); err != nil {
		return state, fmt.Errorf("failed to unmarshal session state: %w", err)
	}
	return state, nil
}
