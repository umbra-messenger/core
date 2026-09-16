package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// HandshakeChallenge is the server's response to HandshakeInit.
type HandshakeChallenge struct {
	// SessionID is the 16-byte unique identifier for this session attempt.
	SessionID [16]byte
	// ExchangePublicKey is the server's ephemeral X25519 public key for this session.
	ExchangePublicKey []byte
	// SigningPublicKey is the server's ephemeral Ed25519 public key for this session.
	SigningPublicKey []byte
	// EncryptedSessionPuzzle holds the serialized EncryptedPackage containing the puzzle and encrypted token.
	EncryptedSessionPuzzle []byte
	// SessionCookie is the AEAD-encrypted server state blob to prevent state-exhaustion DoS.
	SessionCookie []byte
	// Signature is the server's signature over the preceding payload.
	Signature []byte
}

func (h *HandshakeChallenge) MarshalBinary() ([]byte, error) {
	if h.ExchangePublicKey == nil || h.SigningPublicKey == nil || h.EncryptedSessionPuzzle == nil || h.SessionCookie == nil || h.Signature == nil {
		return nil, errors.New("protocol: HandshakeChallenge contains nil slices")
	}

	exchange_pub_len := uint64(len(h.ExchangePublicKey))
	signing_pub_len := uint64(len(h.SigningPublicKey))
	enc_puzzle_len := uint64(len(h.EncryptedSessionPuzzle))
	cookie_len := uint64(len(h.SessionCookie))
	signature_len := uint64(len(h.Signature))

	// 1 (type) + 16 (session_id) + 5*(8 (len) + data) + 16 (checksum)
	total_size := 1 + 16 + 8 + int(exchange_pub_len) + 8 + int(signing_pub_len) + 8 + int(enc_puzzle_len) + 8 + int(cookie_len) + 8 + int(signature_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. MessageType (Wire-format)
	buf[offset] = shared.MSG_HANDSHAKE_CHALLENGE
	offset += 1

	// 2. SessionID (Fixed 16 bytes)
	copy(buf[offset:offset+16], h.SessionID[:])
	offset += 16

	// 3. ExchangePublicKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], exchange_pub_len)
	offset += 8
	copy(buf[offset:offset+int(exchange_pub_len)], h.ExchangePublicKey)
	offset += int(exchange_pub_len)

	// 4. SigningPublicKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], signing_pub_len)
	offset += 8
	copy(buf[offset:offset+int(signing_pub_len)], h.SigningPublicKey)
	offset += int(signing_pub_len)

	// 5. EncryptedSessionPuzzle
	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_puzzle_len)
	offset += 8
	copy(buf[offset:offset+int(enc_puzzle_len)], h.EncryptedSessionPuzzle)
	offset += int(enc_puzzle_len)

	// 6. SessionCookie
	binary.BigEndian.PutUint64(buf[offset:offset+8], cookie_len)
	offset += 8
	copy(buf[offset:offset+int(cookie_len)], h.SessionCookie)
	offset += int(cookie_len)

	// 7. Signature
	binary.BigEndian.PutUint64(buf[offset:offset+8], signature_len)
	offset += 8
	copy(buf[offset:offset+int(signature_len)], h.Signature)
	offset += int(signature_len)

	// 8. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (h *HandshakeChallenge) UnmarshalBinary(data []byte) error {
	// Min size: 1 (type) + 16 (session_id) + 5*8 (lengths) + 16 (checksum) = 73 bytes
	const min_size = 1 + 16 + 40 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for HandshakeChallenge")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in HandshakeChallenge")
	}

	offset := 0

	// 1. MessageType
	msg_type := data[offset]
	offset += 1
	if msg_type != shared.MSG_HANDSHAKE_CHALLENGE {
		return errors.New("protocol: invalid MessageType for HandshakeChallenge")
	}

	// 2. SessionID (Fixed 16 bytes)
	if offset+16 > payload_length {
		return errors.New("protocol: underflow reading SessionID")
	}
	copy(h.SessionID[:], data[offset:offset+16])
	offset += 16

	// 3. ExchangePublicKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading ExchangePublicKey length")
	}
	exchange_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(exchange_pub_len) > payload_length {
		return errors.New("protocol: underflow reading ExchangePublicKey data")
	}
	h.ExchangePublicKey = make([]byte, exchange_pub_len)
	copy(h.ExchangePublicKey, data[offset:offset+int(exchange_pub_len)])
	offset += int(exchange_pub_len)

	// 4. SigningPublicKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SigningPublicKey length")
	}
	signing_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(signing_pub_len) > payload_length {
		return errors.New("protocol: underflow reading SigningPublicKey data")
	}
	h.SigningPublicKey = make([]byte, signing_pub_len)
	copy(h.SigningPublicKey, data[offset:offset+int(signing_pub_len)])
	offset += int(signing_pub_len)

	// 5. EncryptedSessionPuzzle
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedSessionPuzzle length")
	}
	enc_puzzle_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(enc_puzzle_len) > payload_length {
		return errors.New("protocol: underflow reading EncryptedSessionPuzzle data")
	}
	h.EncryptedSessionPuzzle = make([]byte, enc_puzzle_len)
	copy(h.EncryptedSessionPuzzle, data[offset:offset+int(enc_puzzle_len)])
	offset += int(enc_puzzle_len)

	// 6. SessionCookie
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SessionCookie length")
	}
	cookie_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(cookie_len) > payload_length {
		return errors.New("protocol: underflow reading SessionCookie data")
	}
	h.SessionCookie = make([]byte, cookie_len)
	copy(h.SessionCookie, data[offset:offset+int(cookie_len)])
	offset += int(cookie_len)

	// 7. Signature
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	signature_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(signature_len) > payload_length {
		return errors.New("protocol: underflow reading Signature data")
	}
	h.Signature = make([]byte, signature_len)
	copy(h.Signature, data[offset:offset+int(signature_len)])
	offset += int(signature_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in HandshakeChallenge")
	}

	return nil
}
