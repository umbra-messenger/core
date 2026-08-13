package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// GeneralRequest represents a post-handshake client-to-server message.
// It carries the session credentials, a nonce, the encrypted payload,
// and a signature covering session_id || session_token || nonce || encrypted_payload.
type GeneralRequest struct {
	SessionID        []byte
	SessionToken     []byte
	Nonce            []byte
	EncryptedPayload []byte
	Signature        []byte
}

// MarshalBinary serializes the GeneralRequest struct into a binary envelope.
// Binary Layout:
//
//	[8 bytes] session_id_length
//	[N bytes] SessionID
//	[8 bytes] session_token_length
//	[M bytes] SessionToken
//	[8 bytes] nonce_length
//	[P bytes] Nonce
//	[8 bytes] encrypted_payload_length
//	[Q bytes] EncryptedPayload
//	[8 bytes] signature_length
//	[R bytes] Signature
//	[16 bytes] checksum
func (g *GeneralRequest) MarshalBinary() ([]byte, error) {
	if g.SessionID == nil {
		return nil, errors.New("protocol: SessionID is nil")
	}
	if g.SessionToken == nil {
		return nil, errors.New("protocol: SessionToken is nil")
	}
	if g.Nonce == nil {
		return nil, errors.New("protocol: Nonce is nil")
	}
	if g.EncryptedPayload == nil {
		return nil, errors.New("protocol: EncryptedPayload is nil")
	}
	if g.Signature == nil {
		return nil, errors.New("protocol: Signature is nil")
	}

	session_id_length := uint64(len(g.SessionID))
	session_token_length := uint64(len(g.SessionToken))
	nonce_length := uint64(len(g.Nonce))
	encrypted_payload_length := uint64(len(g.EncryptedPayload))
	signature_length := uint64(len(g.Signature))

	totalSize := 8 + int(session_id_length) +
		8 + int(session_token_length) +
		8 + int(nonce_length) +
		8 + int(encrypted_payload_length) +
		8 + int(signature_length) +
		16

	buf := make([]byte, totalSize)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], session_id_length)
	offset += 8
	copy(buf[offset:offset+int(session_id_length)], g.SessionID)
	offset += int(session_id_length)

	binary.BigEndian.PutUint64(buf[offset:offset+8], session_token_length)
	offset += 8
	copy(buf[offset:offset+int(session_token_length)], g.SessionToken)
	offset += int(session_token_length)

	binary.BigEndian.PutUint64(buf[offset:offset+8], nonce_length)
	offset += 8
	copy(buf[offset:offset+int(nonce_length)], g.Nonce)
	offset += int(nonce_length)

	binary.BigEndian.PutUint64(buf[offset:offset+8], encrypted_payload_length)
	offset += 8
	copy(buf[offset:offset+int(encrypted_payload_length)], g.EncryptedPayload)
	offset += int(encrypted_payload_length)

	binary.BigEndian.PutUint64(buf[offset:offset+8], signature_length)
	offset += 8
	copy(buf[offset:offset+int(signature_length)], g.Signature)
	offset += int(signature_length)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

// UnmarshalBinary deserializes binary data into the GeneralRequest struct.
// It validates input length, verifies the trailing checksum immediately to fail fast,
// and then parses the payload checking for underflow.
func (g *GeneralRequest) UnmarshalBinary(data []byte) error {
	const minSize = 56 // (8 * 5) + 16
	if len(data) < minSize {
		return errors.New("protocol: data too short for GeneralRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0

	session_id_length := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(session_id_length) > payload_length {
		return errors.New("protocol: underflow reading SessionID")
	}
	g.SessionID = make([]byte, session_id_length)
	copy(g.SessionID, data[offset:offset+int(session_id_length)])
	offset += int(session_id_length)

	session_token_length := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(session_token_length) > payload_length {
		return errors.New("protocol: underflow reading SessionToken")
	}
	g.SessionToken = make([]byte, session_token_length)
	copy(g.SessionToken, data[offset:offset+int(session_token_length)])
	offset += int(session_token_length)

	nonce_length := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(nonce_length) > payload_length {
		return errors.New("protocol: underflow reading Nonce")
	}
	g.Nonce = make([]byte, nonce_length)
	copy(g.Nonce, data[offset:offset+int(nonce_length)])
	offset += int(nonce_length)

	encrypted_payload_length := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(encrypted_payload_length) > payload_length {
		return errors.New("protocol: underflow reading EncryptedPayload")
	}
	g.EncryptedPayload = make([]byte, encrypted_payload_length)
	copy(g.EncryptedPayload, data[offset:offset+int(encrypted_payload_length)])
	offset += int(encrypted_payload_length)

	signature_length := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(signature_length) > payload_length {
		return errors.New("protocol: underflow reading Signature")
	}
	g.Signature = make([]byte, signature_length)
	copy(g.Signature, data[offset:offset+int(signature_length)])
	offset += int(signature_length)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}

	return nil
}
