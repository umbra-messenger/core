package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// GeneralRequest is the standard post-handshake request envelope sent by the client.
type GeneralRequest struct {
	// SessionID is the 16-byte identifier for the active session.
	SessionID [16]byte
	// Nonce is a monotonically increasing uint64 counter to prevent replay attacks.
	Nonce uint64
	// EncryptedPayload holds the serialized EncryptedPackage containing the application data.
	EncryptedPayload []byte
	// Signature is the client's Ed25519 signature over (SessionID || Nonce || EncryptedPayload).
	Signature []byte
}

func (g *GeneralRequest) MarshalBinary() ([]byte, error) {
	if g.EncryptedPayload == nil || g.Signature == nil {
		return nil, errors.New("protocol: GeneralRequest contains nil slices")
	}

	enc_payload_len := uint64(len(g.EncryptedPayload))
	signature_len := uint64(len(g.Signature))

	// 1 (type) + 16 (session_id) + 8 (nonce) + 8 (len1) + data1 + 8 (len2) + data2 + 16 (checksum)
	total_size := 1 + 16 + 8 + 8 + int(enc_payload_len) + 8 + int(signature_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. MessageType (Wire-format)
	buf[offset] = shared.MSG_GENERAL_REQ
	offset += 1

	// 2. SessionID (Fixed 16 bytes)
	copy(buf[offset:offset+16], g.SessionID[:])
	offset += 16

	// 3. Nonce (Fixed 8 bytes)
	binary.BigEndian.PutUint64(buf[offset:offset+8], g.Nonce)
	offset += 8

	// 4. EncryptedPayload
	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_payload_len)
	offset += 8
	copy(buf[offset:offset+int(enc_payload_len)], g.EncryptedPayload)
	offset += int(enc_payload_len)

	// 5. Signature
	binary.BigEndian.PutUint64(buf[offset:offset+8], signature_len)
	offset += 8
	copy(buf[offset:offset+int(signature_len)], g.Signature)
	offset += int(signature_len)

	// 6. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GeneralRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (type) + 16 (session_id) + 8 (nonce) + 8*2 (lengths) + 16 (checksum) = 57 bytes
	const min_size = 1 + 16 + 8 + 16 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for GeneralRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in GeneralRequest")
	}

	offset := 0

	// 1. MessageType
	msg_type := data[offset]
	offset += 1
	if msg_type != shared.MSG_GENERAL_REQ {
		return errors.New("protocol: invalid MessageType for GeneralRequest")
	}

	// 2. SessionID (Fixed 16 bytes)
	if offset+16 > payload_length {
		return errors.New("protocol: underflow reading SessionID")
	}
	copy(g.SessionID[:], data[offset:offset+16])
	offset += 16

	// 3. Nonce (Fixed 8 bytes)
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Nonce")
	}
	g.Nonce = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	// 4. EncryptedPayload
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedPayload length")
	}
	enc_payload_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(enc_payload_len) > payload_length {
		return errors.New("protocol: underflow reading EncryptedPayload data")
	}
	g.EncryptedPayload = make([]byte, enc_payload_len)
	copy(g.EncryptedPayload, data[offset:offset+int(enc_payload_len)])
	offset += int(enc_payload_len)

	// 5. Signature
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	signature_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(signature_len) > payload_length {
		return errors.New("protocol: underflow reading Signature data")
	}
	g.Signature = make([]byte, signature_len)
	copy(g.Signature, data[offset:offset+int(signature_len)])
	offset += int(signature_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in GeneralRequest")
	}

	return nil
}
