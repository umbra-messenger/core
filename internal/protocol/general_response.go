package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// GeneralResponse represents a post-handshake server-to-client message.
// It carries the encrypted payload and a signature over the encrypted payload.
type GeneralResponse struct {
	EncryptedPayload []byte
	Signature        []byte
}

// MarshalBinary serializes the GeneralResponse struct into a binary envelope.
// Binary Layout:
//
//	[8 bytes] encrypted_payload_length
//	[N bytes] EncryptedPayload
//	[8 bytes] signature_length
//	[M bytes] Signature
//	[16 bytes] checksum
func (g *GeneralResponse) MarshalBinary() ([]byte, error) {
	if g.EncryptedPayload == nil {
		return nil, errors.New("protocol: EncryptedPayload is nil")
	}
	if g.Signature == nil {
		return nil, errors.New("protocol: Signature is nil")
	}

	encrypted_payload_length := uint64(len(g.EncryptedPayload))
	signature_length := uint64(len(g.Signature))

	totalSize := 8 + int(encrypted_payload_length) +
		8 + int(signature_length) +
		16

	buf := make([]byte, totalSize)
	offset := 0

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

// UnmarshalBinary deserializes binary data into the GeneralResponse struct.
// It validates input length, verifies the trailing checksum immediately to fail fast,
// and then parses the payload checking for underflow.
func (g *GeneralResponse) UnmarshalBinary(data []byte) error {
	const minSize = 32 // (8 * 2) + 16
	if len(data) < minSize {
		return errors.New("protocol: data too short for GeneralResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0

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
