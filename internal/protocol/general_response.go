package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// GeneralResponse is the standard post-handshake response envelope sent by the server.
type GeneralResponse struct {
	// EncryptedPayload holds the serialized EncryptedPackage containing the application response data.
	EncryptedPayload []byte
	// Signature is the server's Ed25519 signature over the EncryptedPayload.
	Signature []byte
}

func (g *GeneralResponse) MarshalBinary() ([]byte, error) {
	if g.EncryptedPayload == nil || g.Signature == nil {
		return nil, errors.New("protocol: GeneralResponse contains nil slices")
	}

	enc_payload_len := uint64(len(g.EncryptedPayload))
	signature_len := uint64(len(g.Signature))

	// 1 (type) + 8 (len1) + data1 + 8 (len2) + data2 + 16 (checksum)
	total_size := 1 + 8 + int(enc_payload_len) + 8 + int(signature_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. MessageType (Wire-format)
	buf[offset] = shared.MSG_GENERAL_RES
	offset += 1

	// 2. EncryptedPayload
	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_payload_len)
	offset += 8
	copy(buf[offset:offset+int(enc_payload_len)], g.EncryptedPayload)
	offset += int(enc_payload_len)

	// 3. Signature
	binary.BigEndian.PutUint64(buf[offset:offset+8], signature_len)
	offset += 8
	copy(buf[offset:offset+int(signature_len)], g.Signature)
	offset += int(signature_len)

	// 4. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GeneralResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (type) + 8*2 (lengths) + 16 (checksum) = 33 bytes
	const min_size = 1 + 16 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for GeneralResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in GeneralResponse")
	}

	offset := 0

	// 1. MessageType
	msg_type := data[offset]
	offset += 1
	if msg_type != shared.MSG_GENERAL_RES {
		return errors.New("protocol: invalid MessageType for GeneralResponse")
	}

	// 2. EncryptedPayload
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

	// 3. Signature
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
		return errors.New("protocol: unexpected trailing data in GeneralResponse")
	}

	return nil
}
