package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// HandshakeInit represents the initial handshake message sent by the client.
type HandshakeInit struct {
	ExchangePublicKey    []byte
	SigningPublicKey     []byte
	ExchangeKeySignature []byte
}

func (h *HandshakeInit) MarshalBinary() ([]byte, error) {
	if h.ExchangePublicKey == nil || h.SigningPublicKey == nil || h.ExchangeKeySignature == nil {
		return nil, errors.New("protocol: HandshakeInit fields cannot be nil")
	}
	len_exch_pub := uint64(len(h.ExchangePublicKey))
	len_sign_pub := uint64(len(h.SigningPublicKey))
	len_exch_sig := uint64(len(h.ExchangeKeySignature))

	total_size := 8 + int(len_exch_pub) + 8 + int(len_sign_pub) + 8 + int(len_exch_sig) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_exch_pub)
	offset += 8
	copy(buf[offset:offset+int(len_exch_pub)], h.ExchangePublicKey)
	offset += int(len_exch_pub)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sign_pub)
	offset += 8
	copy(buf[offset:offset+int(len_sign_pub)], h.SigningPublicKey)
	offset += int(len_sign_pub)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_exch_sig)
	offset += 8
	copy(buf[offset:offset+int(len_exch_sig)], h.ExchangeKeySignature)
	offset += int(len_exch_sig)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (h *HandshakeInit) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 8 + 8 + 16 // 40 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for HandshakeInit")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_exch_pub := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_exch_pub) > payload_length {
		return errors.New("protocol: underflow reading ExchangePublicKey")
	}
	h.ExchangePublicKey = make([]byte, len_exch_pub)
	copy(h.ExchangePublicKey, data[offset:offset+int(len_exch_pub)])
	offset += int(len_exch_pub)

	len_sign_pub := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sign_pub) > payload_length {
		return errors.New("protocol: underflow reading SigningPublicKey")
	}
	h.SigningPublicKey = make([]byte, len_sign_pub)
	copy(h.SigningPublicKey, data[offset:offset+int(len_sign_pub)])
	offset += int(len_sign_pub)

	len_exch_sig := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_exch_sig) > payload_length {
		return errors.New("protocol: underflow reading ExchangeKeySignature")
	}
	h.ExchangeKeySignature = make([]byte, len_exch_sig)
	copy(h.ExchangeKeySignature, data[offset:offset+int(len_exch_sig)])
	offset += int(len_exch_sig)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
