package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// HandshakeInit is the first message sent by the client to start an anonymous session.
type HandshakeInit struct {
	// ExchangePublicKey is the client's ephemeral KEM public key.
	ExchangePublicKey []byte
	// SigningPublicKey is the client's ephemeral signing public key.
	SigningPublicKey []byte
	// ExchangeKeySignature is the signature over ExchangePublicKey, signed by SigningPublicKey's private key.
	ExchangeKeySignature []byte
}

func (h *HandshakeInit) MarshalBinary() ([]byte, error) {
	if h.ExchangePublicKey == nil || h.SigningPublicKey == nil || h.ExchangeKeySignature == nil {
		return nil, errors.New("protocol: HandshakeInit contains nil slices")
	}

	exchange_pub_len := uint64(len(h.ExchangePublicKey))
	signing_pub_len := uint64(len(h.SigningPublicKey))
	exchange_sig_len := uint64(len(h.ExchangeKeySignature))

	// 1 (type) + 8 (len) + data + 8 (len) + data + 8 (len) + data + 16 (checksum)
	total_size := 1 + 8 + int(exchange_pub_len) + 8 + int(signing_pub_len) + 8 + int(exchange_sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.MSG_HANDSHAKE_INIT
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], exchange_pub_len)
	offset += 8
	copy(buf[offset:offset+int(exchange_pub_len)], h.ExchangePublicKey)
	offset += int(exchange_pub_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], signing_pub_len)
	offset += 8
	copy(buf[offset:offset+int(signing_pub_len)], h.SigningPublicKey)
	offset += int(signing_pub_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], exchange_sig_len)
	offset += 8
	copy(buf[offset:offset+int(exchange_sig_len)], h.ExchangeKeySignature)
	offset += int(exchange_sig_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (h *HandshakeInit) UnmarshalBinary(data []byte) error {
	// Min size: 1 (type) + 8*3 (lengths) + 16 (checksum) = 41 bytes
	const min_size = 41
	if len(data) < min_size {
		return errors.New("protocol: data too short for HandshakeInit")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in HandshakeInit")
	}

	offset := 0

	msg_type := data[offset]
	offset += 1
	if msg_type != shared.MSG_HANDSHAKE_INIT {
		return errors.New("protocol: invalid MessageType for HandshakeInit")
	}

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading ExchangePublicKey length")
	}
	exchange_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if exchange_pub_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading ExchangePublicKey data")
	}
	h.ExchangePublicKey = make([]byte, int(exchange_pub_len))
	copy(h.ExchangePublicKey, data[offset:offset+int(exchange_pub_len)])
	offset += int(exchange_pub_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SigningPublicKey length")
	}
	signing_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if signing_pub_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading SigningPublicKey data")
	}
	h.SigningPublicKey = make([]byte, int(signing_pub_len))
	copy(h.SigningPublicKey, data[offset:offset+int(signing_pub_len)])
	offset += int(signing_pub_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading ExchangeKeySignature length")
	}
	exchange_sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if exchange_sig_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading ExchangeKeySignature data")
	}
	h.ExchangeKeySignature = make([]byte, int(exchange_sig_len))
	copy(h.ExchangeKeySignature, data[offset:offset+int(exchange_sig_len)])
	offset += int(exchange_sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in HandshakeInit")
	}

	return nil
}
