package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// CreateUserRequest represents a request to register a new user.
type CreateUserRequest struct {
	Username           []byte
	EncryptedMasterKey []byte
	SigningPublicKey   []byte
	ExchangePublicKey  []byte
	Nonce              []byte
	Signature          []byte
}

func (c *CreateUserRequest) MarshalBinary() ([]byte, error) {
	if c.Username == nil || c.EncryptedMasterKey == nil || c.SigningPublicKey == nil || c.ExchangePublicKey == nil || c.Nonce == nil || c.Signature == nil {
		return nil, errors.New("protocol: CreateUserRequest fields cannot be nil")
	}
	len_user := uint64(len(c.Username))
	len_enc_key := uint64(len(c.EncryptedMasterKey))
	len_sign_pub := uint64(len(c.SigningPublicKey))
	len_exch_pub := uint64(len(c.ExchangePublicKey))
	len_nonce := uint64(len(c.Nonce))
	len_sig := uint64(len(c.Signature))

	total_size := 8 + int(len_user) + 8 + int(len_enc_key) + 8 + int(len_sign_pub) + 8 + int(len_exch_pub) + 8 + int(len_nonce) + 8 + int(len_sig) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_user)
	offset += 8
	copy(buf[offset:offset+int(len_user)], c.Username)
	offset += int(len_user)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_enc_key)
	offset += 8
	copy(buf[offset:offset+int(len_enc_key)], c.EncryptedMasterKey)
	offset += int(len_enc_key)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sign_pub)
	offset += 8
	copy(buf[offset:offset+int(len_sign_pub)], c.SigningPublicKey)
	offset += int(len_sign_pub)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_exch_pub)
	offset += 8
	copy(buf[offset:offset+int(len_exch_pub)], c.ExchangePublicKey)
	offset += int(len_exch_pub)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_nonce)
	offset += 8
	copy(buf[offset:offset+int(len_nonce)], c.Nonce)
	offset += int(len_nonce)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sig)
	offset += 8
	copy(buf[offset:offset+int(len_sig)], c.Signature)
	offset += int(len_sig)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *CreateUserRequest) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 8 + 8 + 8 + 8 + 8 + 16 // 64 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for CreateUserRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_user := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_user) > payload_length {
		return errors.New("protocol: underflow reading Username")
	}
	c.Username = make([]byte, len_user)
	copy(c.Username, data[offset:offset+int(len_user)])
	offset += int(len_user)

	len_enc_key := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_enc_key) > payload_length {
		return errors.New("protocol: underflow reading EncryptedMasterKey")
	}
	c.EncryptedMasterKey = make([]byte, len_enc_key)
	copy(c.EncryptedMasterKey, data[offset:offset+int(len_enc_key)])
	offset += int(len_enc_key)

	len_sign_pub := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sign_pub) > payload_length {
		return errors.New("protocol: underflow reading SigningPublicKey")
	}
	c.SigningPublicKey = make([]byte, len_sign_pub)
	copy(c.SigningPublicKey, data[offset:offset+int(len_sign_pub)])
	offset += int(len_sign_pub)

	len_exch_pub := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_exch_pub) > payload_length {
		return errors.New("protocol: underflow reading ExchangePublicKey")
	}
	c.ExchangePublicKey = make([]byte, len_exch_pub)
	copy(c.ExchangePublicKey, data[offset:offset+int(len_exch_pub)])
	offset += int(len_exch_pub)

	len_nonce := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_nonce) > payload_length {
		return errors.New("protocol: underflow reading Nonce")
	}
	c.Nonce = make([]byte, len_nonce)
	copy(c.Nonce, data[offset:offset+int(len_nonce)])
	offset += int(len_nonce)

	len_sig := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sig) > payload_length {
		return errors.New("protocol: underflow reading Signature")
	}
	c.Signature = make([]byte, len_sig)
	copy(c.Signature, data[offset:offset+int(len_sig)])
	offset += int(len_sig)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
