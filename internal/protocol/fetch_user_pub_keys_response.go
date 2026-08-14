package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// FetchUserPubKeysResponse represents the server's response containing user public keys.
type FetchUserPubKeysResponse struct {
	SigningPublicKey  []byte
	ExchangePublicKey []byte
}

func (f *FetchUserPubKeysResponse) MarshalBinary() ([]byte, error) {
	if f.SigningPublicKey == nil || f.ExchangePublicKey == nil {
		return nil, errors.New("protocol: FetchUserPubKeysResponse fields cannot be nil")
	}
	len_sign_pub := uint64(len(f.SigningPublicKey))
	len_exch_pub := uint64(len(f.ExchangePublicKey))

	total_size := 8 + int(len_sign_pub) + 8 + int(len_exch_pub) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sign_pub)
	offset += 8
	copy(buf[offset:offset+int(len_sign_pub)], f.SigningPublicKey)
	offset += int(len_sign_pub)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_exch_pub)
	offset += 8
	copy(buf[offset:offset+int(len_exch_pub)], f.ExchangePublicKey)
	offset += int(len_exch_pub)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (f *FetchUserPubKeysResponse) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 8 + 16 // 32 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for FetchUserPubKeysResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_sign_pub := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sign_pub) > payload_length {
		return errors.New("protocol: underflow reading SigningPublicKey")
	}
	f.SigningPublicKey = make([]byte, len_sign_pub)
	copy(f.SigningPublicKey, data[offset:offset+int(len_sign_pub)])
	offset += int(len_sign_pub)

	len_exch_pub := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_exch_pub) > payload_length {
		return errors.New("protocol: underflow reading ExchangePublicKey")
	}
	f.ExchangePublicKey = make([]byte, len_exch_pub)
	copy(f.ExchangePublicKey, data[offset:offset+int(len_exch_pub)])
	offset += int(len_exch_pub)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
