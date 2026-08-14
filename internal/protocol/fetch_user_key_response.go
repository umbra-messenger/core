package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// FetchUserKeyResponse represents the server's response containing the encrypted master key.
type FetchUserKeyResponse struct {
	EncryptedMasterKey []byte
}

func (f *FetchUserKeyResponse) MarshalBinary() ([]byte, error) {
	if f.EncryptedMasterKey == nil {
		return nil, errors.New("protocol: FetchUserKeyResponse EncryptedMasterKey cannot be nil")
	}
	len_enc_key := uint64(len(f.EncryptedMasterKey))

	total_size := 8 + int(len_enc_key) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_enc_key)
	offset += 8
	copy(buf[offset:offset+int(len_enc_key)], f.EncryptedMasterKey)
	offset += int(len_enc_key)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (f *FetchUserKeyResponse) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 16 // 24 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for FetchUserKeyResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_enc_key := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_enc_key) > payload_length {
		return errors.New("protocol: underflow reading EncryptedMasterKey")
	}
	f.EncryptedMasterKey = make([]byte, len_enc_key)
	copy(f.EncryptedMasterKey, data[offset:offset+int(len_enc_key)])
	offset += int(len_enc_key)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
