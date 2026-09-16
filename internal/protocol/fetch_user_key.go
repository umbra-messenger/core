package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// FetchUserKeyRequest is sent to retrieve the encrypted master key for a given username.
type FetchUserKeyRequest struct {
	Username []byte
}

func (f *FetchUserKeyRequest) MarshalBinary() ([]byte, error) {
	if f.Username == nil {
		return nil, errors.New("protocol: FetchUserKeyRequest contains nil slices")
	}

	username_len := uint64(len(f.Username))

	// 1 (op) + 8 (len) + data + 16 (checksum)
	total_size := 1 + 8 + int(username_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_FETCH_USER_KEY
	offset += 1

	// 2. Username
	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], f.Username)
	offset += int(username_len)

	// 3. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (f *FetchUserKeyRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (len) + 16 (checksum) = 25 bytes
	const min_size = 1 + 8 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for FetchUserKeyRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in FetchUserKeyRequest")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_FETCH_USER_KEY {
		return errors.New("protocol: invalid App OpCode for FetchUserKeyRequest")
	}

	// 2. Username
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Username length")
	}
	username_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(username_len) > payload_length {
		return errors.New("protocol: underflow reading Username data")
	}
	f.Username = make([]byte, username_len)
	copy(f.Username, data[offset:offset+int(username_len)])
	offset += int(username_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in FetchUserKeyRequest")
	}

	return nil
}

// FetchUserKeyResponse returns the encrypted master key (or a deterministic dummy key).
type FetchUserKeyResponse struct {
	StatusCode         uint8
	EncryptedMasterKey []byte
}

func (f *FetchUserKeyResponse) MarshalBinary() ([]byte, error) {
	if f.EncryptedMasterKey == nil {
		return nil, errors.New("protocol: FetchUserKeyResponse contains nil EncryptedMasterKey")
	}

	enc_master_len := uint64(len(f.EncryptedMasterKey))

	// 1 (op) + 1 (status) + 8 (len) + data + 16 (checksum)
	total_size := 1 + 1 + 8 + int(enc_master_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_FETCH_USER_KEY
	offset += 1

	// 2. StatusCode
	buf[offset] = f.StatusCode
	offset += 1

	// 3. EncryptedMasterKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_master_len)
	offset += 8
	copy(buf[offset:offset+int(enc_master_len)], f.EncryptedMasterKey)
	offset += int(enc_master_len)

	// 4. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (f *FetchUserKeyResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 1 (status) + 8 (len) + 16 (checksum) = 26 bytes
	const min_size = 1 + 1 + 8 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for FetchUserKeyResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in FetchUserKeyResponse")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_FETCH_USER_KEY {
		return errors.New("protocol: invalid App OpCode for FetchUserKeyResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	f.StatusCode = data[offset]
	offset += 1

	// 3. EncryptedMasterKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedMasterKey length")
	}
	enc_master_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(enc_master_len) > payload_length {
		return errors.New("protocol: underflow reading EncryptedMasterKey data")
	}
	f.EncryptedMasterKey = make([]byte, enc_master_len)
	copy(f.EncryptedMasterKey, data[offset:offset+int(enc_master_len)])
	offset += int(enc_master_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in FetchUserKeyResponse")
	}

	return nil
}
