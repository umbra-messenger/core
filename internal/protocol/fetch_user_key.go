package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// FetchUserKeyRequest is sent to retrieve the encrypted master key for a username.
type FetchUserKeyRequest struct {
	Username         []byte
	Nonce            uint64
	LoginBrakeCookie []byte
}

func (f *FetchUserKeyRequest) MarshalBinary() ([]byte, error) {
	if f.Username == nil || f.LoginBrakeCookie == nil {
		return nil, errors.New("protocol: FetchUserKeyRequest contains nil slices")
	}

	username_len := uint64(len(f.Username))
	cookie_len := uint64(len(f.LoginBrakeCookie))

	// 1 (op) + 8 (len1) + username + 8 (nonce) + 8 (len2) + cookie + 16 (checksum)
	total_size := 1 + 8 + int(username_len) + 8 + 8 + int(cookie_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_FETCH_USER_KEY
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], f.Username)
	offset += int(username_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], f.Nonce)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:offset+8], cookie_len)
	offset += 8
	copy(buf[offset:offset+int(cookie_len)], f.LoginBrakeCookie)
	offset += int(cookie_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (f *FetchUserKeyRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (len1) + 8 (nonce) + 8 (len2) + 16 (checksum) = 41 bytes
	const min_size = 41
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

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_FETCH_USER_KEY {
		return errors.New("protocol: invalid App OpCode for FetchUserKeyRequest")
	}

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Username length")
	}
	username_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if username_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading Username data")
	}
	f.Username = make([]byte, int(username_len))
	copy(f.Username, data[offset:offset+int(username_len)])
	offset += int(username_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Nonce")
	}
	f.Nonce = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading LoginBrakeCookie length")
	}
	cookie_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if cookie_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading LoginBrakeCookie data")
	}
	f.LoginBrakeCookie = make([]byte, int(cookie_len))
	copy(f.LoginBrakeCookie, data[offset:offset+int(cookie_len)])
	offset += int(cookie_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in FetchUserKeyRequest")
	}

	return nil
}

// FetchUserKeyResponse returns the encrypted master key (or dummy) plus a rotated brake.
type FetchUserKeyResponse struct {
	StatusCode         uint8
	EncryptedMasterKey []byte
	LoginBrake         []byte
	LoginBrakeCookie   []byte
}

func (f *FetchUserKeyResponse) MarshalBinary() ([]byte, error) {
	if f.EncryptedMasterKey == nil || f.LoginBrake == nil || f.LoginBrakeCookie == nil {
		return nil, errors.New("protocol: FetchUserKeyResponse contains nil slices")
	}

	key_len := uint64(len(f.EncryptedMasterKey))
	brake_len := uint64(len(f.LoginBrake))
	cookie_len := uint64(len(f.LoginBrakeCookie))

	// 1 (op) + 1 (status) + 8 (len1) + key + 8 (len2) + brake + 8 (len3) + cookie + 16 (checksum)
	total_size := 1 + 1 + 8 + int(key_len) + 8 + int(brake_len) + 8 + int(cookie_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_FETCH_USER_KEY
	offset += 1

	buf[offset] = f.StatusCode
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], key_len)
	offset += 8
	copy(buf[offset:offset+int(key_len)], f.EncryptedMasterKey)
	offset += int(key_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], brake_len)
	offset += 8
	copy(buf[offset:offset+int(brake_len)], f.LoginBrake)
	offset += int(brake_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], cookie_len)
	offset += 8
	copy(buf[offset:offset+int(cookie_len)], f.LoginBrakeCookie)
	offset += int(cookie_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (f *FetchUserKeyResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 1 (status) + 8*3 (lengths) + 16 (checksum) = 42 bytes
	const min_size = 42
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

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_FETCH_USER_KEY {
		return errors.New("protocol: invalid App OpCode for FetchUserKeyResponse")
	}

	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	f.StatusCode = data[offset]
	offset += 1

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedMasterKey length")
	}
	key_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if key_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading EncryptedMasterKey data")
	}
	f.EncryptedMasterKey = make([]byte, int(key_len))
	copy(f.EncryptedMasterKey, data[offset:offset+int(key_len)])
	offset += int(key_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading LoginBrake length")
	}
	brake_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if brake_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading LoginBrake data")
	}
	f.LoginBrake = make([]byte, int(brake_len))
	copy(f.LoginBrake, data[offset:offset+int(brake_len)])
	offset += int(brake_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading LoginBrakeCookie length")
	}
	cookie_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if cookie_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading LoginBrakeCookie data")
	}
	f.LoginBrakeCookie = make([]byte, int(cookie_len))
	copy(f.LoginBrakeCookie, data[offset:offset+int(cookie_len)])
	offset += int(cookie_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in FetchUserKeyResponse")
	}

	return nil
}
