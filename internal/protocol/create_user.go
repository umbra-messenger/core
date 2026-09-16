package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// CreateUserRequest is sent within an established session to register a new user identity.
type CreateUserRequest struct {
	Username           []byte
	EncryptedMasterKey []byte
	SigningPub         []byte
	ExchangePub        []byte
	Nonce              uint64
	Signature          []byte
}

func (c *CreateUserRequest) MarshalBinary() ([]byte, error) {
	if c.Username == nil || c.EncryptedMasterKey == nil || c.SigningPub == nil || c.ExchangePub == nil || c.Signature == nil {
		return nil, errors.New("protocol: CreateUserRequest contains nil slices")
	}

	username_len := uint64(len(c.Username))
	enc_master_len := uint64(len(c.EncryptedMasterKey))
	signing_pub_len := uint64(len(c.SigningPub))
	exchange_pub_len := uint64(len(c.ExchangePub))
	signature_len := uint64(len(c.Signature))

	// 1 (op) + 8 (len1) + data1 + 8 (len2) + data2 + 8 (len3) + data3 + 8 (len4) + data4 + 8 (nonce) + 8 (len5) + data5 + 16 (checksum)
	total_size := 1 + 8 + int(username_len) + 8 + int(enc_master_len) + 8 + int(signing_pub_len) + 8 + int(exchange_pub_len) + 8 + 8 + int(signature_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_CREATE_USER
	offset += 1

	// 2. Username
	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], c.Username)
	offset += int(username_len)

	// 3. EncryptedMasterKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_master_len)
	offset += 8
	copy(buf[offset:offset+int(enc_master_len)], c.EncryptedMasterKey)
	offset += int(enc_master_len)

	// 4. SigningPub
	binary.BigEndian.PutUint64(buf[offset:offset+8], signing_pub_len)
	offset += 8
	copy(buf[offset:offset+int(signing_pub_len)], c.SigningPub)
	offset += int(signing_pub_len)

	// 5. ExchangePub
	binary.BigEndian.PutUint64(buf[offset:offset+8], exchange_pub_len)
	offset += 8
	copy(buf[offset:offset+int(exchange_pub_len)], c.ExchangePub)
	offset += int(exchange_pub_len)

	// 6. Nonce
	binary.BigEndian.PutUint64(buf[offset:offset+8], c.Nonce)
	offset += 8

	// 7. Signature
	binary.BigEndian.PutUint64(buf[offset:offset+8], signature_len)
	offset += 8
	copy(buf[offset:offset+int(signature_len)], c.Signature)
	offset += int(signature_len)

	// 8. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *CreateUserRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8*5 (lengths) + 8 (nonce) + 16 (checksum) = 57 bytes
	const min_size = 1 + 40 + 8 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for CreateUserRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in CreateUserRequest")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_CREATE_USER {
		return errors.New("protocol: invalid App OpCode for CreateUserRequest")
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
	c.Username = make([]byte, username_len)
	copy(c.Username, data[offset:offset+int(username_len)])
	offset += int(username_len)

	// 3. EncryptedMasterKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedMasterKey length")
	}
	enc_master_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(enc_master_len) > payload_length {
		return errors.New("protocol: underflow reading EncryptedMasterKey data")
	}
	c.EncryptedMasterKey = make([]byte, enc_master_len)
	copy(c.EncryptedMasterKey, data[offset:offset+int(enc_master_len)])
	offset += int(enc_master_len)

	// 4. SigningPub
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SigningPub length")
	}
	signing_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(signing_pub_len) > payload_length {
		return errors.New("protocol: underflow reading SigningPub data")
	}
	c.SigningPub = make([]byte, signing_pub_len)
	copy(c.SigningPub, data[offset:offset+int(signing_pub_len)])
	offset += int(signing_pub_len)

	// 5. ExchangePub
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading ExchangePub length")
	}
	exchange_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(exchange_pub_len) > payload_length {
		return errors.New("protocol: underflow reading ExchangePub data")
	}
	c.ExchangePub = make([]byte, exchange_pub_len)
	copy(c.ExchangePub, data[offset:offset+int(exchange_pub_len)])
	offset += int(exchange_pub_len)

	// 6. Nonce
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Nonce")
	}
	c.Nonce = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	// 7. Signature
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	signature_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(signature_len) > payload_length {
		return errors.New("protocol: underflow reading Signature data")
	}
	c.Signature = make([]byte, signature_len)
	copy(c.Signature, data[offset:offset+int(signature_len)])
	offset += int(signature_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in CreateUserRequest")
	}

	return nil
}

// CreateUserResponse is the server's response to a CreateUserRequest.
type CreateUserResponse struct {
	StatusCode       uint8
	AssignedUsername []byte
}

func (c *CreateUserResponse) MarshalBinary() ([]byte, error) {
	if c.AssignedUsername == nil {
		return nil, errors.New("protocol: CreateUserResponse contains nil AssignedUsername")
	}

	assigned_len := uint64(len(c.AssignedUsername))

	// 1 (op) + 1 (status) + 8 (len) + data + 16 (checksum)
	total_size := 1 + 1 + 8 + int(assigned_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_CREATE_USER
	offset += 1

	// 2. StatusCode
	buf[offset] = c.StatusCode
	offset += 1

	// 3. AssignedUsername
	binary.BigEndian.PutUint64(buf[offset:offset+8], assigned_len)
	offset += 8
	copy(buf[offset:offset+int(assigned_len)], c.AssignedUsername)
	offset += int(assigned_len)

	// 4. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *CreateUserResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 1 (status) + 8 (len) + 16 (checksum) = 26 bytes
	const min_size = 1 + 1 + 8 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for CreateUserResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in CreateUserResponse")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_CREATE_USER {
		return errors.New("protocol: invalid App OpCode for CreateUserResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	c.StatusCode = data[offset]
	offset += 1

	// 3. AssignedUsername
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading AssignedUsername length")
	}
	assigned_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(assigned_len) > payload_length {
		return errors.New("protocol: underflow reading AssignedUsername data")
	}
	c.AssignedUsername = make([]byte, assigned_len)
	copy(c.AssignedUsername, data[offset:offset+int(assigned_len)])
	offset += int(assigned_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in CreateUserResponse")
	}

	return nil
}
