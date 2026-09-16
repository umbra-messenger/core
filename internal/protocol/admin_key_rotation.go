package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// AdminKeyRotationRequest is sent by the owner to rotate the admin_master_key.
type AdminKeyRotationRequest struct {
	GroupID           [16]byte
	GroupVersion      uint64
	NewAdminPublicKey []byte
	OwnerSignature    []byte
}

func (a *AdminKeyRotationRequest) MarshalBinary() ([]byte, error) {
	if a.NewAdminPublicKey == nil || a.OwnerSignature == nil {
		return nil, errors.New("protocol: AdminKeyRotationRequest contains nil slices")
	}

	new_admin_pub_len := uint64(len(a.NewAdminPublicKey))
	owner_sig_len := uint64(len(a.OwnerSignature))

	// 1 (op) + 16 (group_id) + 8 (version) + 8 (len1) + data1 + 8 (len2) + data2 + 16 (checksum)
	total_size := 1 + 16 + 8 + 8 + int(new_admin_pub_len) + 8 + int(owner_sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_ADMIN_KEY_ROTATION
	offset += 1

	// 2. GroupID
	copy(buf[offset:offset+16], a.GroupID[:])
	offset += 16

	// 3. GroupVersion
	binary.BigEndian.PutUint64(buf[offset:offset+8], a.GroupVersion)
	offset += 8

	// 4. NewAdminPublicKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], new_admin_pub_len)
	offset += 8
	copy(buf[offset:offset+int(new_admin_pub_len)], a.NewAdminPublicKey)
	offset += int(new_admin_pub_len)

	// 5. OwnerSignature
	binary.BigEndian.PutUint64(buf[offset:offset+8], owner_sig_len)
	offset += 8
	copy(buf[offset:offset+int(owner_sig_len)], a.OwnerSignature)
	offset += int(owner_sig_len)

	// 6. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (a *AdminKeyRotationRequest) UnmarshalBinary(data []byte) error {
	const min_size = 57
	if len(data) < min_size {
		return errors.New("protocol: data too short for AdminKeyRotationRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in AdminKeyRotationRequest")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_ADMIN_KEY_ROTATION {
		return errors.New("protocol: invalid App OpCode for AdminKeyRotationRequest")
	}

	if offset+16 > payload_length {
		return errors.New("protocol: underflow reading GroupID")
	}
	copy(a.GroupID[:], data[offset:offset+16])
	offset += 16

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading GroupVersion")
	}
	a.GroupVersion = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading NewAdminPublicKey length")
	}
	new_admin_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(new_admin_pub_len) > payload_length {
		return errors.New("protocol: underflow reading NewAdminPublicKey data")
	}
	a.NewAdminPublicKey = make([]byte, new_admin_pub_len)
	copy(a.NewAdminPublicKey, data[offset:offset+int(new_admin_pub_len)])
	offset += int(new_admin_pub_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading OwnerSignature length")
	}
	owner_sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(owner_sig_len) > payload_length {
		return errors.New("protocol: underflow reading OwnerSignature data")
	}
	a.OwnerSignature = make([]byte, owner_sig_len)
	copy(a.OwnerSignature, data[offset:offset+int(owner_sig_len)])
	offset += int(owner_sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in AdminKeyRotationRequest")
	}

	return nil
}

// AdminKeyRotationResponse acknowledges the admin key rotation.
type AdminKeyRotationResponse struct {
	StatusCode uint8
}

func (a *AdminKeyRotationResponse) MarshalBinary() ([]byte, error) {
	total_size := 18
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_ADMIN_KEY_ROTATION
	offset += 1

	buf[offset] = a.StatusCode
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (a *AdminKeyRotationResponse) UnmarshalBinary(data []byte) error {
	const min_size = 18
	if len(data) < min_size {
		return errors.New("protocol: data too short for AdminKeyRotationResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in AdminKeyRotationResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_ADMIN_KEY_ROTATION {
		return errors.New("protocol: invalid App OpCode for AdminKeyRotationResponse")
	}

	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	a.StatusCode = data[offset]
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in AdminKeyRotationResponse")
	}

	return nil
}
