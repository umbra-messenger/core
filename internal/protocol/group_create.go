package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// GroupCreateRequest is sent to create a new group. The server generates the GroupID.
type GroupCreateRequest struct {
	GroupPublicKey []byte
	AdminPublicKey []byte
	OwnerPublicKey []byte
	Signature      []byte
}

func (g *GroupCreateRequest) MarshalBinary() ([]byte, error) {
	if g.GroupPublicKey == nil || g.AdminPublicKey == nil || g.OwnerPublicKey == nil || g.Signature == nil {
		return nil, errors.New("protocol: GroupCreateRequest contains nil slices")
	}

	group_pub_len := uint64(len(g.GroupPublicKey))
	admin_pub_len := uint64(len(g.AdminPublicKey))
	owner_pub_len := uint64(len(g.OwnerPublicKey))
	sig_len := uint64(len(g.Signature))

	// 1 (op) + 8 (len1) + data1 + 8 (len2) + data2 + 8 (len3) + data3 + 8 (len4) + data4 + 16 (checksum)
	total_size := 1 + 8 + int(group_pub_len) + 8 + int(admin_pub_len) + 8 + int(owner_pub_len) + 8 + int(sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_GROUP_CREATE
	offset += 1

	// 2. GroupPublicKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], group_pub_len)
	offset += 8
	copy(buf[offset:offset+int(group_pub_len)], g.GroupPublicKey)
	offset += int(group_pub_len)

	// 3. AdminPublicKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], admin_pub_len)
	offset += 8
	copy(buf[offset:offset+int(admin_pub_len)], g.AdminPublicKey)
	offset += int(admin_pub_len)

	// 4. OwnerPublicKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], owner_pub_len)
	offset += 8
	copy(buf[offset:offset+int(owner_pub_len)], g.OwnerPublicKey)
	offset += int(owner_pub_len)

	// 5. Signature
	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_len)
	offset += 8
	copy(buf[offset:offset+int(sig_len)], g.Signature)
	offset += int(sig_len)

	// 6. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GroupCreateRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8*4 (lengths) + 16 (checksum) = 49 bytes
	const min_size = 49
	if len(data) < min_size {
		return errors.New("protocol: data too short for GroupCreateRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in GroupCreateRequest")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_GROUP_CREATE {
		return errors.New("protocol: invalid App OpCode for GroupCreateRequest")
	}

	// 2. GroupPublicKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading GroupPublicKey length")
	}
	group_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(group_pub_len) > payload_length {
		return errors.New("protocol: underflow reading GroupPublicKey data")
	}
	g.GroupPublicKey = make([]byte, group_pub_len)
	copy(g.GroupPublicKey, data[offset:offset+int(group_pub_len)])
	offset += int(group_pub_len)

	// 3. AdminPublicKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading AdminPublicKey length")
	}
	admin_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(admin_pub_len) > payload_length {
		return errors.New("protocol: underflow reading AdminPublicKey data")
	}
	g.AdminPublicKey = make([]byte, admin_pub_len)
	copy(g.AdminPublicKey, data[offset:offset+int(admin_pub_len)])
	offset += int(admin_pub_len)

	// 4. OwnerPublicKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading OwnerPublicKey length")
	}
	owner_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(owner_pub_len) > payload_length {
		return errors.New("protocol: underflow reading OwnerPublicKey data")
	}
	g.OwnerPublicKey = make([]byte, owner_pub_len)
	copy(g.OwnerPublicKey, data[offset:offset+int(owner_pub_len)])
	offset += int(owner_pub_len)

	// 5. Signature
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(sig_len) > payload_length {
		return errors.New("protocol: underflow reading Signature data")
	}
	g.Signature = make([]byte, sig_len)
	copy(g.Signature, data[offset:offset+int(sig_len)])
	offset += int(sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in GroupCreateRequest")
	}

	return nil
}

// GroupCreateResponse returns the server-generated GroupID.
type GroupCreateResponse struct {
	StatusCode uint8
	GroupID    [16]byte
}

func (g *GroupCreateResponse) MarshalBinary() ([]byte, error) {
	// 1 (op) + 1 (status) + 16 (group_id) + 16 (checksum) = 34 bytes
	total_size := 34
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_GROUP_CREATE
	offset += 1

	// 2. StatusCode
	buf[offset] = g.StatusCode
	offset += 1

	// 3. GroupID
	copy(buf[offset:offset+16], g.GroupID[:])
	offset += 16

	// 4. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GroupCreateResponse) UnmarshalBinary(data []byte) error {
	const min_size = 34
	if len(data) < min_size {
		return errors.New("protocol: data too short for GroupCreateResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in GroupCreateResponse")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_GROUP_CREATE {
		return errors.New("protocol: invalid App OpCode for GroupCreateResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	g.StatusCode = data[offset]
	offset += 1

	// 3. GroupID
	if offset+16 > payload_length {
		return errors.New("protocol: underflow reading GroupID")
	}
	copy(g.GroupID[:], data[offset:offset+16])
	offset += 16

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in GroupCreateResponse")
	}

	return nil
}
