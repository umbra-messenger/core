package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// GroupRekeyRequest is sent by an admin to rotate the group_master_key (kicking members).
type GroupRekeyRequest struct {
	GroupID           [16]byte
	GroupVersion      uint64
	NewGroupPublicKey []byte
	AdminSignature    []byte
}

func (g *GroupRekeyRequest) MarshalBinary() ([]byte, error) {
	if g.NewGroupPublicKey == nil || g.AdminSignature == nil {
		return nil, errors.New("protocol: GroupRekeyRequest contains nil slices")
	}

	new_group_pub_len := uint64(len(g.NewGroupPublicKey))
	admin_sig_len := uint64(len(g.AdminSignature))

	total_size := 1 + 16 + 8 + 8 + int(new_group_pub_len) + 8 + int(admin_sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_GROUP_REKEY
	offset += 1

	copy(buf[offset:offset+16], g.GroupID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], g.GroupVersion)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:offset+8], new_group_pub_len)
	offset += 8
	copy(buf[offset:offset+int(new_group_pub_len)], g.NewGroupPublicKey)
	offset += int(new_group_pub_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], admin_sig_len)
	offset += 8
	copy(buf[offset:offset+int(admin_sig_len)], g.AdminSignature)
	offset += int(admin_sig_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GroupRekeyRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 16 (group_id) + 8 (version) + 8*2 (lengths) + 16 (checksum) = 57 bytes
	const min_size = 57
	if len(data) < min_size {
		return errors.New("protocol: data too short for GroupRekeyRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in GroupRekeyRequest")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_GROUP_REKEY {
		return errors.New("protocol: invalid App OpCode for GroupRekeyRequest")
	}

	if offset+16 > payload_length {
		return errors.New("protocol: underflow reading GroupID")
	}
	copy(g.GroupID[:], data[offset:offset+16])
	offset += 16

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading GroupVersion")
	}
	g.GroupVersion = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading NewGroupPublicKey length")
	}
	new_group_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if new_group_pub_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading NewGroupPublicKey data")
	}
	g.NewGroupPublicKey = make([]byte, int(new_group_pub_len))
	copy(g.NewGroupPublicKey, data[offset:offset+int(new_group_pub_len)])
	offset += int(new_group_pub_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading AdminSignature length")
	}
	admin_sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if admin_sig_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading AdminSignature data")
	}
	g.AdminSignature = make([]byte, int(admin_sig_len))
	copy(g.AdminSignature, data[offset:offset+int(admin_sig_len)])
	offset += int(admin_sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in GroupRekeyRequest")
	}

	return nil
}

// GroupRekeyResponse acknowledges the group rekey.
type GroupRekeyResponse struct {
	StatusCode uint8
}

func (g *GroupRekeyResponse) MarshalBinary() ([]byte, error) {
	total_size := 18
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_GROUP_REKEY
	offset += 1

	buf[offset] = g.StatusCode
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GroupRekeyResponse) UnmarshalBinary(data []byte) error {
	const min_size = 18
	if len(data) < min_size {
		return errors.New("protocol: data too short for GroupRekeyResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in GroupRekeyResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_GROUP_REKEY {
		return errors.New("protocol: invalid App OpCode for GroupRekeyResponse")
	}

	g.StatusCode = data[offset]
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in GroupRekeyResponse")
	}

	return nil
}
