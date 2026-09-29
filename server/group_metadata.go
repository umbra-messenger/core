package server

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// GroupMetadata is the server-side storage representation of a group's public state.
// The server NEVER stores group master keys, membership lists, or owner identities.
type GroupMetadata struct {
	GroupPublicKey []byte
	AdminPublicKey []byte
	OwnerPublicKey []byte
	GroupVersion   uint64
}

func (g *GroupMetadata) MarshalBinary() ([]byte, error) {
	if g.GroupPublicKey == nil || g.AdminPublicKey == nil || g.OwnerPublicKey == nil {
		return nil, errors.New("server: GroupMetadata contains nil slices")
	}

	group_len := uint64(len(g.GroupPublicKey))
	admin_len := uint64(len(g.AdminPublicKey))
	owner_len := uint64(len(g.OwnerPublicKey))

	// 8 (len1) + d1 + 8 (len2) + d2 + 8 (len3) + d3 + 8 (version) + 16 (checksum)
	total_size := 8 + int(group_len) + 8 + int(admin_len) + 8 + int(owner_len) + 8 + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], group_len)
	offset += 8
	copy(buf[offset:offset+int(group_len)], g.GroupPublicKey)
	offset += int(group_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], admin_len)
	offset += 8
	copy(buf[offset:offset+int(admin_len)], g.AdminPublicKey)
	offset += int(admin_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], owner_len)
	offset += 8
	copy(buf[offset:offset+int(owner_len)], g.OwnerPublicKey)
	offset += int(owner_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], g.GroupVersion)
	offset += 8

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GroupMetadata) UnmarshalBinary(data []byte) error {
	// Min size: 8*3 + 8 + 16 = 56 bytes
	const min_size = 56
	if len(data) < min_size {
		return errors.New("server: data too short for GroupMetadata")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("server: checksum mismatch in GroupMetadata")
	}

	offset := 0

	group_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(group_len) > payload_length {
		return errors.New("server: underflow reading GroupPublicKey")
	}
	g.GroupPublicKey = make([]byte, group_len)
	copy(g.GroupPublicKey, data[offset:offset+int(group_len)])
	offset += int(group_len)

	admin_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(admin_len) > payload_length {
		return errors.New("server: underflow reading AdminPublicKey")
	}
	g.AdminPublicKey = make([]byte, admin_len)
	copy(g.AdminPublicKey, data[offset:offset+int(admin_len)])
	offset += int(admin_len)

	owner_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(owner_len) > payload_length {
		return errors.New("server: underflow reading OwnerPublicKey")
	}
	g.OwnerPublicKey = make([]byte, owner_len)
	copy(g.OwnerPublicKey, data[offset:offset+int(owner_len)])
	offset += int(owner_len)

	if offset+8 > payload_length {
		return errors.New("server: underflow reading GroupVersion")
	}
	g.GroupVersion = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset != payload_length {
		return errors.New("server: unexpected trailing data in GroupMetadata")
	}

	return nil
}
