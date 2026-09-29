package server

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// GroupMessage is the server-side storage representation of an encrypted group message.
// MessageID is included in the value so it can be reconstructed during OwnerWipe deletion.
type GroupMessage struct {
	MessageID        [16]byte
	EncryptedMessage []byte
	Timestamp        uint64
	GroupVersion     uint64
}

func (g *GroupMessage) MarshalBinary() ([]byte, error) {
	if g.EncryptedMessage == nil {
		return nil, errors.New("server: GroupMessage contains nil EncryptedMessage")
	}

	enc_len := uint64(len(g.EncryptedMessage))

	// 16 (id) + 8 (len) + data + 8 (ts) + 8 (version) + 16 (checksum)
	total_size := 16 + 8 + int(enc_len) + 8 + 8 + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], g.MessageID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_len)
	offset += 8
	copy(buf[offset:offset+int(enc_len)], g.EncryptedMessage)
	offset += int(enc_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], g.Timestamp)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:offset+8], g.GroupVersion)
	offset += 8

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GroupMessage) UnmarshalBinary(data []byte) error {
	// Min size: 16 (id) + 8 (len) + 8 (ts) + 8 (version) + 16 (checksum) = 56 bytes
	const min_size = 56
	if len(data) < min_size {
		return errors.New("server: data too short for GroupMessage")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("server: checksum mismatch in GroupMessage")
	}

	offset := 0

	copy(g.MessageID[:], data[offset:offset+16])
	offset += 16

	if offset+8 > payload_length {
		return errors.New("server: underflow reading EncryptedMessage length")
	}
	enc_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if enc_len > uint64(payload_length-offset) {
		return errors.New("server: underflow reading EncryptedMessage data")
	}
	g.EncryptedMessage = make([]byte, int(enc_len))
	copy(g.EncryptedMessage, data[offset:offset+int(enc_len)])
	offset += int(enc_len)

	if offset+8 > payload_length {
		return errors.New("server: underflow reading Timestamp")
	}
	g.Timestamp = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+8 > payload_length {
		return errors.New("server: underflow reading GroupVersion")
	}
	g.GroupVersion = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset != payload_length {
		return errors.New("server: unexpected trailing data in GroupMessage")
	}

	return nil
}

// build_group_message_key constructs the storage key: group_id || 0x00 || message_id
func build_group_message_key(group_id [16]byte, message_id [16]byte) []byte {
	key := make([]byte, 16+1+16)
	copy(key[0:16], group_id[:])
	key[16] = 0x00
	copy(key[17:33], message_id[:])
	return key
}

// build_group_message_query_prefix constructs the query prefix: group_id || 0x00
func build_group_message_query_prefix(group_id [16]byte) []byte {
	prefix := make([]byte, 17)
	copy(prefix[0:16], group_id[:])
	prefix[16] = 0x00
	return prefix
}
