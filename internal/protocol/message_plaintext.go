package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// MessagePlaintext represents the inner plaintext of a message before encryption.
// This is what gets encrypted with the group_master_key and stored on the server.
type MessagePlaintext struct {
	SenderUsername   []byte
	SenderSigningPub []byte
	UserSignature    []byte
	Timestamp        int64
	Content          []byte
}

func (m *MessagePlaintext) MarshalBinary() ([]byte, error) {
	if m.SenderUsername == nil || m.SenderSigningPub == nil || m.UserSignature == nil || m.Content == nil {
		return nil, errors.New("protocol: MessagePlaintext fields cannot be nil")
	}
	len_sender := uint64(len(m.SenderUsername))
	len_sign_pub := uint64(len(m.SenderSigningPub))
	len_user_sig := uint64(len(m.UserSignature))
	len_content := uint64(len(m.Content))

	total_size := 8 + int(len_sender) + 8 + int(len_sign_pub) + 8 + int(len_user_sig) + 8 + 8 + int(len_content) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sender)
	offset += 8
	copy(buf[offset:offset+int(len_sender)], m.SenderUsername)
	offset += int(len_sender)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sign_pub)
	offset += 8
	copy(buf[offset:offset+int(len_sign_pub)], m.SenderSigningPub)
	offset += int(len_sign_pub)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_user_sig)
	offset += 8
	copy(buf[offset:offset+int(len_user_sig)], m.UserSignature)
	offset += int(len_user_sig)

	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(m.Timestamp))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_content)
	offset += 8
	copy(buf[offset:offset+int(len_content)], m.Content)
	offset += int(len_content)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (m *MessagePlaintext) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 8 + 8 + 8 + 8 + 16 // 56 bytes (all empty slices)
	if len(data) < min_size {
		return errors.New("protocol: data too short for MessagePlaintext")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_sender := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sender) > payload_length {
		return errors.New("protocol: underflow reading SenderUsername")
	}
	m.SenderUsername = make([]byte, len_sender)
	copy(m.SenderUsername, data[offset:offset+int(len_sender)])
	offset += int(len_sender)

	len_sign_pub := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sign_pub) > payload_length {
		return errors.New("protocol: underflow reading SenderSigningPub")
	}
	m.SenderSigningPub = make([]byte, len_sign_pub)
	copy(m.SenderSigningPub, data[offset:offset+int(len_sign_pub)])
	offset += int(len_sign_pub)

	len_user_sig := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_user_sig) > payload_length {
		return errors.New("protocol: underflow reading UserSignature")
	}
	m.UserSignature = make([]byte, len_user_sig)
	copy(m.UserSignature, data[offset:offset+int(len_user_sig)])
	offset += int(len_user_sig)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Timestamp")
	}
	m.Timestamp = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	len_content := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_content) > payload_length {
		return errors.New("protocol: underflow reading Content")
	}
	m.Content = make([]byte, len_content)
	copy(m.Content, data[offset:offset+int(len_content)])
	offset += int(len_content)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
