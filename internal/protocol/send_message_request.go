package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// SendMessageRequest represents a request to send a message to a group.
type SendMessageRequest struct {
	GroupID          [16]byte
	EncryptedMessage []byte
	Signature        []byte
}

func (s *SendMessageRequest) MarshalBinary() ([]byte, error) {
	if s.EncryptedMessage == nil || s.Signature == nil {
		return nil, errors.New("protocol: SendMessageRequest fields cannot be nil")
	}
	len_enc_msg := uint64(len(s.EncryptedMessage))
	len_sig := uint64(len(s.Signature))

	total_size := 16 + 8 + int(len_enc_msg) + 8 + int(len_sig) + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+16], s.GroupID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_enc_msg)
	offset += 8
	copy(buf[offset:offset+int(len_enc_msg)], s.EncryptedMessage)
	offset += int(len_enc_msg)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sig)
	offset += 8
	copy(buf[offset:offset+int(len_sig)], s.Signature)
	offset += int(len_sig)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SendMessageRequest) UnmarshalBinary(data []byte) error {
	const min_size = 16 + 8 + 8 + 16 // 48 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for SendMessageRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	copy(s.GroupID[:], data[offset:offset+16])
	offset += 16

	len_enc_msg := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_enc_msg) > payload_length {
		return errors.New("protocol: underflow reading EncryptedMessage")
	}
	s.EncryptedMessage = make([]byte, len_enc_msg)
	copy(s.EncryptedMessage, data[offset:offset+int(len_enc_msg)])
	offset += int(len_enc_msg)

	len_sig := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sig) > payload_length {
		return errors.New("protocol: underflow reading Signature")
	}
	s.Signature = make([]byte, len_sig)
	copy(s.Signature, data[offset:offset+int(len_sig)])
	offset += int(len_sig)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
