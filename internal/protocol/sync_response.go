package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// GroupMessage represents an individual message returned by the server.
type GroupMessage struct {
	Timestamp        int64
	EncryptedMessage []byte
	Signature        []byte
}

// SyncGroupResponse represents messages for a single group.
type SyncGroupResponse struct {
	GroupID  [16]byte
	Messages []GroupMessage
}

// SyncResponse represents the server's response to a sync request.
type SyncResponse struct {
	Groups []SyncGroupResponse
}

func (s *SyncResponse) MarshalBinary() ([]byte, error) {
	if s.Groups == nil {
		return nil, errors.New("protocol: SyncResponse Groups cannot be nil")
	}
	len_groups := uint64(len(s.Groups))

	// Calculate total size
	total_size := 8 // groups count
	for i := 0; i < int(len_groups); i++ {
		total_size += 16 // GroupID
		total_size += 8  // messages count
		for j := 0; j < len(s.Groups[i].Messages); j++ {
			total_size += 8                                                 // Timestamp
			total_size += 8 + len(s.Groups[i].Messages[j].EncryptedMessage) // EncryptedMessage
			total_size += 8 + len(s.Groups[i].Messages[j].Signature)        // Signature
		}
	}
	total_size += 16 // checksum

	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_groups)
	offset += 8

	for i := 0; i < int(len_groups); i++ {
		copy(buf[offset:offset+16], s.Groups[i].GroupID[:])
		offset += 16

		len_messages := uint64(len(s.Groups[i].Messages))
		binary.BigEndian.PutUint64(buf[offset:offset+8], len_messages)
		offset += 8

		for j := 0; j < int(len_messages); j++ {
			binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(s.Groups[i].Messages[j].Timestamp))
			offset += 8

			len_enc_msg := uint64(len(s.Groups[i].Messages[j].EncryptedMessage))
			binary.BigEndian.PutUint64(buf[offset:offset+8], len_enc_msg)
			offset += 8
			copy(buf[offset:offset+int(len_enc_msg)], s.Groups[i].Messages[j].EncryptedMessage)
			offset += int(len_enc_msg)

			len_sig := uint64(len(s.Groups[i].Messages[j].Signature))
			binary.BigEndian.PutUint64(buf[offset:offset+8], len_sig)
			offset += 8
			copy(buf[offset:offset+int(len_sig)], s.Groups[i].Messages[j].Signature)
			offset += int(len_sig)
		}
	}

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SyncResponse) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 16 // 24 bytes (just the count, no groups)
	if len(data) < min_size {
		return errors.New("protocol: data too short for SyncResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_groups := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	s.Groups = make([]SyncGroupResponse, len_groups)
	for i := 0; i < int(len_groups); i++ {
		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading GroupID")
		}
		copy(s.Groups[i].GroupID[:], data[offset:offset+16])
		offset += 16

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading messages count")
		}
		len_messages := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8

		s.Groups[i].Messages = make([]GroupMessage, len_messages)
		for j := 0; j < int(len_messages); j++ {
			if offset+8 > payload_length {
				return errors.New("protocol: underflow reading Timestamp")
			}
			s.Groups[i].Messages[j].Timestamp = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
			offset += 8

			if offset+8 > payload_length {
				return errors.New("protocol: underflow reading EncryptedMessage length")
			}
			len_enc_msg := binary.BigEndian.Uint64(data[offset : offset+8])
			offset += 8
			if offset+int(len_enc_msg) > payload_length {
				return errors.New("protocol: underflow reading EncryptedMessage")
			}
			s.Groups[i].Messages[j].EncryptedMessage = make([]byte, len_enc_msg)
			copy(s.Groups[i].Messages[j].EncryptedMessage, data[offset:offset+int(len_enc_msg)])
			offset += int(len_enc_msg)

			if offset+8 > payload_length {
				return errors.New("protocol: underflow reading Signature length")
			}
			len_sig := binary.BigEndian.Uint64(data[offset : offset+8])
			offset += 8
			if offset+int(len_sig) > payload_length {
				return errors.New("protocol: underflow reading Signature")
			}
			s.Groups[i].Messages[j].Signature = make([]byte, len_sig)
			copy(s.Groups[i].Messages[j].Signature, data[offset:offset+int(len_sig)])
			offset += int(len_sig)
		}
	}

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
