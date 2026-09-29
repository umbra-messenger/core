package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// SyncGroupRequest represents a request to sync messages for a specific group.
// SinceTimestamp is the timestamp of the last message the client has fully
// processed. The server returns messages with Timestamp strictly greater than
// this value.
type SyncGroupRequest struct {
	GroupID        [16]byte
	SinceTimestamp uint64
}

// SyncRequest is sent to poll for new messages across multiple groups.
type SyncRequest struct {
	Groups []SyncGroupRequest
}

func (s *SyncRequest) MarshalBinary() ([]byte, error) {
	if s.Groups == nil {
		s.Groups = []SyncGroupRequest{}
	}

	groups_count := uint64(len(s.Groups))

	// 1 (op) + 8 (count) + count*(16 + 8) + 16 (checksum)
	total_size := 1 + 8 + int(groups_count)*24 + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_SYNC
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], groups_count)
	offset += 8

	for i := 0; i < len(s.Groups); i++ {
		group := &s.Groups[i]

		copy(buf[offset:offset+16], group.GroupID[:])
		offset += 16

		binary.BigEndian.PutUint64(buf[offset:offset+8], group.SinceTimestamp)
		offset += 8
	}

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SyncRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (count) + 16 (checksum) = 25 bytes
	const min_size = 25
	if len(data) < min_size {
		return errors.New("protocol: data too short for SyncRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in SyncRequest")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_SYNC {
		return errors.New("protocol: invalid App OpCode for SyncRequest")
	}

	groups_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	// Each SyncGroupRequest is exactly 24 bytes (16 + 8).
	if groups_count > uint64(payload_length-offset)/24 {
		return errors.New("protocol: SyncRequest group count exceeds payload size")
	}

	s.Groups = make([]SyncGroupRequest, int(groups_count))
	for i := uint64(0); i < groups_count; i++ {
		group := &s.Groups[i]

		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading GroupID")
		}
		copy(group.GroupID[:], data[offset:offset+16])
		offset += 16

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading SinceTimestamp")
		}
		group.SinceTimestamp = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in SyncRequest")
	}

	return nil
}

// SyncedMessage represents a single message returned by the server.
type SyncedMessage struct {
	EncryptedMessage []byte
	Timestamp        uint64
	GroupVersion     uint64
}

// SyncGroupResponse represents the synced messages for a specific group.
type SyncGroupResponse struct {
	GroupID  [16]byte
	Messages []SyncedMessage
}

// SyncResponse returns the polled messages for the requested groups.
type SyncResponse struct {
	StatusCode uint8
	Groups     []SyncGroupResponse
}

func (s *SyncResponse) MarshalBinary() ([]byte, error) {
	if s.Groups == nil {
		s.Groups = []SyncGroupResponse{}
	}

	groups_count := uint64(len(s.Groups))
	groups_data_size := 0
	for i := 0; i < len(s.Groups); i++ {
		group := &s.Groups[i]
		if group.Messages == nil {
			group.Messages = []SyncedMessage{}
		}
		groups_data_size += 16 + 8

		for j := 0; j < len(group.Messages); j++ {
			msg := &group.Messages[j]
			if msg.EncryptedMessage == nil {
				return nil, errors.New("protocol: SyncedMessage contains nil EncryptedMessage")
			}
			groups_data_size += 8 + len(msg.EncryptedMessage) + 8 + 8
		}
	}

	total_size := 1 + 1 + 8 + groups_data_size + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_SYNC
	offset += 1

	buf[offset] = s.StatusCode
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], groups_count)
	offset += 8

	for i := 0; i < len(s.Groups); i++ {
		group := &s.Groups[i]

		copy(buf[offset:offset+16], group.GroupID[:])
		offset += 16

		messages_count := uint64(len(group.Messages))
		binary.BigEndian.PutUint64(buf[offset:offset+8], messages_count)
		offset += 8

		for j := 0; j < len(group.Messages); j++ {
			msg := &group.Messages[j]

			enc_msg_len := uint64(len(msg.EncryptedMessage))
			binary.BigEndian.PutUint64(buf[offset:offset+8], enc_msg_len)
			offset += 8
			copy(buf[offset:offset+int(enc_msg_len)], msg.EncryptedMessage)
			offset += int(enc_msg_len)

			binary.BigEndian.PutUint64(buf[offset:offset+8], msg.Timestamp)
			offset += 8

			binary.BigEndian.PutUint64(buf[offset:offset+8], msg.GroupVersion)
			offset += 8
		}
	}

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SyncResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 1 (status) + 8 (count) + 16 (checksum) = 26 bytes
	const min_size = 26
	if len(data) < min_size {
		return errors.New("protocol: data too short for SyncResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in SyncResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_SYNC {
		return errors.New("protocol: invalid App OpCode for SyncResponse")
	}

	s.StatusCode = data[offset]
	offset += 1

	groups_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	// Each SyncGroupResponse is at least 16 (group_id) + 8 (message count) = 24 bytes.
	if groups_count > uint64(payload_length-offset)/24 {
		return errors.New("protocol: SyncResponse group count exceeds payload size")
	}

	s.Groups = make([]SyncGroupResponse, int(groups_count))
	for i := uint64(0); i < groups_count; i++ {
		group := &s.Groups[i]

		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading GroupID")
		}
		copy(group.GroupID[:], data[offset:offset+16])
		offset += 16

		if offset+8 > payload_length {
			return errors.New("protocol: underflow reading Messages count")
		}
		messages_count := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		// Each SyncedMessage is at least 8 (enc len) + 8 (ts) + 8 (version) = 24 bytes.
		if messages_count > uint64(payload_length-offset)/24 {
			return errors.New("protocol: SyncResponse message count exceeds payload size")
		}

		group.Messages = make([]SyncedMessage, int(messages_count))
		for j := uint64(0); j < messages_count; j++ {
			msg := &group.Messages[j]

			if offset+8 > payload_length {
				return errors.New("protocol: underflow reading EncryptedMessage length")
			}
			enc_msg_len := binary.BigEndian.Uint64(data[offset : offset+8])
			offset += 8
			if enc_msg_len > uint64(payload_length-offset) {
				return errors.New("protocol: underflow reading EncryptedMessage data")
			}
			msg.EncryptedMessage = make([]byte, int(enc_msg_len))
			copy(msg.EncryptedMessage, data[offset:offset+int(enc_msg_len)])
			offset += int(enc_msg_len)

			if offset+8 > payload_length {
				return errors.New("protocol: underflow reading Timestamp")
			}
			msg.Timestamp = binary.BigEndian.Uint64(data[offset : offset+8])
			offset += 8

			if offset+8 > payload_length {
				return errors.New("protocol: underflow reading GroupVersion")
			}
			msg.GroupVersion = binary.BigEndian.Uint64(data[offset : offset+8])
			offset += 8
		}
	}

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in SyncResponse")
	}

	return nil
}
