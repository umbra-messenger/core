package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// SyncGroup represents a group to sync in a SyncRequest.
type SyncGroup struct {
	GroupID        [16]byte
	SinceTimestamp int64
}

// SyncRequest represents a request to poll for new messages.
type SyncRequest struct {
	Groups []SyncGroup
}

func (s *SyncRequest) MarshalBinary() ([]byte, error) {
	if s.Groups == nil {
		return nil, errors.New("protocol: SyncRequest Groups cannot be nil")
	}
	len_groups := uint64(len(s.Groups))

	// 8 (groups count) + N * (16 + 8) + 16
	total_size := 8 + int(len_groups)*24 + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_groups)
	offset += 8

	for i := 0; i < int(len_groups); i++ {
		copy(buf[offset:offset+16], s.Groups[i].GroupID[:])
		offset += 16

		binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(s.Groups[i].SinceTimestamp))
		offset += 8
	}

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (s *SyncRequest) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 16 // 24 bytes (just the count, no groups)
	if len(data) < min_size {
		return errors.New("protocol: data too short for SyncRequest")
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

	if offset+int(len_groups)*24 > payload_length {
		return errors.New("protocol: underflow reading Groups")
	}

	s.Groups = make([]SyncGroup, len_groups)
	for i := 0; i < int(len_groups); i++ {
		copy(s.Groups[i].GroupID[:], data[offset:offset+16])
		offset += 16

		s.Groups[i].SinceTimestamp = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
		offset += 8
	}

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
