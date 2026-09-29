package server

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/shared"
)

// RATE_LIMIT_CAS_MAX_RETRIES bounds the retry loop for compare-and-swap
// rate limit updates. Eight retries is comfortably above the expected
// contention for the anonymous session model.
const RATE_LIMIT_CAS_MAX_RETRIES = 8

// build_rate_limit_key constructs a namespaced rate limit storage key:
// tag || 0x00 || identifier.
func build_rate_limit_key(tag string, identifier []byte) []byte {
	key := make([]byte, len(tag)+1+len(identifier))
	copy(key, tag)
	key[len(tag)] = 0x00
	copy(key[len(tag)+1:], identifier)
	return key
}

// cas_advance_timestamp atomically stores current_time at the given key if
// and only if current_time >= stored_time + min_gap_seconds (or the key is
// absent). Returns true if stored, false if the existing value is too recent.
//
// Stored value format: 8-byte Big-Endian uint64.
func (s *Server) cas_advance_timestamp(ctx string, key []byte, current_time uint64, min_gap_seconds uint64) (bool, error) {
	for attempt := 0; attempt < RATE_LIMIT_CAS_MAX_RETRIES; attempt++ {
		old_bytes, err := s.storage.Retrieve(ctx, key)
		var expected []byte
		var old_time uint64
		if err != nil {
			if !errors.Is(err, shared.ErrNotFound) {
				return false, err
			}
			// Key absent. expected == nil signals create-if-not-exists.
		} else {
			if len(old_bytes) != 8 {
				return false, errors.New("server: invalid rate limit record size")
			}
			old_time = binary.BigEndian.Uint64(old_bytes)
			expected = old_bytes
		}

		if old_time != 0 && current_time < old_time+min_gap_seconds {
			return false, nil
		}

		new_bytes := make([]byte, 8)
		binary.BigEndian.PutUint64(new_bytes, current_time)

		swapped, err := s.storage.CompareAndSwap(ctx, key, expected, new_bytes)
		if err != nil {
			return false, err
		}
		if swapped {
			return true, nil
		}
	}
	return false, errors.New("server: rate limit CAS retries exhausted")
}

// cas_accumulate_quota atomically increments a rolling-window counter. The
// quota record is: 8-byte window_start || 8-byte count, both Big-Endian.
// If current_time exceeds the window, the window is reset before the
// increment. If the accumulated count would exceed max_count, no write
// occurs and the function returns false.
func (s *Server) cas_accumulate_quota(ctx string, key []byte, delta uint64, max_count uint64, window_seconds uint64, current_time uint64) (bool, error) {
	for attempt := 0; attempt < RATE_LIMIT_CAS_MAX_RETRIES; attempt++ {
		old_bytes, err := s.storage.Retrieve(ctx, key)
		var expected []byte
		var window_start uint64
		var count uint64
		if err != nil {
			if !errors.Is(err, shared.ErrNotFound) {
				return false, err
			}
			window_start = current_time
			count = 0
		} else {
			if len(old_bytes) != 16 {
				return false, errors.New("server: invalid quota record size")
			}
			window_start = binary.BigEndian.Uint64(old_bytes[0:8])
			count = binary.BigEndian.Uint64(old_bytes[8:16])
			if current_time > window_start+window_seconds {
				window_start = current_time
				count = 0
			}
			expected = old_bytes
		}

		if count+delta > max_count {
			return false, nil
		}

		new_bytes := make([]byte, 16)
		binary.BigEndian.PutUint64(new_bytes[0:8], window_start)
		binary.BigEndian.PutUint64(new_bytes[8:16], count+delta)

		swapped, err := s.storage.CompareAndSwap(ctx, key, expected, new_bytes)
		if err != nil {
			return false, err
		}
		if swapped {
			return true, nil
		}
	}
	return false, errors.New("server: quota CAS retries exhausted")
}
