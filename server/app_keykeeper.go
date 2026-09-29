package server

import (
	"errors"

	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

// build_keykeeper_storage_key constructs the storage key: destination_username || 0x00 || record_id
func build_keykeeper_storage_key(destination_username []byte, record_id [16]byte) []byte {
	key := make([]byte, len(destination_username)+1+16)
	copy(key, destination_username)
	key[len(destination_username)] = 0x00
	copy(key[len(destination_username)+1:], record_id[:])
	return key
}

// build_keykeeper_query_prefix constructs the query prefix: destination_username || 0x00
func build_keykeeper_query_prefix(destination_username []byte) []byte {
	prefix := make([]byte, len(destination_username)+1)
	copy(prefix, destination_username)
	prefix[len(destination_username)] = 0x00
	return prefix
}

func build_rejected_keykeeper_submit_response() ([]byte, error) {
	res := &protocol.KeyKeeperSubmitResponse{
		StatusCode: shared.APP_STATUS_REJECTED,
		RecordIDs:  [][16]byte{},
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_keykeeper_submit(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.KeyKeeperSubmitRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Validate batch size (defense-in-depth: UnmarshalBinary already enforces it).
	if len(req.Records) > shared.KEYKEEPER_MAX_BATCH_SIZE {
		return build_rejected_keykeeper_submit_response()
	}

	// 2. Validate each record's encrypted payload size.
	for i := 0; i < len(req.Records); i++ {
		if len(req.Records[i].EncryptedPayload) > shared.KEYKEEPER_MAX_RECORD_SIZE {
			return build_rejected_keykeeper_submit_response()
		}
	}

	current_time := s.time_func()

	// 3. Per-session rate limit (1 batch per second). CAS-protected so
	//    concurrent requests from the same session cannot both pass.
	session_key := build_rate_limit_key("kk_session", session_id[:])
	allowed, err := s.cas_advance_timestamp(shared.STORE_CTX_RATE_LIMIT, session_key, current_time, 1)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return build_rejected_keykeeper_submit_response()
	}

	// 4. Per-destination rate limit. Each destination's quota is
	//    incremented atomically. If any destination rejects, the batch is
	//    rejected; earlier destinations that already advanced keep their
	//    increment, which is acceptable for a soft rate limit.
	dest_counts := make(map[string]uint64)
	for i := 0; i < len(req.Records); i++ {
		dest_counts[string(req.Records[i].DestinationUsername)]++
	}

	for dest, add_count := range dest_counts {
		dst_key := build_rate_limit_key("kk_dst", []byte(dest))
		allowed, err := s.cas_accumulate_quota(
			shared.STORE_CTX_RATE_LIMIT,
			dst_key,
			add_count,
			uint64(shared.KEYKEEPER_DST_RATE_LIMIT_MAX),
			uint64(shared.KEYKEEPER_DST_RATE_LIMIT_WINDOW_SECS),
			current_time,
		)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return build_rejected_keykeeper_submit_response()
		}
	}

	// 5. Store all records.
	record_ids := make([][16]byte, len(req.Records))
	for i := 0; i < len(req.Records); i++ {
		rec := &req.Records[i]

		var record_id [16]byte
		if err := s.crypt.Rand(record_id[:]); err != nil {
			return nil, err
		}

		storage_record := &KeyKeeperStorageRecord{
			RecordID:            record_id,
			DestinationUsername: rec.DestinationUsername,
			KemCiphertext:       rec.KemCiphertext,
			EncryptedPayload:    rec.EncryptedPayload,
			Timestamp:           current_time,
			IsPermanent:         false,
		}

		record_bytes, err := storage_record.MarshalBinary()
		if err != nil {
			return nil, err
		}

		storage_key := build_keykeeper_storage_key(rec.DestinationUsername, record_id)
		if err := s.storage.Store(shared.STORE_CTX_KEYKEEPER, storage_key, record_bytes); err != nil {
			return nil, err
		}

		record_ids[i] = record_id
	}

	res := &protocol.KeyKeeperSubmitResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
		RecordIDs:  record_ids,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_keykeeper_fetch(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.KeyKeeperFetchRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	query_prefix := build_keykeeper_query_prefix(req.Username)
	results, err := s.storage.Query(shared.STORE_CTX_KEYKEEPER, query_prefix, nil)
	if err != nil {
		return nil, err
	}

	records := make([]protocol.KeyKeeperRecord, 0, len(results))
	for i := 0; i < len(results); i++ {
		storage_record := &KeyKeeperStorageRecord{}
		if err := storage_record.UnmarshalBinary(results[i]); err != nil {
			continue
		}
		if storage_record.IsPermanent {
			continue
		}
		records = append(records, protocol.KeyKeeperRecord{
			RecordID:         storage_record.RecordID,
			KemCiphertext:    storage_record.KemCiphertext,
			EncryptedPayload: storage_record.EncryptedPayload,
			Timestamp:        storage_record.Timestamp,
		})
	}

	res := &protocol.KeyKeeperFetchResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
		Records:    records,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_keykeeper_batch_fetch(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.KeyKeeperBatchFetchRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	signing_pub, err := s.get_user_signing_pub(req.Username)
	if err != nil {
		return nil, err
	}

	sig_payload := make([]byte, len(req.Username)+len(req.RecordIDs)*16)
	copy(sig_payload, req.Username)
	sig_offset := len(req.Username)
	for i := 0; i < len(req.RecordIDs); i++ {
		copy(sig_payload[sig_offset:], req.RecordIDs[i][:])
		sig_offset += 16
	}

	is_valid, err := s.crypt.Verify(shared.CTX_KEYKEEPER_BATCH_FETCH, sig_payload, req.Signature, signing_pub)
	if err != nil || !is_valid {
		return nil, errors.New("invalid batch fetch signature")
	}

	records := make([]protocol.KeyKeeperRecord, 0, len(req.RecordIDs))
	for i := 0; i < len(req.RecordIDs); i++ {
		storage_key := build_keykeeper_storage_key(req.Username, req.RecordIDs[i])
		record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_KEYKEEPER, storage_key)
		if err != nil {
			return nil, errors.New("record not found for username")
		}

		storage_record := &KeyKeeperStorageRecord{}
		if err := storage_record.UnmarshalBinary(record_bytes); err != nil {
			return nil, err
		}

		records = append(records, protocol.KeyKeeperRecord{
			RecordID:         storage_record.RecordID,
			KemCiphertext:    storage_record.KemCiphertext,
			EncryptedPayload: storage_record.EncryptedPayload,
			Timestamp:        storage_record.Timestamp,
		})
	}

	res := &protocol.KeyKeeperBatchFetchResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
		Records:    records,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_keykeeper_classify(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.KeyKeeperClassifyRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	signing_pub, err := s.get_user_signing_pub(req.DestinationUsername)
	if err != nil {
		return nil, err
	}

	sig_payload := make([]byte, len(req.DestinationUsername)+len(req.ImportantIDs)*16+len(req.GarbageIDs)*16)
	copy(sig_payload, req.DestinationUsername)
	sig_offset := len(req.DestinationUsername)
	for i := 0; i < len(req.ImportantIDs); i++ {
		copy(sig_payload[sig_offset:], req.ImportantIDs[i][:])
		sig_offset += 16
	}
	for i := 0; i < len(req.GarbageIDs); i++ {
		copy(sig_payload[sig_offset:], req.GarbageIDs[i][:])
		sig_offset += 16
	}

	is_valid, err := s.crypt.Verify(shared.CTX_KEYKEEPER_CLASSIFY, sig_payload, req.Signature, signing_pub)
	if err != nil || !is_valid {
		return nil, errors.New("invalid classify signature")
	}

	// Validate ownership of ALL records in BOTH lists BEFORE any mutation.
	important_records := make([]*KeyKeeperStorageRecord, len(req.ImportantIDs))
	for i := 0; i < len(req.ImportantIDs); i++ {
		storage_key := build_keykeeper_storage_key(req.DestinationUsername, req.ImportantIDs[i])
		record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_KEYKEEPER, storage_key)
		if err != nil {
			return nil, errors.New("important record not found for username")
		}
		storage_record := &KeyKeeperStorageRecord{}
		if err := storage_record.UnmarshalBinary(record_bytes); err != nil {
			return nil, err
		}
		important_records[i] = storage_record
	}

	for i := 0; i < len(req.GarbageIDs); i++ {
		storage_key := build_keykeeper_storage_key(req.DestinationUsername, req.GarbageIDs[i])
		if _, err := s.storage.Retrieve(shared.STORE_CTX_KEYKEEPER, storage_key); err != nil {
			return nil, errors.New("garbage record not found for username")
		}
	}

	// All validations passed; mutate.
	for i := 0; i < len(req.GarbageIDs); i++ {
		storage_key := build_keykeeper_storage_key(req.DestinationUsername, req.GarbageIDs[i])
		if err := s.storage.Delete(shared.STORE_CTX_KEYKEEPER, storage_key); err != nil {
			return nil, err
		}
	}

	for i := 0; i < len(req.ImportantIDs); i++ {
		important_records[i].IsPermanent = true
		updated_bytes, err := important_records[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		storage_key := build_keykeeper_storage_key(req.DestinationUsername, req.ImportantIDs[i])
		if err := s.storage.Store(shared.STORE_CTX_KEYKEEPER, storage_key, updated_bytes); err != nil {
			return nil, err
		}
	}

	res := &protocol.KeyKeeperClassifyResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
	}
	return res.MarshalBinary()
}

// get_user_signing_pub retrieves the user's signing public key from storage.
func (s *Server) get_user_signing_pub(username []byte) ([]byte, error) {
	record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_USER_KEY, username)
	if err != nil {
		return nil, err
	}
	record := &UserRecord{}
	if err := record.UnmarshalBinary(record_bytes); err != nil {
		return nil, err
	}
	return record.SigningPub, nil
}
