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

func (s *Server) handle_app_keykeeper_submit(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.KeyKeeperSubmitRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Validate batch size
	if len(req.Records) > shared.KEYKEEPER_MAX_BATCH_SIZE {
		res := &protocol.KeyKeeperSubmitResponse{
			StatusCode: shared.APP_STATUS_BRAKE_ROTATE, // Reuse as generic rejection
			RecordIDs:  [][16]byte{},
		}
		return res.MarshalBinary()
	}

	// 2. Validate each record's encrypted payload size
	for i := 0; i < len(req.Records); i++ {
		if len(req.Records[i].EncryptedPayload) > shared.KEYKEEPER_MAX_RECORD_SIZE {
			res := &protocol.KeyKeeperSubmitResponse{
				StatusCode: shared.APP_STATUS_BRAKE_ROTATE,
				RecordIDs:  [][16]byte{},
			}
			return res.MarshalBinary()
		}
	}

	// 3. Per-session rate limit (1 batch per second)
	current_time := s.time_func()
	if current_time <= session_state.LastKeyKeeperSubmitTime {
		res := &protocol.KeyKeeperSubmitResponse{
			StatusCode: shared.APP_STATUS_BRAKE_ROTATE,
			RecordIDs:  [][16]byte{},
		}
		return res.MarshalBinary()
	}

	// 4. Store all records
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

	// 5. Update session rate limit timestamp
	session_state.LastKeyKeeperSubmitTime = current_time
	if err := s.store_session_state(session_id, session_state); err != nil {
		return nil, err
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

	// Query all records for the destination username
	query_prefix := build_keykeeper_query_prefix(req.Username)
	results, err := s.storage.Query(shared.STORE_CTX_KEYKEEPER, query_prefix, nil)
	if err != nil {
		return nil, err
	}

	// Filter non-permanent records
	var records []protocol.KeyKeeperRecord
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

	// 1. Verify signature against user's SigningPub
	signing_pub, err := s.get_user_signing_pub(req.Username)
	if err != nil {
		return nil, err
	}

	// Build signature payload: username || record_ids
	sig_payload_len := len(req.Username) + len(req.RecordIDs)*16
	sig_payload := make([]byte, sig_payload_len)
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

	// 2. Fetch each record and verify ownership
	var records []protocol.KeyKeeperRecord
	for i := 0; i < len(req.RecordIDs); i++ {
		storage_key := build_keykeeper_storage_key(req.Username, req.RecordIDs[i])
		record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_KEYKEEPER, storage_key)
		if err != nil {
			// Record does not belong to this username — reject entire request
			return nil, errors.New("record does not belong to username")
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

	// 1. Verify signature against user's SigningPub
	signing_pub, err := s.get_user_signing_pub(req.DestinationUsername)
	if err != nil {
		return nil, err
	}

	// Build signature payload: destination_username || important_ids || garbage_ids
	sig_payload_len := len(req.DestinationUsername) + len(req.ImportantIDs)*16 + len(req.GarbageIDs)*16
	sig_payload := make([]byte, sig_payload_len)
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

	// 2. Verify ownership and delete garbage records
	for i := 0; i < len(req.GarbageIDs); i++ {
		storage_key := build_keykeeper_storage_key(req.DestinationUsername, req.GarbageIDs[i])
		if err := s.storage.Delete(shared.STORE_CTX_KEYKEEPER, storage_key); err != nil {
			return nil, errors.New("garbage record does not belong to username")
		}
	}

	// 3. Verify ownership and mark important records as permanent
	for i := 0; i < len(req.ImportantIDs); i++ {
		storage_key := build_keykeeper_storage_key(req.DestinationUsername, req.ImportantIDs[i])
		record_bytes, err := s.storage.Retrieve(shared.STORE_CTX_KEYKEEPER, storage_key)
		if err != nil {
			return nil, errors.New("important record does not belong to username")
		}

		storage_record := &KeyKeeperStorageRecord{}
		if err := storage_record.UnmarshalBinary(record_bytes); err != nil {
			return nil, err
		}

		storage_record.IsPermanent = true
		updated_bytes, err := storage_record.MarshalBinary()
		if err != nil {
			return nil, err
		}

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
