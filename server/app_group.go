package server

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

func (s *Server) handle_app_group_create(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.GroupCreateRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Per-session rate limit. CAS-protected.
	current_time := s.time_func()
	gc_key := build_rate_limit_key("group_create", session_id[:])
	allowed, err := s.cas_advance_timestamp(
		shared.STORE_CTX_RATE_LIMIT,
		gc_key,
		current_time,
		uint64(shared.GROUP_CREATE_MIN_INTERVAL_SECONDS),
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errors.New("group create rate limit exceeded")
	}

	// 2. Generate server-side GroupID.
	var group_id [16]byte
	if err := s.crypt.Rand(group_id[:]); err != nil {
		return nil, err
	}

	// 3. Store GroupMetadata.
	metadata := &GroupMetadata{
		GroupPublicKey: req.GroupPublicKey,
		AdminPublicKey: req.AdminPublicKey,
		OwnerPublicKey: req.OwnerPublicKey,
		GroupVersion:   0,
	}
	metadata_bytes, err := metadata.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if err := s.storage.Store(shared.STORE_CTX_GROUP_KEY, group_id[:], metadata_bytes); err != nil {
		return nil, err
	}

	// 4. Return GroupID.
	res := &protocol.GroupCreateResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
		GroupID:    group_id,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_group_post_message(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.GroupPostMessageRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Retrieve GroupMetadata
	metadata_bytes, err := s.storage.Retrieve(shared.STORE_CTX_GROUP_KEY, req.GroupID[:])
	if err != nil {
		return nil, errors.New("group not found")
	}

	metadata := &GroupMetadata{}
	if err := metadata.UnmarshalBinary(metadata_bytes); err != nil {
		return nil, err
	}

	// 2. Verify GroupSignature against stored GroupPublicKey
	is_valid, err := s.crypt.Verify(shared.CTX_GROUP_WRITE, req.EncryptedMessage, req.GroupSignature, metadata.GroupPublicKey)
	if err != nil || !is_valid {
		return nil, errors.New("invalid group write signature")
	}

	// 3. Generate MessageID and Timestamp
	var message_id [16]byte
	if err := s.crypt.Rand(message_id[:]); err != nil {
		return nil, err
	}
	timestamp := s.time_func()

	// 4. Store message with current GroupVersion
	message := &GroupMessage{
		MessageID:        message_id,
		EncryptedMessage: req.EncryptedMessage,
		Timestamp:        timestamp,
		GroupVersion:     metadata.GroupVersion,
	}
	message_bytes, err := message.MarshalBinary()
	if err != nil {
		return nil, err
	}

	storage_key := build_group_message_key(req.GroupID, message_id)
	if err := s.storage.Store(shared.STORE_CTX_GROUP_MESSAGE, storage_key, message_bytes); err != nil {
		return nil, err
	}

	res := &protocol.GroupPostMessageResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_group_rekey(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.GroupRekeyRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Retrieve GroupMetadata
	metadata_bytes, err := s.storage.Retrieve(shared.STORE_CTX_GROUP_KEY, req.GroupID[:])
	if err != nil {
		return nil, errors.New("group not found")
	}

	metadata := &GroupMetadata{}
	if err := metadata.UnmarshalBinary(metadata_bytes); err != nil {
		return nil, err
	}

	// 2. Replay protection: provided version must be greater than current
	if req.GroupVersion <= metadata.GroupVersion {
		return nil, errors.New("stale group version")
	}

	// 3. Verify AdminSignature
	// Signature payload: GroupID || GroupVersion || NewGroupPublicKey
	sig_payload := make([]byte, 16+8+len(req.NewGroupPublicKey))
	copy(sig_payload[0:16], req.GroupID[:])
	binary.BigEndian.PutUint64(sig_payload[16:24], req.GroupVersion)
	copy(sig_payload[24:], req.NewGroupPublicKey)

	is_valid, err := s.crypt.Verify(shared.CTX_GROUP_REKEY, sig_payload, req.AdminSignature, metadata.AdminPublicKey)
	if err != nil || !is_valid {
		return nil, errors.New("invalid admin rekey signature")
	}

	// 4. Update GroupPublicKey and GroupVersion
	metadata.GroupPublicKey = req.NewGroupPublicKey
	metadata.GroupVersion = req.GroupVersion

	updated_bytes, err := metadata.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if err := s.storage.Store(shared.STORE_CTX_GROUP_KEY, req.GroupID[:], updated_bytes); err != nil {
		return nil, err
	}

	res := &protocol.GroupRekeyResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_admin_key_rotation(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.AdminKeyRotationRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Retrieve GroupMetadata
	metadata_bytes, err := s.storage.Retrieve(shared.STORE_CTX_GROUP_KEY, req.GroupID[:])
	if err != nil {
		return nil, errors.New("group not found")
	}

	metadata := &GroupMetadata{}
	if err := metadata.UnmarshalBinary(metadata_bytes); err != nil {
		return nil, err
	}

	// 2. Replay protection
	if req.GroupVersion <= metadata.GroupVersion {
		return nil, errors.New("stale group version")
	}

	// 3. Verify OwnerSignature
	// Signature payload: GroupID || GroupVersion || NewAdminPublicKey
	sig_payload := make([]byte, 16+8+len(req.NewAdminPublicKey))
	copy(sig_payload[0:16], req.GroupID[:])
	binary.BigEndian.PutUint64(sig_payload[16:24], req.GroupVersion)
	copy(sig_payload[24:], req.NewAdminPublicKey)

	is_valid, err := s.crypt.Verify(shared.CTX_GROUP_ADMIN_ROTATION, sig_payload, req.OwnerSignature, metadata.OwnerPublicKey)
	if err != nil || !is_valid {
		return nil, errors.New("invalid owner admin rotation signature")
	}

	// 4. Update AdminPublicKey and GroupVersion
	metadata.AdminPublicKey = req.NewAdminPublicKey
	metadata.GroupVersion = req.GroupVersion

	updated_bytes, err := metadata.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if err := s.storage.Store(shared.STORE_CTX_GROUP_KEY, req.GroupID[:], updated_bytes); err != nil {
		return nil, err
	}

	res := &protocol.AdminKeyRotationResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_owner_wipe(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.OwnerWipeRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Retrieve GroupMetadata
	metadata_bytes, err := s.storage.Retrieve(shared.STORE_CTX_GROUP_KEY, req.GroupID[:])
	if err != nil {
		return nil, errors.New("group not found")
	}

	metadata := &GroupMetadata{}
	if err := metadata.UnmarshalBinary(metadata_bytes); err != nil {
		return nil, err
	}

	// 2. Replay protection
	if req.GroupVersion <= metadata.GroupVersion {
		return nil, errors.New("stale group version")
	}

	// 3. Verify OwnerSignature
	// Signature payload: GroupID || GroupVersion
	sig_payload := make([]byte, 16+8)
	copy(sig_payload[0:16], req.GroupID[:])
	binary.BigEndian.PutUint64(sig_payload[16:24], req.GroupVersion)

	is_valid, err := s.crypt.Verify(shared.CTX_GROUP_WIPE, sig_payload, req.OwnerSignature, metadata.OwnerPublicKey)
	if err != nil || !is_valid {
		return nil, errors.New("invalid owner wipe signature")
	}

	// 4. Delete all messages for this group
	query_prefix := build_group_message_query_prefix(req.GroupID)
	message_values, err := s.storage.Query(shared.STORE_CTX_GROUP_MESSAGE, query_prefix, nil)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(message_values); i++ {
		msg := &GroupMessage{}
		if err := msg.UnmarshalBinary(message_values[i]); err != nil {
			continue
		}
		storage_key := build_group_message_key(req.GroupID, msg.MessageID)
		if err := s.storage.Delete(shared.STORE_CTX_GROUP_MESSAGE, storage_key); err != nil {
			return nil, err
		}
	}

	// 5. Delete group metadata
	if err := s.storage.Delete(shared.STORE_CTX_GROUP_KEY, req.GroupID[:]); err != nil {
		return nil, err
	}

	res := &protocol.OwnerWipeResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
	}
	return res.MarshalBinary()
}
