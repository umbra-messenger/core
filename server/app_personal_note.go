package server

import (
	"errors"

	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

func (s *Server) handle_app_personal_note_fetch(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.PersonalNoteFetchRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Verify signature
	signing_pub, err := s.get_user_signing_pub(req.Username)
	if err != nil {
		return nil, err
	}

	is_valid, err := s.crypt.Verify(shared.CTX_PERSONAL_NOTE_FETCH, req.Username, req.Signature, signing_pub)
	if err != nil || !is_valid {
		return nil, errors.New("invalid personal note fetch signature")
	}

	// 2. Retrieve encrypted note
	note_bytes, err := s.storage.Retrieve(shared.STORE_CTX_PERSONAL_NOTE, req.Username)
	if err != nil {
		// Note does not exist — return empty note
		note_bytes = []byte{}
	}

	res := &protocol.PersonalNoteFetchResponse{
		StatusCode:    shared.APP_STATUS_SUCCESS,
		EncryptedNote: note_bytes,
	}
	return res.MarshalBinary()
}

func (s *Server) handle_app_personal_note_update(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.PersonalNoteUpdateRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	// 1. Verify signature over username || encrypted_note
	signing_pub, err := s.get_user_signing_pub(req.Username)
	if err != nil {
		return nil, err
	}

	sig_payload := make([]byte, len(req.Username)+len(req.EncryptedNote))
	copy(sig_payload, req.Username)
	copy(sig_payload[len(req.Username):], req.EncryptedNote)

	is_valid, err := s.crypt.Verify(shared.CTX_PERSONAL_NOTE_UPDATE, sig_payload, req.Signature, signing_pub)
	if err != nil || !is_valid {
		return nil, errors.New("invalid personal note update signature")
	}

	// 2. Validate note size
	if len(req.EncryptedNote) > shared.PERSONAL_NOTE_MAX_SIZE {
		return nil, errors.New("personal note exceeds maximum size")
	}

	// 3. Store encrypted note
	if err := s.storage.Store(shared.STORE_CTX_PERSONAL_NOTE, req.Username, req.EncryptedNote); err != nil {
		return nil, err
	}

	res := &protocol.PersonalNoteUpdateResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
	}
	return res.MarshalBinary()
}
