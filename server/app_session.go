package server

import (
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

func (s *Server) handle_app_destroy_session(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.DestroySessionRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	if err := s.storage.Delete(shared.STORE_CTX_SESSION_KEY, session_id[:]); err != nil {
		return nil, err
	}

	res := &protocol.DestroySessionResponse{
		StatusCode: 0,
	}
	return res.MarshalBinary()
}
