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

	// Remove the session and all rate-limit records keyed by this session.
	// Delete failures are ignored so that a partially-cleaned session is not
	// left behind; the caller sees success once the session record is gone.
	_ = s.storage.Delete(shared.STORE_CTX_SESSION_KEY, session_id[:])
	_ = s.storage.Delete(shared.STORE_CTX_RATE_LIMIT, build_rate_limit_key("kk_session", session_id[:]))
	_ = s.storage.Delete(shared.STORE_CTX_RATE_LIMIT, build_rate_limit_key("group_create", session_id[:]))
	_ = s.storage.Delete(shared.STORE_CTX_RATE_LIMIT, build_rate_limit_key("reg", session_id[:]))

	res := &protocol.DestroySessionResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
	}
	return res.MarshalBinary()
}
