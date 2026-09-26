package server

import (
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

type Server struct {
	storage    shared.Storage
	crypt      crypt.CryptoSuite
	cookie_key [32]byte
	dummy_salt [32]byte
}

func NewServer(storage shared.Storage, crypt crypt.CryptoSuite, cookie_key [32]byte, dummy_salt [32]byte) *Server {
	return &Server{
		storage:    storage,
		crypt:      crypt,
		cookie_key: cookie_key,
		dummy_salt: dummy_salt,
	}
}

func (s *Server) Route(request_payload []byte) []byte {
	if len(request_payload) < 1+shared.CHECKSUM_LEN {
		return s.build_error_response(shared.ERR_CODE_INSUFFICIENT_DATA)
	}

	msg_type := request_payload[0]

	switch msg_type {
	case shared.MSG_HANDSHAKE_INIT:
		return s.handle_handshake_init(request_payload)
	case shared.MSG_VERIFICATION_REQ:
		return s.handle_verification_req(request_payload)
	case shared.MSG_GENERAL_REQ:
		return s.handle_general_req(request_payload)
	default:
		return s.build_error_response(shared.ERR_CODE_UNKNOWN_MSG_TYPE)
	}
}

func (s *Server) dispatch_app_request(session_id [16]byte, session_state *SessionState, app_opcode uint8, payload []byte) ([]byte, error) {
	switch app_opcode {
	case shared.APP_OP_CREATE_USER:
		return s.handle_app_create_user(session_id, session_state, payload)
	case shared.APP_OP_FETCH_USER_KEY:
		return s.handle_app_fetch_user_key(session_id, session_state, payload)
	case shared.APP_OP_LOOKUP_PUBLIC_KEY:
		return s.handle_app_lookup_public_key(session_id, session_state, payload)
	case shared.APP_OP_DESTROY_SESSION:
		return s.handle_app_destroy_session(session_id, session_state, payload)
	default:
		return nil, errors.New("unknown app opcode")
	}
}

func (s *Server) build_error_response(error_code uint16) []byte {
	env := &protocol.ErrorEnvelope{ErrorCode: error_code}
	data, err := env.MarshalBinary()
	if err != nil {
		return nil
	}
	return data
}
