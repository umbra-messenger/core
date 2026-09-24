package server

import (
	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

type Server struct {
	storage    shared.Storage
	crypt      crypt.CryptoSuite
	cookie_key [32]byte
}

func NewServer(storage shared.Storage, crypt crypt.CryptoSuite, cookie_key [32]byte) *Server {
	return &Server{
		storage:    storage,
		crypt:      crypt,
		cookie_key: cookie_key,
	}
}

func (s *Server) Route(request_payload []byte) []byte {
	// Minimum size to read MessageType (1 byte) + Checksum (16 bytes)
	if len(request_payload) < 1+shared.CHECKSUM_LEN {
		return s.build_error_response(shared.ERR_CODE_INSUFFICIENT_DATA)
	}

	// Read MessageType (Byte 0) to route.
	// The actual checksum verification is handled fail-fast inside the specific struct's UnmarshalBinary.
	msg_type := request_payload[0]

	switch msg_type {
	case shared.MSG_HANDSHAKE_INIT:
		return s.handle_handshake_init(request_payload)

	case shared.MSG_VERIFICATION_REQ:
		return s.handle_verification_req(request_payload)

	case shared.MSG_GENERAL_REQ:
		return s.handle_general_req(request_payload)

	default:
		// Unknown or unsupported message type
		return s.build_error_response(shared.ERR_CODE_UNKNOWN_MSG_TYPE)
	}
}

func (s *Server) build_error_response(error_code uint16) []byte {
	env := &protocol.ErrorEnvelope{ErrorCode: error_code}
	data, err := env.MarshalBinary()
	if err != nil {
		// Fallback: If even error marshalling fails, return nil.
		// In practice, ErrorEnvelope Marshal should never fail unless OOM.
		return nil
	}
	return data
}
