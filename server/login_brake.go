package server

import (
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

// generate_login_brake creates a new random brake and its encrypted cookie.
// Returns: plaintext brake, encrypted cookie bytes, timestamp.
func (s *Server) generate_login_brake(version uint64) ([]byte, []byte, uint64, error) {
	brake := make([]byte, shared.LOGIN_BRAKE_LEN)
	if err := s.crypt.Rand(brake); err != nil {
		return nil, nil, 0, err
	}

	timestamp := s.time_func()

	// Timestamp is intentionally excluded from the cookie to save bytes.
	// The server tracks it securely in its own SessionState.
	cookie := &protocol.LoginBrakeCookie{
		LoginBrake: brake,
		Version:    version,
	}
	cookie_bytes, err := cookie.MarshalBinary()
	if err != nil {
		return nil, nil, 0, err
	}

	nonce, ct, tag, err := s.crypt.EncryptFull(shared.CTX_LOGIN_BRAKE_COOKIE, cookie_bytes, s.cookie_key[:], nil)
	if err != nil {
		return nil, nil, 0, err
	}

	pkg := &protocol.EncryptedPackage{Nonce: nonce, Ciphertext: ct, Tag: tag}
	pkg_bytes, err := pkg.MarshalBinary()
	if err != nil {
		return nil, nil, 0, err
	}

	return brake, pkg_bytes, timestamp, nil
}

// decrypt_login_brake_cookie decrypts and parses an encrypted brake cookie.
func (s *Server) decrypt_login_brake_cookie(cookie_bytes []byte) (*protocol.LoginBrakeCookie, error) {
	pkg := &protocol.EncryptedPackage{}
	if err := pkg.UnmarshalBinary(cookie_bytes); err != nil {
		return nil, err
	}

	plaintext, err := s.crypt.DecryptFull(shared.CTX_LOGIN_BRAKE_COOKIE, pkg.Ciphertext, s.cookie_key[:], nil, pkg.Tag, pkg.Nonce, true)
	if err != nil {
		return nil, err
	}

	cookie := &protocol.LoginBrakeCookie{}
	if err := cookie.UnmarshalBinary(plaintext); err != nil {
		return nil, err
	}

	return cookie, nil
}

// store_session_state marshals and persists the session state.
func (s *Server) store_session_state(session_id [16]byte, session_state *SessionState) error {
	state_bytes, err := session_state.MarshalBinary()
	if err != nil {
		return err
	}
	return s.storage.Store(shared.STORE_CTX_SESSION_KEY, session_id[:], state_bytes)
}
