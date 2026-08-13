package shared

const (
	CTX_EXCHANGE_KEY_DERIV       = "exchange_key_derivation"
	CTX_SIGNING_KEY_DERIV        = "signing_key_derivation"
	CTX_SHARED_SECRET_DERIV      = "shared_secret_derivation"
	CTX_SESSION_KEY_DERIV        = "session_symmetric_key"
	CTX_PUZZLE_KEY_DERIV         = "puzzle_key_derivation"
	CTX_PUZZLE_HASH              = "handshake_challenge_hash"
	CTX_SESSION_TOKEN_CRYPTO     = "session_token_encryption"
	CTX_CHALLENGE_PAYLOAD_CRYPTO = "challenge_payload_encryption"
	CTX_HANDSHAKE_INIT_SIG       = "handshake_init_signature"
	CTX_HANDSHAKE_CHALLENGE_SIG  = "handshake_challenge_signature"
	CTX_GENERAL_REQUEST_CRYPTO   = "general_request_payload"
	CTX_GENERAL_REQUEST_SIG      = "general_request_signature"
	CTX_GENERAL_RESPONSE_CRYPTO  = "general_response_payload"
	CTX_GENERAL_RESPONSE_SIG     = "general_response_signature"
)
