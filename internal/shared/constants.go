package shared

// Domain separation contexts (CTX_*) enforce strict cryptographic isolation.
// They MUST be centralized here and matched exactly between client and server.
const (
	CTX_SESSION_KEY_DERIV      = "umbra.session.key_derivation"
	CTX_CLIENT_SESSION_SIGNING = "umbra.session.signing_key.client"
	CTX_SERVER_SESSION_SIGNING = "umbra.session.signing_key.server"
	CTX_PUZZLE_HASH            = "umbra.puzzle.fast_hash"
	CTX_PUZZLE_KEY_DERIV       = "umbra.puzzle.slow_key"
	CTX_SERVER_COOKIE          = "umbra.server.cookie_aead"
	CTX_KEYKEEPER_KEY_DERIV    = "umbra.keykeeper.encryption_key"
	CTX_PERSONAL_NOTE_DERIV    = "umbra.personal_note.encryption_key"
	CTX_KEM_ENCAPSULATE        = "umbra.kem.encapsulate"
	CTX_AEAD_PUZZLE_TOKEN      = "umbra.aead.puzzle_token"
	CTX_AEAD_SESSION_PUZZLE    = "umbra.aead.session_puzzle"
	CTX_AEAD_VERIFICATION_RESP = "umbra.aead.verification_resp"
	CTX_AEAD_GENERAL_PAYLOAD   = "umbra.aead.general_payload"
	CTX_HANDSHAKE_INIT_SIG     = "umbra.handshake.init_signature"
	CTX_DUMMY_USER_KEY         = "umbra.dummy.user_key"
	CTX_DUMMY_PUB_KEY          = "umbra.dummy.pub_key"
	CTX_USER_REGISTRATION_POW  = "umbra.user.registration_pow"
	CTX_USER_REGISTRATION      = "umbra.user.registration_auth"
)

// Storage contexts (STORE_CTX_*) tell the Host the logical category of stored data.
const (
	STORE_CTX_SESSION_KEY     = "session_key"
	STORE_CTX_NONCE           = "nonce"
	STORE_CTX_CLIENT_STATE    = "client_state"
	STORE_CTX_USER_KEY        = "user_key"
	STORE_CTX_GROUP_KEY       = "group_key"
	STORE_CTX_CLIENT_REGISTRY = "client_registry"
	STORE_CTX_KEYKEEPER       = "keykeeper"
	STORE_CTX_PERSONAL_NOTE   = "personal_note"
)

// Protocol sizes, limits, and magic bytes.
const (
	SESSION_ID_LEN                        = 16
	SESSION_TOKEN_LEN                     = 32
	MASTER_KEY_LEN                        = 32
	CHECKSUM_LEN                          = 16
	PUZZLE_KEYSPACE_BITS                  = 20
	KEYKEEPER_MAX_RECORD_SIZE             = 4096
	PERSONAL_NOTE_MAX_SIZE                = 65536
	USERNAME_DISCRIMINATOR_MAX_TRIES      = 7
	USER_REGISTRATION_POW_DIFFICULTY_BITS = 6
)

// Message Types (uint8) for Server routing.
const (
	MSG_HANDSHAKE_INIT      uint8 = 0x01
	MSG_HANDSHAKE_CHALLENGE uint8 = 0x02
	MSG_VERIFICATION_REQ    uint8 = 0x03
	MSG_VERIFICATION_RES    uint8 = 0x04
	MSG_GENERAL_REQ         uint8 = 0x05
	MSG_GENERAL_RES         uint8 = 0x06
	MSG_ERROR               uint8 = 0xFF
)

// Application Payload OpCodes
const (
	APP_OP_CREATE_USER           uint8 = 0x01
	APP_OP_FETCH_USER_KEY        uint8 = 0x02
	APP_OP_LOOKUP_PUBLIC_KEY     uint8 = 0x03
	APP_OP_DESTROY_SESSION       uint8 = 0x04
	APP_OP_SYNC                  uint8 = 0x10
	APP_OP_KEYKEEPER_SUBMIT      uint8 = 0x20
	APP_OP_KEYKEEPER_FETCH       uint8 = 0x21
	APP_OP_KEYKEEPER_BATCH_FETCH uint8 = 0x22
	APP_OP_KEYKEEPER_CLASSIFY    uint8 = 0x23
	APP_OP_PERSONAL_NOTE_FETCH   uint8 = 0x30
	APP_OP_PERSONAL_NOTE_UPDATE  uint8 = 0x31
	APP_OP_GROUP_CREATE          uint8 = 0x40
	APP_OP_GROUP_POST_MESSAGE    uint8 = 0x41
	APP_OP_GROUP_REKEY           uint8 = 0x42
	APP_OP_ADMIN_KEY_ROTATION    uint8 = 0x43
	APP_OP_OWNER_WIPE            uint8 = 0x44
)

// Error Codes (Wire-Format)
const (
	ERR_CODE_INVALID_PROTOCOL  uint16 = 01001
	ERR_CODE_INSUFFICIENT_DATA uint16 = 01002
	ERR_CODE_TRAILING_DATA     uint16 = 01003
	ERR_CODE_UNKNOWN_MSG_TYPE  uint16 = 01004
	ERR_CODE_INVALID_SIGNATURE uint16 = 02001
	ERR_CODE_INVALID_SESSION   uint16 = 02002
	ERR_CODE_REPLAY_ATTACK     uint16 = 02003
	ERR_CODE_PUZZLE_UNSOLVED   uint16 = 02004
	ERR_CODE_INVALID_KEY       uint16 = 02005
	ERR_CODE_INTERNAL_SERVER   uint16 = 05000
)
