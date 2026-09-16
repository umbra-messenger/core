package shared

// Domain separation contexts (CTX_*) enforce strict cryptographic isolation.
// They MUST be centralized here and matched exactly between client and server.
const (
	CTX_SESSION_KEY_DERIV   = "umbra.session.key_derivation"
	CTX_SESSION_SIGNING     = "umbra.session.signing_key"
	CTX_PUZZLE_HASH         = "umbra.puzzle.fast_hash"
	CTX_PUZZLE_KEY_DERIV    = "umbra.puzzle.slow_key"
	CTX_SERVER_COOKIE       = "umbra.server.cookie_aead"
	CTX_KEYKEEPER_KEY_DERIV = "umbra.keykeeper.encryption_key"
	CTX_PERSONAL_NOTE_DERIV = "umbra.personal_note.encryption_key"
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
	SESSION_ID_LEN            = 16
	SESSION_TOKEN_LEN         = 32
	MASTER_KEY_LEN            = 32
	CHECKSUM_LEN              = 16
	PUZZLE_KEYSPACE_BITS      = 20
	KEYKEEPER_MAX_RECORD_SIZE = 4096
	PERSONAL_NOTE_MAX_SIZE    = 65536
)

// Message Types (uint8) for Server routing.
const (
	MSG_HANDSHAKE_INIT      uint8 = 1
	MSG_HANDSHAKE_CHALLENGE uint8 = 2
	MSG_VERIFICATION_REQ    uint8 = 3
	MSG_VERIFICATION_RES    uint8 = 4
	MSG_GENERAL_REQ         uint8 = 5
	MSG_GENERAL_RES         uint8 = 6
	MSG_KEYKEEPER_SUBMIT    uint8 = 7
	MSG_KEYKEEPER_FETCH     uint8 = 8
	MSG_KEYKEEPER_CLASSIFY  uint8 = 9
	MSG_KEYKEEPER_BATCH     uint8 = 10
	MSG_PERSONAL_NOTE_FETCH uint8 = 11
	MSG_PERSONAL_NOTE_UPD   uint8 = 12
	MSG_SYNC_REQ            uint8 = 13
	MSG_SYNC_RES            uint8 = 14
	MSG_CREATE_USER_REQ     uint8 = 15
	MSG_FETCH_USER_KEY_REQ  uint8 = 16
	MSG_DESTROY_SESSION_REQ uint8 = 17
	MSG_GROUP_CREATE_REQ    uint8 = 18
	MSG_GROUP_REKEY_REQ     uint8 = 19
	MSG_GROUP_ADMIN_ROT_REQ uint8 = 20
	MSG_GROUP_WIPE_REQ      uint8 = 21
)

// Application Payload OpCodes
const (
	APP_OP_CREATE_USER           = 0x01
	APP_OP_FETCH_USER_KEY        = 0x02
	APP_OP_LOOKUP_PUBLIC_KEY     = 0x03
	APP_OP_DESTROY_SESSION       = 0x04
	APP_OP_SYNC                  = 0x10
	APP_OP_KEYKEEPER_SUBMIT      = 0x20
	APP_OP_KEYKEEPER_FETCH       = 0x21
	APP_OP_KEYKEEPER_BATCH_FETCH = 0x22
	APP_OP_KEYKEEPER_CLASSIFY    = 0x23
	APP_OP_PERSONAL_NOTE_FETCH   = 0x30
	APP_OP_PERSONAL_NOTE_UPDATE  = 0x31
	APP_OP_GROUP_CREATE          = 0x40
	APP_OP_GROUP_POST_MESSAGE    = 0x41
	APP_OP_GROUP_REKEY           = 0x42
	APP_OP_ADMIN_KEY_ROTATION    = 0x43
	APP_OP_OWNER_WIPE            = 0x44
)
