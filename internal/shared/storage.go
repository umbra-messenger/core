package shared

const (
	STORE_CTX_SESSION_KEY = "session_key"
	STORE_CTX_NONCE       = "nonce"
)

type Storage interface {
	Store(ctx string, key string, value []byte) error
	Retrieve(ctx string, key string) ([]byte, error)
	Delete(ctx string, key string) error
	IsSafe() bool
	GetTempKey() []byte
}
