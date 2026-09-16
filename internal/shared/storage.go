package shared

type Storage interface {
	Store(ctx string, key string, value []byte) error
	Retrieve(ctx string, key string) ([]byte, error)
	Delete(ctx string, key string) error
	IsSafe() bool
	GetTempKey() []byte
}
