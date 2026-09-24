package shared

type Storage interface {
	Store(ctx string, key []byte, value []byte) error
	Retrieve(ctx string, key []byte) ([]byte, error)
	Delete(ctx string, key []byte) error
	IsSafe() bool
	GetTempKey() []byte
}
