package shared

type Storage interface {
	Store(ctx string, key []byte, value []byte) error
	Retrieve(ctx string, key []byte) ([]byte, error) // MUST return ErrNotFound if absent
	Delete(ctx string, key []byte) error
	Query(ctx string, prefix []byte, sort_key_filter []byte) ([][]byte, error)
	CompareAndSwap(ctx string, key []byte, expected []byte, new_value []byte) (swapped bool, err error)
	IsSafe() bool
	GetTempKey() []byte
}
