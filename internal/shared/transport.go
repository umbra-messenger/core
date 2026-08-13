package shared

type Transport interface {
	Send(payload []byte) error
	Receive() ([]byte, error)
	Close() error
}
