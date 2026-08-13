package crypt

type StreamHasher interface {
	AbsorbChunk(chunk []byte) error
	Squeeze(output []byte) error
	Close() error
}
