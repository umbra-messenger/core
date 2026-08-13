package crypt

type StreamEncryptor interface {
	EncryptChunk(plaintext_chunk []byte) (ciphertext_chunk []byte, err error)
	Finalize() (tag [16]byte, err error)
	Reset(ctx string) error
	Close() error
}

type StreamDecryptor interface {
	DecryptChunk(ciphertext_chunk []byte) (plaintext_chunk []byte, err error)
	Finalize(tag [16]byte) error
	Reset(ctx string, nonce [12]byte) error
	Close() error
}
