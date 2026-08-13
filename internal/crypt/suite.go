package crypt

type CryptoSuite interface {
	Name() string
	Version() string

	// --- Symmetric AEAD ---
	EncryptFull(ctx string, plaintext []byte, key []byte) (nonce [12]byte, ciphertext []byte, tag [16]byte, err error)
	DecryptFull(ctx string, ciphertext []byte, tag [16]byte, nonce [12]byte, key []byte, break_on_invalid bool) (plaintext []byte, err error)

	NewStreamEncryptor(ctx string, key []byte) (nonce [12]byte, encryptor StreamEncryptor, err error)
	NewStreamDecryptor(ctx string, nonce [12]byte, key []byte) (decryptor StreamDecryptor, err error)

	// // --- Hashing & KDF ---
	Hash(ctx string, data []byte, out_length int) (output []byte, err error)
	HashPassword(ctx string, password []byte, salt []byte, out_length int) (output []byte, err error)

	NewStreamHasher(ctx string) (hasher StreamHasher, err error)

	MAC(ctx string, key, data []byte, out_length int) (output []byte, err error)

	// --- Asymmetric Key Exchange ---
	DeriveExchangeKeyPair(ctx string, master [32]byte) (public_key []byte, private_key []byte, err error)
	DeriveSharedSecret(ctx string, local_private_key []byte, remote_public_key []byte) (shared_secret []byte, err error)

	// --- Digital Signatures ---
	DeriveSigningKeyPair(ctx string, master [32]byte) (public_key []byte, private_key []byte, err error)
	Sign(ctx string, message []byte, private_key []byte) (signature []byte, err error)
	Verify(ctx string, message []byte, signature []byte, public_key []byte) (is_valid bool, err error)

	// --- RNG ---
	Rand(data []byte) error
}
