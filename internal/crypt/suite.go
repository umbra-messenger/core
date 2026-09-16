package crypt

type CryptoSuite interface {
	// --- Metadata ---
	Name() string
	// --- Metadata ---
	Version() string

	// --- RNG ---
	Rand(data []byte) error

	// --- Symmetric AEAD ---
	EncryptFull(ctx string, plaintext []byte, key []byte, aad []byte) (nonce [12]byte, ciphertext []byte, tag [16]byte, err error)
	DecryptFull(ctx string, ciphertext []byte, key []byte, aad []byte, tag [16]byte, nonce [12]byte, break_on_invalid bool) (plaintext []byte, err error)

	NewStreamEncryptor(ctx string, key []byte, aad []byte) (nonce [12]byte, encryptor StreamEncryptor, err error)
	NewStreamDecryptor(ctx string, key []byte, aad []byte, nonce [12]byte) (decryptor StreamDecryptor, err error)

	// --- Hashing & KDF ---
	Hash(ctx string, data []byte, out_length int) (output []byte, err error)
	HashPassword(ctx string, password []byte, salt []byte, out_length int) (output []byte, err error)

	NewStreamHasher(ctx string) (hasher StreamHasher, err error)

	MAC(ctx string, key, data []byte, out_length int) (output []byte, err error)

	// --- Asymmetric Key Exchange (KEM Model) ---

	// DeriveExchangeKeyPair generates a KEM keypair from a 32-byte master seed.
	// The Host implementation is responsible for expanding this 32-byte seed
	// into the specific seed length required by the algorithm (e.g., 64 bytes for ML-KEM).
	DeriveExchangeKeyPair(ctx string, master [32]byte) (public_key []byte, private_key []byte, err error)

	// Encapsulate generates a shared secret and a ciphertext using the remote public key.
	// - PQC (ML-KEM): Performs standard KEM encapsulation.
	// - Classical (X25519/ECDH): Generates an ephemeral keypair, performs DH,
	//   and returns the ephemeral public key as the 'ciphertext'.
	Encapsulate(ctx string, remote_public_key []byte) (ciphertext []byte, shared_secret []byte, err error)

	// Decapsulate recovers the shared secret using the local private key and the ciphertext.
	// - PQC (ML-KEM): Performs standard KEM decapsulation.
	// - Classical (X25519/ECDH): Performs DH using the local private key and the
	//   'ciphertext' (which is the remote's ephemeral public key).
	Decapsulate(ctx string, local_private_key []byte, ciphertext []byte) (shared_secret []byte, err error)

	// --- Digital Signatures ---
	DeriveSigningKeyPair(ctx string, master [32]byte) (public_key []byte, private_key []byte, err error)
	Sign(ctx string, message []byte, private_key []byte) (signature []byte, err error)
	Verify(ctx string, message []byte, signature []byte, public_key []byte) (is_valid bool, err error)
}
