package shared

import "errors"

var (
	// Protocol parsing & integrity errors
	ErrInvalidChecksum  = errors.New("protocol: invalid checksum")
	ErrInsufficientData = errors.New("protocol: insufficient data")
	ErrTrailingData     = errors.New("protocol: unexpected trailing data")

	// Cryptographic & Session errors
	ErrInvalidSignature = errors.New("protocol: invalid signature")
	ErrInvalidSession   = errors.New("protocol: invalid or expired session")
	ErrReplayAttack     = errors.New("protocol: nonce replay detected")
	ErrPuzzleUnsolved   = errors.New("protocol: handshake puzzle unsolved")
	ErrInvalidKey       = errors.New("protocol: invalid cryptographic key")
)
