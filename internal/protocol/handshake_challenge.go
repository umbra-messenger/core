package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

type HandshakeChallenge struct {
	KemCiphertext          []byte
	SessionSigningPubKey   []byte
	EncryptedSessionPuzzle []byte
	SessionCookie          []byte
	Signature              []byte
}

func (h *HandshakeChallenge) MarshalBinary() ([]byte, error) {
	if h.KemCiphertext == nil || h.SessionSigningPubKey == nil || h.EncryptedSessionPuzzle == nil || h.SessionCookie == nil || h.Signature == nil {
		return nil, errors.New("protocol: HandshakeChallenge contains nil slices")
	}

	kem_ct_len := uint64(len(h.KemCiphertext))
	sig_pub_len := uint64(len(h.SessionSigningPubKey))
	puzzle_len := uint64(len(h.EncryptedSessionPuzzle))
	cookie_len := uint64(len(h.SessionCookie))
	sig_len := uint64(len(h.Signature))

	// 1 (type) + 5*(8 + data) + 16 (checksum)
	total_size := 1 + 8 + int(kem_ct_len) + 8 + int(sig_pub_len) + 8 + int(puzzle_len) + 8 + int(cookie_len) + 8 + int(sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.MSG_HANDSHAKE_CHALLENGE
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], kem_ct_len)
	offset += 8
	copy(buf[offset:offset+int(kem_ct_len)], h.KemCiphertext)
	offset += int(kem_ct_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_pub_len)
	offset += 8
	copy(buf[offset:offset+int(sig_pub_len)], h.SessionSigningPubKey)
	offset += int(sig_pub_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], puzzle_len)
	offset += 8
	copy(buf[offset:offset+int(puzzle_len)], h.EncryptedSessionPuzzle)
	offset += int(puzzle_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], cookie_len)
	offset += 8
	copy(buf[offset:offset+int(cookie_len)], h.SessionCookie)
	offset += int(cookie_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_len)
	offset += 8
	copy(buf[offset:offset+int(sig_len)], h.Signature)
	offset += int(sig_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (h *HandshakeChallenge) UnmarshalBinary(data []byte) error {
	// Min size: 1 (type) + 5*8 (lengths) + 16 (checksum) = 57 bytes
	const min_size = 57
	if len(data) < min_size {
		return errors.New("protocol: data too short for HandshakeChallenge")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in HandshakeChallenge")
	}

	offset := 0

	msg_type := data[offset]
	offset += 1
	if msg_type != shared.MSG_HANDSHAKE_CHALLENGE {
		return errors.New("protocol: invalid MessageType for HandshakeChallenge")
	}

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading KemCiphertext length")
	}
	kem_ct_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if kem_ct_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading KemCiphertext data")
	}
	h.KemCiphertext = make([]byte, int(kem_ct_len))
	copy(h.KemCiphertext, data[offset:offset+int(kem_ct_len)])
	offset += int(kem_ct_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SessionSigningPubKey length")
	}
	sig_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if sig_pub_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading SessionSigningPubKey data")
	}
	h.SessionSigningPubKey = make([]byte, int(sig_pub_len))
	copy(h.SessionSigningPubKey, data[offset:offset+int(sig_pub_len)])
	offset += int(sig_pub_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedSessionPuzzle length")
	}
	puzzle_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if puzzle_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading EncryptedSessionPuzzle data")
	}
	h.EncryptedSessionPuzzle = make([]byte, int(puzzle_len))
	copy(h.EncryptedSessionPuzzle, data[offset:offset+int(puzzle_len)])
	offset += int(puzzle_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SessionCookie length")
	}
	cookie_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if cookie_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading SessionCookie data")
	}
	h.SessionCookie = make([]byte, int(cookie_len))
	copy(h.SessionCookie, data[offset:offset+int(cookie_len)])
	offset += int(cookie_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if sig_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading Signature data")
	}
	h.Signature = make([]byte, int(sig_len))
	copy(h.Signature, data[offset:offset+int(sig_len)])
	offset += int(sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in HandshakeChallenge")
	}

	return nil
}
