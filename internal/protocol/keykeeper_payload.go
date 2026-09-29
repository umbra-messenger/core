package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// KeyKeeperPayload is the client-side encrypted inner payload stored in a KeyKeeper record.
// It is NOT routed (no MessageType, no App OpCode).
// The sender constructs, signs, and encrypts this. The recipient decrypts and verifies it.
type KeyKeeperPayload struct {
	RecordType   uint8
	GroupID      [16]byte
	GroupVersion uint64
	Payload      []byte
	SenderHint   []byte
	CreatedAt    uint64
	SignerPubKey []byte
	Signature    []byte
}

func (k *KeyKeeperPayload) MarshalBinary() ([]byte, error) {
	if k.Payload == nil || k.SenderHint == nil || k.SignerPubKey == nil || k.Signature == nil {
		return nil, errors.New("protocol: KeyKeeperPayload contains nil slices")
	}

	payload_len := uint64(len(k.Payload))
	hint_len := uint64(len(k.SenderHint))
	pubkey_len := uint64(len(k.SignerPubKey))
	sig_len := uint64(len(k.Signature))

	// 1 (type) + 16 (group_id) + 8 (version) + 8 (len1) + d1 + 8 (len2) + d2 + 8 (created_at) + 8 (len3) + d3 + 8 (len4) + d4 + 16 (checksum)
	total_size := 1 + 16 + 8 + 8 + int(payload_len) + 8 + int(hint_len) + 8 + 8 + int(pubkey_len) + 8 + int(sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = k.RecordType
	offset += 1

	copy(buf[offset:offset+16], k.GroupID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], k.GroupVersion)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:offset+8], payload_len)
	offset += 8
	copy(buf[offset:offset+int(payload_len)], k.Payload)
	offset += int(payload_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], hint_len)
	offset += 8
	copy(buf[offset:offset+int(hint_len)], k.SenderHint)
	offset += int(hint_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], k.CreatedAt)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:offset+8], pubkey_len)
	offset += 8
	copy(buf[offset:offset+int(pubkey_len)], k.SignerPubKey)
	offset += int(pubkey_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_len)
	offset += 8
	copy(buf[offset:offset+int(sig_len)], k.Signature)
	offset += int(sig_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperPayload) UnmarshalBinary(data []byte) error {
	// Min size: 1 (type) + 16 (group_id) + 8 (version) + 8*4 (four length prefixes) + 8 (created_at) + 16 (checksum) = 81 bytes
	const min_size = 81
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperPayload")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperPayload")
	}

	offset := 0

	k.RecordType = data[offset]
	offset += 1

	copy(k.GroupID[:], data[offset:offset+16])
	offset += 16

	k.GroupVersion = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Payload length")
	}
	payload_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if payload_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading Payload data")
	}
	k.Payload = make([]byte, int(payload_len))
	copy(k.Payload, data[offset:offset+int(payload_len)])
	offset += int(payload_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SenderHint length")
	}
	hint_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if hint_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading SenderHint data")
	}
	k.SenderHint = make([]byte, int(hint_len))
	copy(k.SenderHint, data[offset:offset+int(hint_len)])
	offset += int(hint_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading CreatedAt")
	}
	k.CreatedAt = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SignerPubKey length")
	}
	pubkey_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if pubkey_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading SignerPubKey data")
	}
	k.SignerPubKey = make([]byte, int(pubkey_len))
	copy(k.SignerPubKey, data[offset:offset+int(pubkey_len)])
	offset += int(pubkey_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if sig_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading Signature data")
	}
	k.Signature = make([]byte, int(sig_len))
	copy(k.Signature, data[offset:offset+int(sig_len)])
	offset += int(sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperPayload")
	}

	return nil
}

// SignaturePayload returns the bytes that should be signed/verified.
// Covers: RecordType || GroupID || GroupVersion || Payload || SenderHint || CreatedAt || SignerPubKey
func (k *KeyKeeperPayload) SignaturePayload() []byte {
	payload_len := len(k.Payload)
	hint_len := len(k.SenderHint)
	pubkey_len := len(k.SignerPubKey)

	total := 1 + 16 + 8 + 8 + payload_len + 8 + hint_len + 8 + 8 + pubkey_len
	buf := make([]byte, total)
	offset := 0

	buf[offset] = k.RecordType
	offset += 1

	copy(buf[offset:offset+16], k.GroupID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], k.GroupVersion)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(payload_len))
	offset += 8
	copy(buf[offset:offset+payload_len], k.Payload)
	offset += payload_len

	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(hint_len))
	offset += 8
	copy(buf[offset:offset+hint_len], k.SenderHint)
	offset += hint_len

	binary.BigEndian.PutUint64(buf[offset:offset+8], k.CreatedAt)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(pubkey_len))
	offset += 8
	copy(buf[offset:offset+pubkey_len], k.SignerPubKey)

	return buf
}
