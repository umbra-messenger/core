package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// VerificationRequest is sent by the client to prove puzzle completion and finalize session establishment.
type VerificationRequest struct {
	// SessionCookie is the AEAD-encrypted state blob returned by the server in HandshakeChallenge.
	SessionCookie []byte
	// SessionTokenFound is the session_token encrypted with session_sym_key to prove possession.
	SessionTokenFound []byte
	// SessionSigningPubKey is the client's derived Ed25519 public key for future GeneralRequest signatures.
	SessionSigningPubKey []byte
}

func (v *VerificationRequest) MarshalBinary() ([]byte, error) {
	if v.SessionCookie == nil || v.SessionTokenFound == nil || v.SessionSigningPubKey == nil {
		return nil, errors.New("protocol: VerificationRequest contains nil slices")
	}

	cookie_len := uint64(len(v.SessionCookie))
	token_found_len := uint64(len(v.SessionTokenFound))
	signing_pub_len := uint64(len(v.SessionSigningPubKey))

	// 1 (type) + 3*(8 (len) + data) + 16 (checksum)
	total_size := 1 + 8 + int(cookie_len) + 8 + int(token_found_len) + 8 + int(signing_pub_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. MessageType (Wire-format)
	buf[offset] = shared.MSG_VERIFICATION_REQ
	offset += 1

	// 2. SessionCookie
	binary.BigEndian.PutUint64(buf[offset:offset+8], cookie_len)
	offset += 8
	copy(buf[offset:offset+int(cookie_len)], v.SessionCookie)
	offset += int(cookie_len)

	// 3. SessionTokenFound
	binary.BigEndian.PutUint64(buf[offset:offset+8], token_found_len)
	offset += 8
	copy(buf[offset:offset+int(token_found_len)], v.SessionTokenFound)
	offset += int(token_found_len)

	// 4. SessionSigningPublicKey
	binary.BigEndian.PutUint64(buf[offset:offset+8], signing_pub_len)
	offset += 8
	copy(buf[offset:offset+int(signing_pub_len)], v.SessionSigningPubKey)
	offset += int(signing_pub_len)

	// 5. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (v *VerificationRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (type) + 3*8 (lengths) + 16 (checksum) = 41 bytes
	const min_size = 1 + 24 + 16
	if len(data) < min_size {
		return errors.New("protocol: data too short for VerificationRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in VerificationRequest")
	}

	offset := 0

	// 1. MessageType
	msg_type := data[offset]
	offset += 1
	if msg_type != shared.MSG_VERIFICATION_REQ {
		return errors.New("protocol: invalid MessageType for VerificationRequest")
	}

	// 2. SessionCookie
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SessionCookie length")
	}
	cookie_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(cookie_len) > payload_length {
		return errors.New("protocol: underflow reading SessionCookie data")
	}
	v.SessionCookie = make([]byte, cookie_len)
	copy(v.SessionCookie, data[offset:offset+int(cookie_len)])
	offset += int(cookie_len)

	// 3. SessionTokenFound
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SessionTokenFound length")
	}
	token_found_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(token_found_len) > payload_length {
		return errors.New("protocol: underflow reading SessionTokenFound data")
	}
	v.SessionTokenFound = make([]byte, token_found_len)
	copy(v.SessionTokenFound, data[offset:offset+int(token_found_len)])
	offset += int(token_found_len)

	// 4. SessionSigningPublicKey
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading SessionSigningPublicKey length")
	}
	signing_pub_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(signing_pub_len) > payload_length {
		return errors.New("protocol: underflow reading SessionSigningPublicKey data")
	}
	v.SessionSigningPubKey = make([]byte, signing_pub_len)
	copy(v.SessionSigningPubKey, data[offset:offset+int(signing_pub_len)])
	offset += int(signing_pub_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in VerificationRequest")
	}

	return nil
}
