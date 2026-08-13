package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// HandshakeChallenge represents the server's response to HandshakeInit.
type HandshakeChallenge struct {
	SessionID         []byte
	ExchangePublicKey []byte
	SigningPublicKey  []byte
	EncryptedPayload  []byte
	Signature         []byte
}

func (c *HandshakeChallenge) MarshalBinary() ([]byte, error) {
	if c.SessionID == nil || c.ExchangePublicKey == nil || c.SigningPublicKey == nil || c.EncryptedPayload == nil || c.Signature == nil {
		return nil, errors.New("protocol: HandshakeChallenge fields cannot be nil")
	}
	len_sid := uint64(len(c.SessionID))
	len_exch := uint64(len(c.ExchangePublicKey))
	len_sign := uint64(len(c.SigningPublicKey))
	len_enc := uint64(len(c.EncryptedPayload))
	len_sig := uint64(len(c.Signature))

	total_size := 8 + int(len_sid) + 8 + int(len_exch) + 8 + int(len_sign) + 8 + int(len_enc) + 8 + int(len_sig) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sid)
	offset += 8
	copy(buf[offset:offset+int(len_sid)], c.SessionID)
	offset += int(len_sid)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_exch)
	offset += 8
	copy(buf[offset:offset+int(len_exch)], c.ExchangePublicKey)
	offset += int(len_exch)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sign)
	offset += 8
	copy(buf[offset:offset+int(len_sign)], c.SigningPublicKey)
	offset += int(len_sign)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_enc)
	offset += 8
	copy(buf[offset:offset+int(len_enc)], c.EncryptedPayload)
	offset += int(len_enc)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sig)
	offset += 8
	copy(buf[offset:offset+int(len_sig)], c.Signature)
	offset += int(len_sig)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *HandshakeChallenge) UnmarshalBinary(data []byte) error {
	const min_size = 8 + 8 + 8 + 8 + 8 + 16 // 56 bytes
	if len(data) < min_size {
		return errors.New("protocol: data too short for HandshakeChallenge")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	len_sid := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sid) > payload_length {
		return errors.New("protocol: underflow reading SessionID")
	}
	c.SessionID = make([]byte, len_sid)
	copy(c.SessionID, data[offset:offset+int(len_sid)])
	offset += int(len_sid)

	len_exch := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_exch) > payload_length {
		return errors.New("protocol: underflow reading ExchangePublicKey")
	}
	c.ExchangePublicKey = make([]byte, len_exch)
	copy(c.ExchangePublicKey, data[offset:offset+int(len_exch)])
	offset += int(len_exch)

	len_sign := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sign) > payload_length {
		return errors.New("protocol: underflow reading SigningPublicKey")
	}
	c.SigningPublicKey = make([]byte, len_sign)
	copy(c.SigningPublicKey, data[offset:offset+int(len_sign)])
	offset += int(len_sign)

	len_enc := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_enc) > payload_length {
		return errors.New("protocol: underflow reading EncryptedPayload")
	}
	c.EncryptedPayload = make([]byte, len_enc)
	copy(c.EncryptedPayload, data[offset:offset+int(len_enc)])
	offset += int(len_enc)

	len_sig := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sig) > payload_length {
		return errors.New("protocol: underflow reading Signature")
	}
	c.Signature = make([]byte, len_sig)
	copy(c.Signature, data[offset:offset+int(len_sig)])
	offset += int(len_sig)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
