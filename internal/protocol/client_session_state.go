package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

// ClientSessionState represents the persistent state of a session stored by the client.
type ClientSessionState struct {
	SessionMasterKey        [32]byte
	ServerExchangePublicKey []byte
	ServerSigningPublicKey  []byte
	SessionID               []byte
	SessionToken            []byte
	SessionSymmetricKey     []byte
	IsEstablished           bool
	Username                []byte
	UserMasterKey           [32]byte
}

func (c *ClientSessionState) MarshalBinary() ([]byte, error) {
	if c.ServerExchangePublicKey == nil || c.ServerSigningPublicKey == nil || c.SessionID == nil || c.SessionToken == nil || c.SessionSymmetricKey == nil {
		return nil, errors.New("protocol: ClientSessionState slice fields cannot be nil")
	}
	len_server_exch := uint64(len(c.ServerExchangePublicKey))
	len_server_sign := uint64(len(c.ServerSigningPublicKey))
	len_sid := uint64(len(c.SessionID))
	len_token := uint64(len(c.SessionToken))
	len_sym := uint64(len(c.SessionSymmetricKey))
	len_user := uint64(len(c.Username))

	// 32 + 8+server_exch + 8+server_sign + 8+sid + 8+token + 8+sym + 1 + 8+user + 32 + 16
	total_size := 32 + 8 + int(len_server_exch) + 8 + int(len_server_sign) + 8 + int(len_sid) + 8 + int(len_token) + 8 + int(len_sym) + 1 + 8 + int(len_user) + 32 + 16
	buf := make([]byte, total_size)
	offset := 0

	copy(buf[offset:offset+32], c.SessionMasterKey[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_server_exch)
	offset += 8
	copy(buf[offset:offset+int(len_server_exch)], c.ServerExchangePublicKey)
	offset += int(len_server_exch)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_server_sign)
	offset += 8
	copy(buf[offset:offset+int(len_server_sign)], c.ServerSigningPublicKey)
	offset += int(len_server_sign)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sid)
	offset += 8
	copy(buf[offset:offset+int(len_sid)], c.SessionID)
	offset += int(len_sid)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_token)
	offset += 8
	copy(buf[offset:offset+int(len_token)], c.SessionToken)
	offset += int(len_token)

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_sym)
	offset += 8
	copy(buf[offset:offset+int(len_sym)], c.SessionSymmetricKey)
	offset += int(len_sym)

	if c.IsEstablished {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], len_user)
	offset += 8
	copy(buf[offset:offset+int(len_user)], c.Username)
	offset += int(len_user)

	copy(buf[offset:offset+32], c.UserMasterKey[:])
	offset += 32

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (c *ClientSessionState) UnmarshalBinary(data []byte) error {
	// 32 + 8 + 8 + 8 + 8 + 8 + 1 + 8 + 32 + 16 = 121 bytes minimum
	const min_size = 121
	if len(data) < min_size {
		return errors.New("protocol: data too short for ClientSessionState")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	if received_checksum != crypt.Checksum(data[:payload_length]) {
		return errors.New("protocol: checksum mismatch")
	}

	offset := 0
	copy(c.SessionMasterKey[:], data[offset:offset+32])
	offset += 32

	len_server_exch := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_server_exch) > payload_length {
		return errors.New("protocol: underflow reading ServerExchangePublicKey")
	}
	c.ServerExchangePublicKey = make([]byte, len_server_exch)
	copy(c.ServerExchangePublicKey, data[offset:offset+int(len_server_exch)])
	offset += int(len_server_exch)

	len_server_sign := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_server_sign) > payload_length {
		return errors.New("protocol: underflow reading ServerSigningPublicKey")
	}
	c.ServerSigningPublicKey = make([]byte, len_server_sign)
	copy(c.ServerSigningPublicKey, data[offset:offset+int(len_server_sign)])
	offset += int(len_server_sign)

	len_sid := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sid) > payload_length {
		return errors.New("protocol: underflow reading SessionID")
	}
	c.SessionID = make([]byte, len_sid)
	copy(c.SessionID, data[offset:offset+int(len_sid)])
	offset += int(len_sid)

	len_token := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_token) > payload_length {
		return errors.New("protocol: underflow reading SessionToken")
	}
	c.SessionToken = make([]byte, len_token)
	copy(c.SessionToken, data[offset:offset+int(len_token)])
	offset += int(len_token)

	len_sym := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_sym) > payload_length {
		return errors.New("protocol: underflow reading SessionSymmetricKey")
	}
	c.SessionSymmetricKey = make([]byte, len_sym)
	copy(c.SessionSymmetricKey, data[offset:offset+int(len_sym)])
	offset += int(len_sym)

	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading IsEstablished")
	}
	c.IsEstablished = data[offset] == 1
	offset += 1

	len_user := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(len_user) > payload_length {
		return errors.New("protocol: underflow reading Username")
	}
	c.Username = make([]byte, len_user)
	copy(c.Username, data[offset:offset+int(len_user)])
	offset += int(len_user)

	if offset+32 > payload_length {
		return errors.New("protocol: underflow reading UserMasterKey")
	}
	copy(c.UserMasterKey[:], data[offset:offset+32])
	offset += 32

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in payload")
	}
	return nil
}
