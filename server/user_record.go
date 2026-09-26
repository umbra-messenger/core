package server

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
)

type UserRecord struct {
	EncryptedMasterKey []byte
	SigningPub         []byte
	ExchangePub        []byte
}

func (u *UserRecord) MarshalBinary() ([]byte, error) {
	if u.EncryptedMasterKey == nil || u.SigningPub == nil || u.ExchangePub == nil {
		return nil, errors.New("server: UserRecord contains nil slices")
	}

	master_len := uint64(len(u.EncryptedMasterKey))
	sig_len := uint64(len(u.SigningPub))
	ex_len := uint64(len(u.ExchangePub))

	// 8*3 (lengths) + data + 16 (checksum)
	total_size := 24 + int(master_len) + int(sig_len) + int(ex_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], master_len)
	offset += 8
	copy(buf[offset:offset+int(master_len)], u.EncryptedMasterKey)
	offset += int(master_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_len)
	offset += 8
	copy(buf[offset:offset+int(sig_len)], u.SigningPub)
	offset += int(sig_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], ex_len)
	offset += 8
	copy(buf[offset:offset+int(ex_len)], u.ExchangePub)
	offset += int(ex_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (u *UserRecord) UnmarshalBinary(data []byte) error {
	const min_size = 24 + 16
	if len(data) < min_size {
		return errors.New("server: data too short for UserRecord")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("server: checksum mismatch in UserRecord")
	}

	offset := 0

	master_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	u.EncryptedMasterKey = make([]byte, master_len)
	copy(u.EncryptedMasterKey, data[offset:offset+int(master_len)])
	offset += int(master_len)

	sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	u.SigningPub = make([]byte, sig_len)
	copy(u.SigningPub, data[offset:offset+int(sig_len)])
	offset += int(sig_len)

	ex_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	u.ExchangePub = make([]byte, ex_len)
	copy(u.ExchangePub, data[offset:offset+int(ex_len)])
	offset += int(ex_len)

	if offset != payload_length {
		return errors.New("server: unexpected trailing data in UserRecord")
	}

	return nil
}
