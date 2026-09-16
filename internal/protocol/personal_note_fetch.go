package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// PersonalNoteFetchRequest is sent to retrieve the encrypted personal note for a user.
type PersonalNoteFetchRequest struct {
	Username  []byte
	Signature []byte
}

func (p *PersonalNoteFetchRequest) MarshalBinary() ([]byte, error) {
	if p.Username == nil || p.Signature == nil {
		return nil, errors.New("protocol: PersonalNoteFetchRequest contains nil slices")
	}

	username_len := uint64(len(p.Username))
	sig_len := uint64(len(p.Signature))

	// 1 (op) + 8 (len1) + data1 + 8 (len2) + data2 + 16 (checksum)
	total_size := 1 + 8 + int(username_len) + 8 + int(sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_PERSONAL_NOTE_FETCH
	offset += 1

	// 2. Username
	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], p.Username)
	offset += int(username_len)

	// 3. Signature
	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_len)
	offset += 8
	copy(buf[offset:offset+int(sig_len)], p.Signature)
	offset += int(sig_len)

	// 4. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (p *PersonalNoteFetchRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (len1) + 8 (len2) + 16 (checksum) = 33 bytes
	const min_size = 33
	if len(data) < min_size {
		return errors.New("protocol: data too short for PersonalNoteFetchRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in PersonalNoteFetchRequest")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_PERSONAL_NOTE_FETCH {
		return errors.New("protocol: invalid App OpCode for PersonalNoteFetchRequest")
	}

	// 2. Username
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Username length")
	}
	username_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(username_len) > payload_length {
		return errors.New("protocol: underflow reading Username data")
	}
	p.Username = make([]byte, username_len)
	copy(p.Username, data[offset:offset+int(username_len)])
	offset += int(username_len)

	// 3. Signature
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(sig_len) > payload_length {
		return errors.New("protocol: underflow reading Signature data")
	}
	p.Signature = make([]byte, sig_len)
	copy(p.Signature, data[offset:offset+int(sig_len)])
	offset += int(sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in PersonalNoteFetchRequest")
	}

	return nil
}

// PersonalNoteFetchResponse returns the encrypted personal note for the user.
type PersonalNoteFetchResponse struct {
	StatusCode    uint8
	EncryptedNote []byte
}

func (p *PersonalNoteFetchResponse) MarshalBinary() ([]byte, error) {
	if p.EncryptedNote == nil {
		p.EncryptedNote = []byte{}
	}

	note_len := uint64(len(p.EncryptedNote))

	// 1 (op) + 1 (status) + 8 (len) + data + 16 (checksum)
	total_size := 1 + 1 + 8 + int(note_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_PERSONAL_NOTE_FETCH
	offset += 1

	// 2. StatusCode
	buf[offset] = p.StatusCode
	offset += 1

	// 3. EncryptedNote
	binary.BigEndian.PutUint64(buf[offset:offset+8], note_len)
	offset += 8
	copy(buf[offset:offset+int(note_len)], p.EncryptedNote)
	offset += int(note_len)

	// 4. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (p *PersonalNoteFetchResponse) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 1 (status) + 8 (len) + 16 (checksum) = 26 bytes
	const min_size = 26
	if len(data) < min_size {
		return errors.New("protocol: data too short for PersonalNoteFetchResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in PersonalNoteFetchResponse")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_PERSONAL_NOTE_FETCH {
		return errors.New("protocol: invalid App OpCode for PersonalNoteFetchResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	p.StatusCode = data[offset]
	offset += 1

	// 3. EncryptedNote
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedNote length")
	}
	note_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(note_len) > payload_length {
		return errors.New("protocol: underflow reading EncryptedNote data")
	}
	p.EncryptedNote = make([]byte, note_len)
	copy(p.EncryptedNote, data[offset:offset+int(note_len)])
	offset += int(note_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in PersonalNoteFetchResponse")
	}

	return nil
}
