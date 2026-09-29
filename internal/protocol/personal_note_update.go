package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// PersonalNoteUpdateRequest is sent to update the encrypted personal note for a user.
type PersonalNoteUpdateRequest struct {
	Username      []byte
	EncryptedNote []byte
	Signature     []byte
}

func (p *PersonalNoteUpdateRequest) MarshalBinary() ([]byte, error) {
	if p.Username == nil || p.EncryptedNote == nil || p.Signature == nil {
		return nil, errors.New("protocol: PersonalNoteUpdateRequest contains nil slices")
	}

	username_len := uint64(len(p.Username))
	note_len := uint64(len(p.EncryptedNote))
	sig_len := uint64(len(p.Signature))

	total_size := 1 + 8 + int(username_len) + 8 + int(note_len) + 8 + int(sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_PERSONAL_NOTE_UPDATE
	offset += 1

	binary.BigEndian.PutUint64(buf[offset:offset+8], username_len)
	offset += 8
	copy(buf[offset:offset+int(username_len)], p.Username)
	offset += int(username_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], note_len)
	offset += 8
	copy(buf[offset:offset+int(note_len)], p.EncryptedNote)
	offset += int(note_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_len)
	offset += 8
	copy(buf[offset:offset+int(sig_len)], p.Signature)
	offset += int(sig_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (p *PersonalNoteUpdateRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8*3 (lengths) + 16 (checksum) = 41 bytes
	const min_size = 41
	if len(data) < min_size {
		return errors.New("protocol: data too short for PersonalNoteUpdateRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in PersonalNoteUpdateRequest")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_PERSONAL_NOTE_UPDATE {
		return errors.New("protocol: invalid App OpCode for PersonalNoteUpdateRequest")
	}

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Username length")
	}
	username_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if username_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading Username data")
	}
	p.Username = make([]byte, int(username_len))
	copy(p.Username, data[offset:offset+int(username_len)])
	offset += int(username_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedNote length")
	}
	note_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if note_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading EncryptedNote data")
	}
	p.EncryptedNote = make([]byte, int(note_len))
	copy(p.EncryptedNote, data[offset:offset+int(note_len)])
	offset += int(note_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if sig_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading Signature data")
	}
	p.Signature = make([]byte, int(sig_len))
	copy(p.Signature, data[offset:offset+int(sig_len)])
	offset += int(sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in PersonalNoteUpdateRequest")
	}

	return nil
}

// PersonalNoteUpdateResponse acknowledges the note update.
type PersonalNoteUpdateResponse struct {
	StatusCode uint8
}

func (p *PersonalNoteUpdateResponse) MarshalBinary() ([]byte, error) {
	total_size := 18
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_PERSONAL_NOTE_UPDATE
	offset += 1

	buf[offset] = p.StatusCode
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (p *PersonalNoteUpdateResponse) UnmarshalBinary(data []byte) error {
	const min_size = 18
	if len(data) < min_size {
		return errors.New("protocol: data too short for PersonalNoteUpdateResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in PersonalNoteUpdateResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_PERSONAL_NOTE_UPDATE {
		return errors.New("protocol: invalid App OpCode for PersonalNoteUpdateResponse")
	}

	p.StatusCode = data[offset]
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in PersonalNoteUpdateResponse")
	}

	return nil
}
