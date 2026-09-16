package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// OwnerWipeRequest is sent by the owner to delete all server-side state for a group.
type OwnerWipeRequest struct {
	GroupID        [16]byte
	GroupVersion   uint64
	OwnerSignature []byte
}

func (o *OwnerWipeRequest) MarshalBinary() ([]byte, error) {
	if o.OwnerSignature == nil {
		return nil, errors.New("protocol: OwnerWipeRequest contains nil slices")
	}

	owner_sig_len := uint64(len(o.OwnerSignature))

	// 1 (op) + 16 (group_id) + 8 (version) + 8 (len) + data + 16 (checksum)
	total_size := 1 + 16 + 8 + 8 + int(owner_sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_OWNER_WIPE
	offset += 1

	// 2. GroupID
	copy(buf[offset:offset+16], o.GroupID[:])
	offset += 16

	// 3. GroupVersion
	binary.BigEndian.PutUint64(buf[offset:offset+8], o.GroupVersion)
	offset += 8

	// 4. OwnerSignature
	binary.BigEndian.PutUint64(buf[offset:offset+8], owner_sig_len)
	offset += 8
	copy(buf[offset:offset+int(owner_sig_len)], o.OwnerSignature)
	offset += int(owner_sig_len)

	// 5. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (o *OwnerWipeRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 16 (group_id) + 8 (version) + 8 (len) + 16 (checksum) = 49 bytes
	const min_size = 49
	if len(data) < min_size {
		return errors.New("protocol: data too short for OwnerWipeRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in OwnerWipeRequest")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_OWNER_WIPE {
		return errors.New("protocol: invalid App OpCode for OwnerWipeRequest")
	}

	// 2. GroupID
	if offset+16 > payload_length {
		return errors.New("protocol: underflow reading GroupID")
	}
	copy(o.GroupID[:], data[offset:offset+16])
	offset += 16

	// 3. GroupVersion
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading GroupVersion")
	}
	o.GroupVersion = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	// 4. OwnerSignature
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading OwnerSignature length")
	}
	owner_sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(owner_sig_len) > payload_length {
		return errors.New("protocol: underflow reading OwnerSignature data")
	}
	o.OwnerSignature = make([]byte, owner_sig_len)
	copy(o.OwnerSignature, data[offset:offset+int(owner_sig_len)])
	offset += int(owner_sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in OwnerWipeRequest")
	}

	return nil
}

// OwnerWipeResponse acknowledges the group wipe.
type OwnerWipeResponse struct {
	StatusCode uint8
}

func (o *OwnerWipeResponse) MarshalBinary() ([]byte, error) {
	total_size := 18
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_OWNER_WIPE
	offset += 1

	buf[offset] = o.StatusCode
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (o *OwnerWipeResponse) UnmarshalBinary(data []byte) error {
	const min_size = 18
	if len(data) < min_size {
		return errors.New("protocol: data too short for OwnerWipeResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in OwnerWipeResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_OWNER_WIPE {
		return errors.New("protocol: invalid App OpCode for OwnerWipeResponse")
	}

	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	o.StatusCode = data[offset]
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in OwnerWipeResponse")
	}

	return nil
}
