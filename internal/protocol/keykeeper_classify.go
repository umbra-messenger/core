package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// KeyKeeperClassifyRequest is sent to mark records as permanent (important) or delete them (garbage).
type KeyKeeperClassifyRequest struct {
	DestinationUsername []byte
	ImportantIDs        [][16]byte
	GarbageIDs          [][16]byte
	Signature           []byte
}

func (k *KeyKeeperClassifyRequest) MarshalBinary() ([]byte, error) {
	if k.DestinationUsername == nil || k.Signature == nil {
		return nil, errors.New("protocol: KeyKeeperClassifyRequest contains nil slices")
	}
	if k.ImportantIDs == nil {
		k.ImportantIDs = [][16]byte{}
	}
	if k.GarbageIDs == nil {
		k.GarbageIDs = [][16]byte{}
	}

	dest_len := uint64(len(k.DestinationUsername))
	imp_count := uint64(len(k.ImportantIDs))
	garb_count := uint64(len(k.GarbageIDs))
	sig_len := uint64(len(k.Signature))

	// 1 (op) + 8 (len1) + data1 + 8 (count2) + count2*16 + 8 (count3) + count3*16 + 8 (len4) + data4 + 16 (checksum)
	total_size := 1 + 8 + int(dest_len) + 8 + int(imp_count)*16 + 8 + int(garb_count)*16 + 8 + int(sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_KEYKEEPER_CLASSIFY
	offset += 1

	// 2. DestinationUsername
	binary.BigEndian.PutUint64(buf[offset:offset+8], dest_len)
	offset += 8
	copy(buf[offset:offset+int(dest_len)], k.DestinationUsername)
	offset += int(dest_len)

	// 3. ImportantIDs Count
	binary.BigEndian.PutUint64(buf[offset:offset+8], imp_count)
	offset += 8

	// 4. ImportantIDs Data
	for i := 0; i < len(k.ImportantIDs); i++ {
		copy(buf[offset:offset+16], k.ImportantIDs[i][:])
		offset += 16
	}

	// 5. GarbageIDs Count
	binary.BigEndian.PutUint64(buf[offset:offset+8], garb_count)
	offset += 8

	// 6. GarbageIDs Data
	for i := 0; i < len(k.GarbageIDs); i++ {
		copy(buf[offset:offset+16], k.GarbageIDs[i][:])
		offset += 16
	}

	// 7. Signature
	binary.BigEndian.PutUint64(buf[offset:offset+8], sig_len)
	offset += 8
	copy(buf[offset:offset+int(sig_len)], k.Signature)
	offset += int(sig_len)

	// 8. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperClassifyRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 8 (len1) + 8 (count2) + 8 (count3) + 8 (len4) + 16 (checksum) = 49 bytes
	const min_size = 49
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperClassifyRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperClassifyRequest")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_CLASSIFY {
		return errors.New("protocol: invalid App OpCode for KeyKeeperClassifyRequest")
	}

	// 2. DestinationUsername
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading DestinationUsername length")
	}
	dest_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(dest_len) > payload_length {
		return errors.New("protocol: underflow reading DestinationUsername data")
	}
	k.DestinationUsername = make([]byte, dest_len)
	copy(k.DestinationUsername, data[offset:offset+int(dest_len)])
	offset += int(dest_len)

	// 3. ImportantIDs Count
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading ImportantIDs count")
	}
	imp_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	k.ImportantIDs = make([][16]byte, imp_count)
	for i := uint64(0); i < imp_count; i++ {
		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading ImportantID data")
		}
		copy(k.ImportantIDs[i][:], data[offset:offset+16])
		offset += 16
	}

	// 4. GarbageIDs Count
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading GarbageIDs count")
	}
	garb_count := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	k.GarbageIDs = make([][16]byte, garb_count)
	for i := uint64(0); i < garb_count; i++ {
		if offset+16 > payload_length {
			return errors.New("protocol: underflow reading GarbageID data")
		}
		copy(k.GarbageIDs[i][:], data[offset:offset+16])
		offset += 16
	}

	// 5. Signature
	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading Signature length")
	}
	sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset+int(sig_len) > payload_length {
		return errors.New("protocol: underflow reading Signature data")
	}
	k.Signature = make([]byte, sig_len)
	copy(k.Signature, data[offset:offset+int(sig_len)])
	offset += int(sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperClassifyRequest")
	}

	return nil
}

// KeyKeeperClassifyResponse acknowledges the classification request.
type KeyKeeperClassifyResponse struct {
	StatusCode uint8
}

func (k *KeyKeeperClassifyResponse) MarshalBinary() ([]byte, error) {
	// 1 (op) + 1 (status) + 16 (checksum) = 18 bytes
	total_size := 18
	buf := make([]byte, total_size)
	offset := 0

	// 1. App OpCode
	buf[offset] = shared.APP_OP_KEYKEEPER_CLASSIFY
	offset += 1

	// 2. StatusCode
	buf[offset] = k.StatusCode
	offset += 1

	// 3. Checksum
	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (k *KeyKeeperClassifyResponse) UnmarshalBinary(data []byte) error {
	const min_size = 18
	if len(data) < min_size {
		return errors.New("protocol: data too short for KeyKeeperClassifyResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in KeyKeeperClassifyResponse")
	}

	offset := 0

	// 1. App OpCode
	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_KEYKEEPER_CLASSIFY {
		return errors.New("protocol: invalid App OpCode for KeyKeeperClassifyResponse")
	}

	// 2. StatusCode
	if offset+1 > payload_length {
		return errors.New("protocol: underflow reading StatusCode")
	}
	k.StatusCode = data[offset]
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in KeyKeeperClassifyResponse")
	}

	return nil
}
