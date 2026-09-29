package protocol

import (
	"encoding/binary"
	"errors"

	"github.com/umbra-messenger/core/internal/crypt"
	"github.com/umbra-messenger/core/internal/shared"
)

// GroupPostMessageRequest is sent to write an encrypted message to a group.
type GroupPostMessageRequest struct {
	GroupID          [16]byte
	EncryptedMessage []byte
	GroupSignature   []byte
}

func (g *GroupPostMessageRequest) MarshalBinary() ([]byte, error) {
	if g.EncryptedMessage == nil || g.GroupSignature == nil {
		return nil, errors.New("protocol: GroupPostMessageRequest contains nil slices")
	}

	enc_msg_len := uint64(len(g.EncryptedMessage))
	group_sig_len := uint64(len(g.GroupSignature))

	total_size := 1 + 16 + 8 + int(enc_msg_len) + 8 + int(group_sig_len) + 16
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_GROUP_POST_MESSAGE
	offset += 1

	copy(buf[offset:offset+16], g.GroupID[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], enc_msg_len)
	offset += 8
	copy(buf[offset:offset+int(enc_msg_len)], g.EncryptedMessage)
	offset += int(enc_msg_len)

	binary.BigEndian.PutUint64(buf[offset:offset+8], group_sig_len)
	offset += 8
	copy(buf[offset:offset+int(group_sig_len)], g.GroupSignature)
	offset += int(group_sig_len)

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GroupPostMessageRequest) UnmarshalBinary(data []byte) error {
	// Min size: 1 (op) + 16 (group_id) + 8*2 (lengths) + 16 (checksum) = 49 bytes
	const min_size = 49
	if len(data) < min_size {
		return errors.New("protocol: data too short for GroupPostMessageRequest")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in GroupPostMessageRequest")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_GROUP_POST_MESSAGE {
		return errors.New("protocol: invalid App OpCode for GroupPostMessageRequest")
	}

	if offset+16 > payload_length {
		return errors.New("protocol: underflow reading GroupID")
	}
	copy(g.GroupID[:], data[offset:offset+16])
	offset += 16

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading EncryptedMessage length")
	}
	enc_msg_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if enc_msg_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading EncryptedMessage data")
	}
	g.EncryptedMessage = make([]byte, int(enc_msg_len))
	copy(g.EncryptedMessage, data[offset:offset+int(enc_msg_len)])
	offset += int(enc_msg_len)

	if offset+8 > payload_length {
		return errors.New("protocol: underflow reading GroupSignature length")
	}
	group_sig_len := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if group_sig_len > uint64(payload_length-offset) {
		return errors.New("protocol: underflow reading GroupSignature data")
	}
	g.GroupSignature = make([]byte, int(group_sig_len))
	copy(g.GroupSignature, data[offset:offset+int(group_sig_len)])
	offset += int(group_sig_len)

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in GroupPostMessageRequest")
	}

	return nil
}

// GroupPostMessageResponse acknowledges the message write.
type GroupPostMessageResponse struct {
	StatusCode uint8
}

func (g *GroupPostMessageResponse) MarshalBinary() ([]byte, error) {
	total_size := 18
	buf := make([]byte, total_size)
	offset := 0

	buf[offset] = shared.APP_OP_GROUP_POST_MESSAGE
	offset += 1

	buf[offset] = g.StatusCode
	offset += 1

	checksum := crypt.Checksum(buf[:offset])
	copy(buf[offset:offset+16], checksum[:])

	return buf, nil
}

func (g *GroupPostMessageResponse) UnmarshalBinary(data []byte) error {
	const min_size = 18
	if len(data) < min_size {
		return errors.New("protocol: data too short for GroupPostMessageResponse")
	}

	payload_length := len(data) - 16
	var received_checksum [16]byte
	copy(received_checksum[:], data[payload_length:])

	expected_checksum := crypt.Checksum(data[:payload_length])
	if received_checksum != expected_checksum {
		return errors.New("protocol: checksum mismatch in GroupPostMessageResponse")
	}

	offset := 0

	app_op := data[offset]
	offset += 1
	if app_op != shared.APP_OP_GROUP_POST_MESSAGE {
		return errors.New("protocol: invalid App OpCode for GroupPostMessageResponse")
	}

	g.StatusCode = data[offset]
	offset += 1

	if offset != payload_length {
		return errors.New("protocol: unexpected trailing data in GroupPostMessageResponse")
	}

	return nil
}
