package server

import (
	"github.com/umbra-messenger/core/internal/protocol"
	"github.com/umbra-messenger/core/internal/shared"
)

func (s *Server) handle_app_sync(session_id [16]byte, session_state *SessionState, payload []byte) ([]byte, error) {
	req := &protocol.SyncRequest{}
	if err := req.UnmarshalBinary(payload); err != nil {
		return nil, err
	}

	groups := make([]protocol.SyncGroupResponse, len(req.Groups))

	for i := 0; i < len(req.Groups); i++ {
		group_req := &req.Groups[i]

		groups[i] = protocol.SyncGroupResponse{
			GroupID:  group_req.GroupID,
			Messages: []protocol.SyncedMessage{},
		}

		query_prefix := build_group_message_query_prefix(group_req.GroupID)
		message_values, err := s.storage.Query(shared.STORE_CTX_GROUP_MESSAGE, query_prefix, nil)
		if err != nil {
			// Group may not exist — return empty message list (zero-knowledge).
			continue
		}

		// Client contract: SinceTimestamp is the timestamp of the last message
		// the client has fully processed. Return strictly newer messages.
		for j := 0; j < len(message_values); j++ {
			msg := &GroupMessage{}
			if err := msg.UnmarshalBinary(message_values[j]); err != nil {
				continue
			}
			if msg.Timestamp > group_req.SinceTimestamp {
				groups[i].Messages = append(groups[i].Messages, protocol.SyncedMessage{
					EncryptedMessage: msg.EncryptedMessage,
					Timestamp:        msg.Timestamp,
					GroupVersion:     msg.GroupVersion,
				})
			}
		}
	}

	res := &protocol.SyncResponse{
		StatusCode: shared.APP_STATUS_SUCCESS,
		Groups:     groups,
	}
	return res.MarshalBinary()
}
