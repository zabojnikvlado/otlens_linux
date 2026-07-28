package smb

import "time"

// Observation is passive SMB2/SMB3 metadata. Payload fields are unavailable
// for encrypted SMB3 transform records and remain empty in that case.
type Observation struct {
	Timestamp        time.Time `json:"timestamp"`
	ClientIP         string    `json:"client_ip"`
	ServerIP         string    `json:"server_ip"`
	ClientPort       uint16    `json:"client_port"`
	ServerPort       uint16    `json:"server_port"`
	Dialect          string    `json:"dialect,omitempty"`
	Command          string    `json:"command"`
	MessageID        uint64    `json:"message_id,omitempty"`
	SessionID        uint64    `json:"session_id,omitempty"`
	TreeID           uint32    `json:"tree_id,omitempty"`
	FileIDPersistent uint64    `json:"file_id_persistent,omitempty"`
	FileIDVolatile   uint64    `json:"file_id_volatile,omitempty"`
	RequestCommand   string    `json:"request_command,omitempty"`
	RequestMatched   bool      `json:"request_matched"`
	StreamGapped     bool      `json:"stream_gapped"`
	StreamResynced   bool      `json:"stream_resynced"`
	ShareName        string    `json:"share_name,omitempty"`
	FileName         string    `json:"file_name,omitempty"`
	NamedPipe        string    `json:"named_pipe,omitempty"`
	Direction        string    `json:"direction"`
	Bytes            uint64    `json:"bytes,omitempty"`
	Status           uint32    `json:"status,omitempty"`
	IsResponse       bool      `json:"is_response"`
	IsAdminShare     bool      `json:"is_admin_share"`
	IsExecutable     bool      `json:"is_executable"`
	IsScript         bool      `json:"is_script"`
	IsEncrypted      bool      `json:"is_encrypted"`
}
