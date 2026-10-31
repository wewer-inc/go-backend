package adminaudit

import (
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
)

// ListRequest is the query string of GET /v1/admin/audit.
type ListRequest struct {
	Page               int    `form:"page"                 binding:"omitempty,min=1"`
	PageSize           int    `form:"page_size"            binding:"omitempty,min=1,max=100"`
	Event              string `form:"event"                binding:"omitempty,max=100"`
	ActorUserID        uint   `form:"actor_user_id"`
	ImpersonatorUserID uint   `form:"impersonator_user_id"`
}

// VerifyRequest is the query string of GET /v1/admin/audit/verify. Pass the head_id and
// head returned by an earlier run, stored away from the database, as the checkpoint. A
// check with no checkpoint cannot notice that the newest rows were deleted.
type VerifyRequest struct {
	CheckpointID   uint   `form:"checkpoint_id"   binding:"required_with=CheckpointHash"`
	CheckpointHash string `form:"checkpoint_hash" binding:"required_with=CheckpointID,omitempty,len=64,hexadecimal"`
}

// LogResponse is one audit row. Detail stays a string because the hash covers its exact
// bytes, and hash and prev_hash are served so a client can verify rows independently.
type LogResponse struct {
	ID                 uint      `json:"id"`
	CreatedAt          time.Time `json:"created_at"`
	Event              string    `json:"event"`
	ActorUserID        *uint     `json:"actor_user_id,omitempty"`
	ImpersonatorUserID *uint     `json:"impersonator_user_id,omitempty"`
	IP                 string    `json:"ip,omitempty"`
	Detail             string    `json:"detail,omitempty"`
	ChainVersion       int       `json:"chain_version"`
	PrevHash           string    `json:"prev_hash"`
	Hash               string    `json:"hash"`
}

func toLogResponse(l *audit.Log) LogResponse {
	return LogResponse{
		ID:                 l.ID,
		CreatedAt:          l.CreatedAt,
		Event:              l.Event,
		ActorUserID:        l.ActorUserID,
		ImpersonatorUserID: l.ImpersonatorUserID,
		IP:                 l.IP,
		Detail:             l.Detail,
		ChainVersion:       l.ChainVersion,
		PrevHash:           l.PrevHash,
		Hash:               l.Hash,
	}
}
