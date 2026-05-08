package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AuditLogResponse represents the response payload for an audit log entry
type AuditLogResponse struct {
	ID        uuid.UUID  `json:"id"`
	Timestamp time.Time  `json:"timestamp"`
	TraceID   *uuid.UUID `json:"traceId,omitempty"`

	EventType string `json:"eventType,omitempty"`
	Action    string `json:"action,omitempty"`
	Status    string `json:"status"`

	ActorType string `json:"actorType"`
	ActorID   string `json:"actorId"`

	TargetType string  `json:"targetType"`
	TargetID   *string `json:"targetId,omitempty"`

	Metadata json.RawMessage `json:"metadata,omitempty"`

	Message            json.RawMessage `json:"message,omitempty"`
	Signature          string          `json:"signature,omitempty"`
	SignatureAlgorithm string          `json:"signatureAlgorithm,omitempty"`
	PublicKeyID        string          `json:"publicKeyId,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
}

// GetAuditLogsResponse represents the response for querying audit logs
type GetAuditLogsResponse struct {
	Logs   []AuditLogResponse `json:"logs"`
	Total  int64              `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}

// ToAuditLogResponse converts an AuditLog model to an AuditLogResponse
func ToAuditLogResponse(log AuditLog) AuditLogResponse {
	return AuditLogResponse{
		ID:                 log.ID,
		Timestamp:          log.Timestamp,
		TraceID:            log.TraceID,
		EventType:          log.EventType,
		Action:             log.Action,
		Status:             log.Status,
		ActorType:          log.ActorType,
		ActorID:            log.ActorID,
		TargetType:         log.TargetType,
		TargetID:           log.TargetID,
		Metadata:           json.RawMessage(log.Metadata),
		Message:            json.RawMessage(log.Message),
		Signature:          log.Signature,
		SignatureAlgorithm: log.SignatureAlgorithm,
		PublicKeyID:        log.PublicKeyID,
		CreatedAt:          log.CreatedAt,
	}
}

// ErrorResponse represents a structured error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details any    `json:"details,omitempty"`
}

// AuditSummaryResponse represents the structured daily audit report
type AuditSummaryResponse struct {
	Date            string             `json:"date"`
	Summary         string             `json:"summary"`
	RuntimeActivity []AuditSummaryItem `json:"runtimeActivity"`
}

// AuditSummaryItem represents a single activity item in the audit summary
type AuditSummaryItem struct {
	Actor     string    `json:"actor"`
	ActorType string    `json:"actorType"`
	Action    string    `json:"action"`
	EventType string    `json:"eventType"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	ID        uuid.UUID `json:"id,omitempty"`
	Count     int       `json:"count"`
}

// BatchResult represents the result of a batch audit log creation.
// It supports partial success — valid logs are ingested, invalid ones are routed
// to the Failed list with per-item error details.
type BatchResult struct {
	Succeeded []AuditLog       `json:"succeeded"`
	Failed    []BatchItemError `json:"failed,omitempty"`
}

// BatchItemError represents a single failed item in a batch operation.
type BatchItemError struct {
	Index  int    `json:"index"`  // 0-based index in the original request array
	Error  string `json:"error"`  // Human-readable error description
	Action string `json:"action"` // Action field from the original request (for identification)
}
