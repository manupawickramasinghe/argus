package database

import (
	"context"
	"time"

	"github.com/LSFLK/argus/internal/api/v1/models"
	"github.com/google/uuid"
)

const (
	// Pagination defaults
	DefaultLimit = 100
	MaxLimit     = 1000
)

// AuditReader defines the interface for querying audit logs.
// This is used by the service layer to retrieve logs from a primary storage backend.
type AuditReader interface {
	// GetAuditLogsByTraceID retrieves all audit logs for a given trace ID
	GetAuditLogsByTraceID(ctx context.Context, traceID string) ([]models.AuditLog, error)

	// GetAuditLogs retrieves audit logs with optional filtering
	GetAuditLogs(ctx context.Context, filters *AuditLogFilters) ([]models.AuditLog, int64, error)

	// GetAuditLogByID retrieves a single audit log entry by its ID
	GetAuditLogByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error)

	// GetAuditSummary retrieves summary of audit logs
	GetAuditSummary(ctx context.Context, startTime, endTime time.Time) ([]models.AuditSummaryItem, error)
}

// AuditLogFilters represents query filters for retrieving audit logs
type AuditLogFilters struct {
	TraceID        *string
	EventType      *string
	Action         *string
	Status         *string
	StartTime      *time.Time
	EndTime        *time.Time
	Limit          int
	Offset         int
	IncludeMessage bool
}
