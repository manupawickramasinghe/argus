package testutil

import (
	"context"
	"fmt"
	"sort"

	"github.com/LSFLK/argus/internal/api/v1/database"
	v1models "github.com/LSFLK/argus/internal/api/v1/models"
	"github.com/google/uuid"
)

// MockRepository implements both sinks.Sink and database.AuditReader for testing.
type MockRepository struct {
	logs        []*v1models.AuditLog
	InjectError error
}

// NewMockRepository creates a new MockRepository instance.
func NewMockRepository() *MockRepository {
	return &MockRepository{
		logs: make([]*v1models.AuditLog, 0),
	}
}

func (m *MockRepository) Name() string {
	return "MockRepository"
}

// Write simulates persisting an audit log (implements sinks.Sink).
func (m *MockRepository) Write(ctx context.Context, log *v1models.AuditLog) error {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	m.logs = append(m.logs, log)
	return nil
}

// CreateAuditLog is a convenience method for testing (compatibility with old tests).
func (m *MockRepository) CreateAuditLog(ctx context.Context, log *v1models.AuditLog) (*v1models.AuditLog, error) {
	err := m.Write(ctx, log)
	return log, err
}

// CreateAuditLogBatch is a convenience method for testing (compatibility with old tests).
func (m *MockRepository) CreateAuditLogBatch(ctx context.Context, logs []v1models.AuditLog) ([]v1models.AuditLog, error) {
	for i := range logs {
		_ = m.Write(ctx, &logs[i])
	}
	return logs, nil
}

// WriteBatch simulates persisting multiple audit logs (implements sinks.Sink).
func (m *MockRepository) WriteBatch(ctx context.Context, logs []v1models.AuditLog) error {
	for i := range logs {
		_ = m.Write(ctx, &logs[i])
	}
	return nil
}

// Close is a no-op for the MockRepository.
func (m *MockRepository) Close() error {
	return nil
}

// IsCritical returns true for MockRepository.
func (m *MockRepository) IsCritical() bool {
	return true
}

// GetAuditLogsByTraceID retrieves all audit logs for a given trace ID (implements database.AuditReader).
func (m *MockRepository) GetAuditLogsByTraceID(ctx context.Context, traceID string) ([]v1models.AuditLog, error) {
	traceUUID, err := uuid.Parse(traceID)
	if err != nil {
		return []v1models.AuditLog{}, nil
	}

	filteredLogs := []v1models.AuditLog{}
	for _, log := range m.logs {
		if log.TraceID != nil && *log.TraceID == traceUUID {
			filteredLogs = append(filteredLogs, *log)
		}
	}

	sort.Slice(filteredLogs, func(i, j int) bool {
		return filteredLogs[i].Timestamp.Before(filteredLogs[j].Timestamp)
	})

	return filteredLogs, nil
}

// GetAuditLogs retrieves audit logs with optional filtering (implements database.AuditReader).
func (m *MockRepository) GetAuditLogs(ctx context.Context, filters *database.AuditLogFilters) ([]v1models.AuditLog, int64, error) {
	if m.InjectError != nil {
		return nil, 0, m.InjectError
	}

	if filters == nil {
		filters = &database.AuditLogFilters{}
	}

	filteredLogs := []v1models.AuditLog{}
	for _, log := range m.logs {
		matches := true
		if filters.TraceID != nil && *filters.TraceID != "" {
			traceUUID, err := uuid.Parse(*filters.TraceID)
			if err != nil {
				continue
			}
			if log.TraceID == nil || *log.TraceID != traceUUID {
				matches = false
			}
		}
		if matches && filters.EventType != nil && *filters.EventType != "" {
			if log.EventType != *filters.EventType {
				matches = false
			}
		}
		if matches && filters.Action != nil && *filters.Action != "" {
			if log.Action != *filters.Action {
				matches = false
			}
		}
		if matches && filters.Status != nil && *filters.Status != "" {
			if log.Status != *filters.Status {
				matches = false
			}
		}

		if matches {
			filteredLogs = append(filteredLogs, *log)
		}
	}

	total := int64(len(filteredLogs))
	sort.Slice(filteredLogs, func(i, j int) bool {
		return filteredLogs[i].Timestamp.After(filteredLogs[j].Timestamp)
	})

	limit := filters.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filters.Offset
	if offset < 0 {
		offset = 0
	}

	start := offset
	end := offset + limit
	if start > len(filteredLogs) {
		start = len(filteredLogs)
	}
	if end > len(filteredLogs) {
		end = len(filteredLogs)
	}

	if start >= end {
		return []v1models.AuditLog{}, total, nil
	}

	paginatedLogs := filteredLogs[start:end]
	if !filters.IncludeMessage {
		for i := range paginatedLogs {
			paginatedLogs[i].Message = nil
		}
	}

	return paginatedLogs, total, nil
}

// GetAuditLogByID retrieves a single audit log entry by its ID (implements database.AuditReader).
func (m *MockRepository) GetAuditLogByID(ctx context.Context, id uuid.UUID) (*v1models.AuditLog, error) {
	for _, log := range m.logs {
		if log.ID == id {
			return log, nil
		}
	}
	return nil, fmt.Errorf("audit log not found with ID %s", id)
}

// GetLogs returns all logs stored in the mock.
func (m *MockRepository) GetLogs() []*v1models.AuditLog {
	return m.logs
}

// ClearLogs clears all stored logs.
func (m *MockRepository) ClearLogs() {
	m.logs = make([]*v1models.AuditLog, 0)
}
