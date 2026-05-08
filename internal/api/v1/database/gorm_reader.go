package database

import (
	"context"

	"github.com/LSFLK/argus/internal/api/v1/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GormReader implements the AuditReader interface using GORM.
// This separates the read concerns from the write-only Pipeline Sinks.
type GormReader struct {
	db *gorm.DB
}

// NewGormReader creates a new GormReader.
func NewGormReader(db *gorm.DB) *GormReader {
	return &GormReader{db: db}
}

func (r *GormReader) GetAuditLogs(ctx context.Context, filters *AuditLogFilters) ([]models.AuditLog, int64, error) {
	var logs []models.AuditLog
	var total int64

	if filters == nil {
		filters = &AuditLogFilters{}
	}

	query := r.db.WithContext(ctx).Model(&models.AuditLog{})
	if !filters.IncludeMessage {
		query = query.Omit("message")
	}

	if filters.TraceID != nil && *filters.TraceID != "" {
		query = query.Where("trace_id = ?", *filters.TraceID)
	}
	if filters.EventType != nil && *filters.EventType != "" {
		query = query.Where("event_type = ?", *filters.EventType)
	}
	if filters.Action != nil && *filters.Action != "" {
		query = query.Where("action = ?", *filters.Action)
	}
	if filters.Status != nil && *filters.Status != "" {
		query = query.Where("status = ?", *filters.Status)
	}
	if filters.StartTime != nil {
		query = query.Where("timestamp >= ?", *filters.StartTime)
	}
	if filters.EndTime != nil {
		query = query.Where("timestamp <= ?", *filters.EndTime)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	limit := filters.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	if err := query.Order("timestamp DESC").Limit(limit).Offset(filters.Offset).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (r *GormReader) GetAuditLogByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error) {
	var log models.AuditLog
	if err := r.db.WithContext(ctx).First(&log, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &log, nil
}

func (r *GormReader) GetAuditLogsByTraceID(ctx context.Context, traceID string) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	if err := r.db.WithContext(ctx).Where("trace_id = ?", traceID).Order("timestamp ASC").Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

func (r *GormReader) GetAuditSummary(ctx context.Context, startTime, endTime time.Time) ([]models.AuditSummaryItem, error) {
	var summary []models.AuditSummaryItem
	err := r.db.WithContext(ctx).
		Model(&models.AuditLog{}).
		Select("actor_id as actor, actor_type, action, event_type, status, max(timestamp) as timestamp, count(id) as count").
		Where("timestamp >= ? AND timestamp < ?", startTime, endTime).
		Group("actor_id, actor_type, action, event_type, status").
		Find(&summary).Error
	return summary, err
}
