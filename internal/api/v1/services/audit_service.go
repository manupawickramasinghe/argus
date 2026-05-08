package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/LSFLK/argus/internal/api/v1/database"
	v1models "github.com/LSFLK/argus/internal/api/v1/models"
	"github.com/LSFLK/argus/internal/metrics"
	"github.com/LSFLK/argus/internal/pipeline"
	"github.com/LSFLK/argus/pkg/audit"
	"github.com/google/uuid"
)

// AuditService handles generalized audit log operations.
// It uses a Sink Manager to fan out logs to multiple destinations.
type AuditService struct {
	pipeline          *pipeline.Manager
	reader            database.AuditReader
	keys              *PublicKeyRegistry
	requireSignatures bool
}

// NewAuditService creates a new audit service instance.
func NewAuditService(mgr *pipeline.Manager, reader database.AuditReader, keys *PublicKeyRegistry) *AuditService {
	return &AuditService{
		pipeline:          mgr,
		reader:            reader,
		keys:              keys,
		requireSignatures: os.Getenv("REQUIRE_SIGNATURES") == "true",
	}
}

// CreateAuditLog creates a new audit log entry from a request
func (s *AuditService) CreateAuditLog(ctx context.Context, req *v1models.CreateAuditLogRequest) (*v1models.AuditLog, error) {
	// Enforce signatures in production if configured
	if s.requireSignatures && req.Signature == "" {
		return nil, fmt.Errorf("%w: signature is strictly required for non-repudiation", ErrValidation)
	}

	// Verify signature if provided
	if req.Signature != "" {
		if err := s.verifyRequestSignature(req); err != nil {
			metrics.SignatureVerificationErrors.Inc()
			return nil, fmt.Errorf("%w: signature verification failed: %w", ErrValidation, err)
		}
	}

	// Marshal metadata to JSONB
	metaBytes, err := json.Marshal(req.Metadata)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal metadata: %w", ErrValidation, err)
	}

	// Convert request to model
	auditLog := &v1models.AuditLog{
		EventType:          req.EventType,
		Action:             req.Action,
		Status:             req.Status,
		ActorType:          req.ActorType,
		ActorID:            req.ActorID,
		TargetType:         req.TargetType,
		TargetID:           req.TargetID,
		Message:            v1models.JSONBRawMessage(req.Message),
		Metadata:           v1models.JSONBRawMessage(metaBytes),
		Signature:          req.Signature,
		SignatureAlgorithm: req.SignatureAlgorithm,
		PublicKeyID:        req.PublicKeyID,
	}

	// Parse and validate timestamp (required)
	timestamp, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid timestamp format, expected RFC3339: %w", ErrValidation, err)
	}
	auditLog.Timestamp = timestamp.UTC()

	// Handle trace ID
	if req.TraceID != nil && *req.TraceID != "" {
		traceUUID, err := uuid.Parse(*req.TraceID)
		if err != nil {
			// Wrap as domain validation error
			return nil, fmt.Errorf("%w: invalid traceId format: %w", ErrValidation, err)
		}
		auditLog.TraceID = &traceUUID
	}

	// Validate before creating
	if err := auditLog.Validate(); err != nil {
		// All validation errors from the model are treated as domain validation errors
		// This abstracts away the implementation details (GORM or other validation)
		return nil, fmt.Errorf("%w: %w", ErrValidation, err)
	}

	// Set default values before dispatching to sinks
	if auditLog.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID v7: %w", err)
		}
		auditLog.ID = id
	}
	auditLog.CreatedAt = time.Now().UTC()

	// Dispatch to all registered sinks (fan-out)
	errs := s.pipeline.Dispatch(ctx, auditLog)
	if len(errs) > 0 {
		for _, err := range errs {
			slog.Error("Sink dispatch failed", "error", err)
		}

		if s.pipeline.HasCriticalFailure(errs) {
			return nil, fmt.Errorf("critical storage sink failed: %w", errs[0])
		}
	}

	metrics.LogsIngestedTotal.Inc()
	return auditLog, nil
}

// CreateAuditLogBatch creates a batch of audit logs with partial-success semantics.
// Instead of rejecting the entire batch when one log has a malformed signature,
// valid logs are ingested and invalid ones are reported as failures.
// This prevents a single bad log from causing DoS against 99 valid logs.
func (s *AuditService) CreateAuditLogBatch(ctx context.Context, batchReq v1models.CreateAuditLogBatchRequest) (*v1models.BatchResult, error) {
	result := &v1models.BatchResult{
		Succeeded: make([]v1models.AuditLog, 0, len(batchReq)),
		Failed:    make([]v1models.BatchItemError, 0),
	}

	validLogs := make([]v1models.AuditLog, 0, len(batchReq))

	for i, req := range batchReq {
		// Enforce signatures in production if configured
		if s.requireSignatures && req.Signature == "" {
			result.Failed = append(result.Failed, v1models.BatchItemError{
				Index:  i,
				Error:  "signature is strictly required for non-repudiation",
				Action: req.Action,
			})
			continue
		}

		// Verify signature if provided — failure routes to DLQ, not batch rejection
		if req.Signature != "" {
			if err := s.verifyRequestSignature(&req); err != nil {
				metrics.SignatureVerificationErrors.Inc()
				result.Failed = append(result.Failed, v1models.BatchItemError{
					Index:  i,
					Error:  fmt.Sprintf("signature verification failed: %v", err),
					Action: req.Action,
				})
				continue
			}
		}

		// Marshal metadata to JSONB
		metaBytes, err := json.Marshal(req.Metadata)
		if err != nil {
			result.Failed = append(result.Failed, v1models.BatchItemError{
				Index:  i,
				Error:  fmt.Sprintf("failed to marshal metadata: %v", err),
				Action: req.Action,
			})
			continue
		}

		// Convert request to model
		auditLog := v1models.AuditLog{
			EventType:          req.EventType,
			Action:             req.Action,
			Status:             req.Status,
			ActorType:          req.ActorType,
			ActorID:            req.ActorID,
			TargetType:         req.TargetType,
			TargetID:           req.TargetID,
			Message:            v1models.JSONBRawMessage(req.Message),
			Metadata:           v1models.JSONBRawMessage(metaBytes),
			Signature:          req.Signature,
			SignatureAlgorithm: req.SignatureAlgorithm,
			PublicKeyID:        req.PublicKeyID,
		}

		// Parse and validate timestamp
		timestamp, err := time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			result.Failed = append(result.Failed, v1models.BatchItemError{
				Index:  i,
				Error:  fmt.Sprintf("invalid timestamp format, expected RFC3339: %v", err),
				Action: req.Action,
			})
			continue
		}
		auditLog.Timestamp = timestamp.UTC()

		if req.TraceID != nil && *req.TraceID != "" {
			traceUUID, err := uuid.Parse(*req.TraceID)
			if err != nil {
				result.Failed = append(result.Failed, v1models.BatchItemError{
					Index:  i,
					Error:  fmt.Sprintf("invalid traceId format: %v", err),
					Action: req.Action,
				})
				continue
			}
			auditLog.TraceID = &traceUUID
		}

		if err := auditLog.Validate(); err != nil {
			result.Failed = append(result.Failed, v1models.BatchItemError{
				Index:  i,
				Error:  fmt.Sprintf("validation error: %v", err),
				Action: req.Action,
			})
			continue
		}

		validLogs = append(validLogs, auditLog)
	}

	// If ALL logs failed validation, return an error so the handler can respond 400
	if len(validLogs) == 0 && len(result.Failed) > 0 {
		return result, fmt.Errorf("%w: all %d logs in batch failed validation", ErrValidation, len(result.Failed))
	}

	// Populate IDs and Timestamps for the valid batch
	for i := range validLogs {
		if validLogs[i].ID == uuid.Nil {
			id, err := uuid.NewV7()
			if err != nil {
				return nil, fmt.Errorf("failed to generate UUID v7 for batch item %d: %w", i, err)
			}
			validLogs[i].ID = id
		}
		validLogs[i].CreatedAt = time.Now().UTC()
	}

	// Dispatch valid batch to all registered sinks (fan-out)
	// This is much more efficient than individual dispatch as it allows
	// sinks (like Postgres) to use bulk insert operations.
	if len(validLogs) > 0 {
		errs := s.pipeline.DispatchBatch(ctx, validLogs)
		if len(errs) > 0 {
			for _, err := range errs {
				slog.Error("Sink batch dispatch failed", "error", err)
			}

			// If any critical storage sink failed, fail the batch operation
			if s.pipeline.HasCriticalFailure(errs) {
				return nil, fmt.Errorf("critical storage sink failed for batch: %w", errs[0])
			}
		}
	}

	metrics.LogsIngestedTotal.Add(float64(len(validLogs)))
	result.Succeeded = validLogs
	return result, nil
}

// GetAuditLogs retrieves audit logs with optional filtering
func (s *AuditService) GetAuditLogs(ctx context.Context, traceID *string, eventType *string, limit, offset int, includeMessage bool) ([]v1models.AuditLog, int64, error) {
	filters := &database.AuditLogFilters{
		TraceID:        traceID,
		EventType:      eventType,
		Limit:          limit,
		Offset:         offset,
		IncludeMessage: includeMessage,
	}

	return s.reader.GetAuditLogs(ctx, filters)
}

// GetAuditLogByID retrieves a single audit log entry by its ID
func (s *AuditService) GetAuditLogByID(ctx context.Context, id uuid.UUID) (*v1models.AuditLog, error) {
	log, err := s.reader.GetAuditLogByID(ctx, id)
	if err != nil {
		// Map repository errors to domain errors
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return nil, err
	}
	return log, nil
}

// GetAuditLogsByTraceID retrieves audit logs by trace ID (convenience method)
func (s *AuditService) GetAuditLogsByTraceID(ctx context.Context, traceID string) ([]v1models.AuditLog, error) {
	return s.reader.GetAuditLogsByTraceID(ctx, traceID)
}

func (s *AuditService) verifyRequestSignature(req *v1models.CreateAuditLogRequest) error {
	if s.keys == nil {
		return fmt.Errorf("public key registry not initialized")
	}

	key, ok := s.keys.GetKey(req.PublicKeyID)
	if !ok {
		return fmt.Errorf("untrusted public key ID: %s", req.PublicKeyID)
	}

	// Reconstruct the package audit's Request DTO for canonicalization
	auditReq := &audit.AuditLogRequest{
		TraceID:            req.TraceID,
		Timestamp:          req.Timestamp,
		EventType:          req.EventType,
		Action:             req.Action,
		Status:             req.Status,
		ActorType:          req.ActorType,
		ActorID:            req.ActorID,
		TargetType:         req.TargetType,
		TargetID:           req.TargetID,
		Message:            req.Message,
		Metadata:           req.Metadata,
		Signature:          req.Signature,
		SignatureAlgorithm: req.SignatureAlgorithm,
		PublicKeyID:        req.PublicKeyID,
	}

	payload, err := audit.CanonicalizeRequest(auditReq)
	if err != nil {
		return fmt.Errorf("failed to canonicalize request: %w", err)
	}

	return audit.VerifyPayload(payload, req.Signature, req.SignatureAlgorithm, key)
}

// GetAuditSummary generates a summary report of audit logs for the current day
func (s *AuditService) GetAuditSummary(ctx context.Context) (*v1models.AuditSummaryResponse, error) {
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	items, err := s.reader.GetAuditSummary(ctx, startOfDay, endOfDay)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch summary: %w", err)
	}

	summary := &v1models.AuditSummaryResponse{
		Date:            now.Format("2006-01-02"),
		Summary:         fmt.Sprintf("Audit activity report for %s", now.Format("January 02, 2006")),
		RuntimeActivity: items,
	}

	return summary, nil
}
