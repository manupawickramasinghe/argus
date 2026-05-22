package sinks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/LSFLK/argus/internal/api/v1/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PostgresSink implements the Sink interface using GORM.
// It supports PostgreSQL and SQLite (useful for local development).
// This sink maintains a partitioned hash chain for non-repudiation.
type PostgresSink struct {
	db *gorm.DB
}

// NewPostgresSink creates a new PostgresSink and ensures the schema is migrated.
func NewPostgresSink(db *gorm.DB) *PostgresSink {
	if err := db.AutoMigrate(&models.AuditLog{}); err != nil {
		slog.Warn("Failed to auto-migrate audit_logs table", "error", err)
	}
	return &PostgresSink{db: db}
}

func (s *PostgresSink) Name() string {
	return "PostgresSink"
}

// Write persists an audit log to the database with partitioned hash chaining.
// Chains are partitioned by ActorID to prevent global lock contention.
func (s *PostgresSink) Write(ctx context.Context, log *models.AuditLog) error {
	// Integrity check
	if (log.Signature != "" || log.PublicKeyID != "") && len(log.Message) == 0 {
		return fmt.Errorf("invalid audit log: signature present but message is empty")
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var lastLog models.AuditLog
		// Fetch the most recent log for THIS ACTOR to continue the partitioned hash chain.
		// Uses SELECT ... FOR UPDATE to prevent race conditions during concurrent ingestion.
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("actor_id = ?", log.ActorID).
			Order("created_at DESC, id DESC").
			First(&lastLog).Error; err != nil && err != gorm.ErrRecordNotFound {
			return err
		}

		var err error
		log.PreviousHash = lastLog.CurrentHash
		log.CurrentHash, err = s.computeHash(log)
		if err != nil {
			return fmt.Errorf("failed to compute hash: %w", err)
		}

		if err := tx.Create(log).Error; err != nil {
			return err
		}
		return nil
	})
}

// WriteBatch persists multiple audit logs to the database using bulk inserts.
// Note: Batching across different actors in a single transaction is supported,
// but each actor's chain is updated sequentially within the transaction.
func (s *PostgresSink) WriteBatch(ctx context.Context, logs []models.AuditLog) error {
	if len(logs) == 0 {
		return nil
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Group logs by ActorID to handle partitioned chains efficiently
		actorLastHashes := make(map[string]string)

		// 1. Extract unique ActorIDs from the batch to prevent lock interleaving
		var actorIDs []string
		actorMap := make(map[string]bool)
		for i := range logs {
			aID := logs[i].ActorID
			if !actorMap[aID] {
				actorMap[aID] = true
				actorIDs = append(actorIDs, aID)
			}
		}

		// 2. Sort them alphabetically. This guarantees a deterministic lock acquisition
		// order across all concurrent transactions, completely preventing database deadlocks.
		sort.Strings(actorIDs)

		// 3. Acquire row-level locks sequentially in sorted order
		// Using a single query to prevent N+1 query performance issues while maintaining deterministic lock order
		var lastLogs []models.AuditLog
		// Explicitly add FOR UPDATE because GORM's Clauses(clause.Locking{}) is ignored with Raw queries.
		// We can conditionally append FOR UPDATE if we are not on sqlite.
		query := `
			SELECT * FROM audit_logs
			WHERE id IN (
				SELECT id FROM (
					SELECT id, ROW_NUMBER() OVER(PARTITION BY actor_id ORDER BY created_at DESC, id DESC) as rn
					FROM audit_logs
					WHERE actor_id IN ?
				) t WHERE rn = 1
			)
			ORDER BY actor_id
		`
		if tx.Dialector.Name() != "sqlite" {
			query += " FOR UPDATE"
		}

		if err := tx.Raw(query, actorIDs).Scan(&lastLogs).Error; err != nil {
			return err
		}
		for i := range lastLogs {
			actorLastHashes[lastLogs[i].ActorID] = lastLogs[i].CurrentHash
		}

		// 4. Compute hash chain updates using pre-locked hashes
		for i := range logs {
			actorID := logs[i].ActorID
			logs[i].PreviousHash = actorLastHashes[actorID]
			currHash, err := s.computeHash(&logs[i])
			if err != nil {
				return fmt.Errorf("failed to compute batch hash at index %d: %w", i, err)
			}
			logs[i].CurrentHash = currHash
			actorLastHashes[actorID] = currHash
		}

		// Use GORM's bulk insert feature
		return tx.CreateInBatches(logs, 100).Error
	})
}

// Close is a no-op for the GORM sink as the connection pool is managed externally.
func (s *PostgresSink) Close() error {
	return nil
}

// IsCritical returns true for PostgresSink.
func (s *PostgresSink) IsCritical() bool {
	return true
}

func (s *PostgresSink) computeHash(log *models.AuditLog) (string, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(log.PreviousHash)); err != nil {
		return "", err
	}

	payload := struct {
		ID                 uuid.UUID
		TraceID            *uuid.UUID
		Timestamp          int64
		EventType          string
		Action             string
		Status             string
		ActorType          string
		ActorID            string
		TargetType         string
		TargetID           *string
		Message            models.JSONBRawMessage
		Metadata           models.JSONBRawMessage
		Signature          string
		SignatureAlgorithm string
		PublicKeyID        string
	}{
		ID:                 log.ID,
		TraceID:            log.TraceID,
		Timestamp:          log.Timestamp.Truncate(time.Microsecond).UnixMicro(),
		EventType:          log.EventType,
		Action:             log.Action,
		Status:             log.Status,
		ActorType:          log.ActorType,
		ActorID:            log.ActorID,
		TargetType:         log.TargetType,
		TargetID:           log.TargetID,
		Message:            log.Message,
		Metadata:           log.Metadata,
		Signature:          log.Signature,
		SignatureAlgorithm: log.SignatureAlgorithm,
		PublicKeyID:        log.PublicKeyID,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	if _, err := h.Write(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
