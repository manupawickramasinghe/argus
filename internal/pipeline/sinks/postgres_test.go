package sinks

import (
	"context"
	"testing"
	"time"

	"github.com/LSFLK/argus/internal/api/v1/database"
	"github.com/LSFLK/argus/internal/api/v1/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNewPostgresSink(t *testing.T) {
	// Setup in-memory SQLite for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	sink := NewPostgresSink(db)

	assert.NotNil(t, sink, "Sink should not be nil")
	assert.Equal(t, db, sink.db, "Sink should use the provided DB instance")
}

func TestPostgresSink_PartitionedHashChaining(t *testing.T) {
	// Setup in-memory SQLite for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	sink := NewPostgresSink(db)
	ctx := context.Background()

	// 1. Actor A - First log
	logA1 := &models.AuditLog{
		Action:    "CREATE",
		ActorID:   "actor-A",
		Timestamp: time.Now().UTC(),
	}
	err = sink.Write(ctx, logA1)
	require.NoError(t, err)
	assert.Empty(t, logA1.PreviousHash, "First log for Actor A should have no previous hash")

	// 2. Actor B - First log (should be independent of Actor A)
	logB1 := &models.AuditLog{
		Action:    "CREATE",
		ActorID:   "actor-B",
		Timestamp: time.Now().UTC(),
	}
	err = sink.Write(ctx, logB1)
	require.NoError(t, err)
	assert.Empty(t, logB1.PreviousHash, "First log for Actor B should have no previous hash")

	// 3. Actor A - Second log (should link to A1)
	logA2 := &models.AuditLog{
		Action:    "UPDATE",
		ActorID:   "actor-A",
		Timestamp: time.Now().UTC(),
	}
	err = sink.Write(ctx, logA2)
	require.NoError(t, err)
	assert.Equal(t, logA1.CurrentHash, logA2.PreviousHash, "Second log for Actor A should link to its predecessor")

	// 4. Actor B - Second log (should link to B1)
	logB2 := &models.AuditLog{
		Action:    "UPDATE",
		ActorID:   "actor-B",
		Timestamp: time.Now().UTC(),
	}
	err = sink.Write(ctx, logB2)
	require.NoError(t, err)
	assert.Equal(t, logB1.CurrentHash, logB2.PreviousHash, "Second log for Actor B should link to its predecessor")
	assert.NotEqual(t, logA2.CurrentHash, logB2.CurrentHash, "Parallel chains should have different hashes")
}

func TestPostgresSink_ReadSeparation(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	sink := NewPostgresSink(db)
	reader := database.NewGormReader(db)
	ctx := context.Background()

	log := &models.AuditLog{
		Action:    "READ_TEST",
		ActorID:   "tester",
		Timestamp: time.Now().UTC(),
	}
	_ = sink.Write(ctx, log)

	// Test GormReader independently
	found, err := reader.GetAuditLogByID(ctx, log.ID)
	require.NoError(t, err)
	assert.Equal(t, log.Action, found.Action)

	// Verify Sink no longer has read methods (compile-time check via interface)
	// var _ database.AuditReader = sink // This would fail to compile now
}
