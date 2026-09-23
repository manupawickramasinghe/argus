package sinks

import (
	"context"
	"testing"
	"time"

	"github.com/LSFLK/argus/internal/api/v1/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsoleSink_Name(t *testing.T) {
	sink := NewConsoleSink()
	assert.Equal(t, "ConsoleSink", sink.Name())
}

func TestConsoleSink_IsCritical(t *testing.T) {
	sink := NewConsoleSink()
	assert.False(t, sink.IsCritical())
}

func TestConsoleSink_Close(t *testing.T) {
	sink := NewConsoleSink()
	err := sink.Close()
	assert.NoError(t, err)
}

func TestConsoleSink_Write(t *testing.T) {
	sink := NewConsoleSink()
	ctx := context.Background()

	log := &models.AuditLog{
		Action:    "TEST_ACTION",
		ActorID:   "test-actor",
		Timestamp: time.Now().UTC(),
	}

	err := sink.Write(ctx, log)
	require.NoError(t, err)
}

func TestConsoleSink_WriteBatch(t *testing.T) {
	sink := NewConsoleSink()
	ctx := context.Background()

	logs := []models.AuditLog{
		{
			Action:    "TEST_ACTION_1",
			ActorID:   "test-actor-1",
			Timestamp: time.Now().UTC(),
		},
		{
			Action:    "TEST_ACTION_2",
			ActorID:   "test-actor-2",
			Timestamp: time.Now().UTC(),
		},
	}

	err := sink.WriteBatch(ctx, logs)
	require.NoError(t, err)
}
