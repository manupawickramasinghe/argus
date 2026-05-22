package services

import (
	"context"
	"errors"
	"testing"
	"time"

	v1models "github.com/LSFLK/argus/internal/api/v1/models"
	v1testutil "github.com/LSFLK/argus/internal/api/v1/testutil"
	"github.com/LSFLK/argus/internal/pipeline"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditService_CreateAuditLog(t *testing.T) {
	v1testutil.SetupTestEnums()
	mockRepo := v1testutil.NewMockRepository()
	mgr := pipeline.NewManager(nil, mockRepo)
	service := NewAuditService(mgr, mockRepo, nil)

	tests := []struct {
		name    string
		req     *v1models.CreateAuditLogRequest
		wantErr bool
	}{
		{
			name: "Valid request with SERVICE actor",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     v1models.StatusSuccess,
				ActorType:  "SERVICE",
				ActorID:    "service-a",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-b"),
				EventType:  "MANAGEMENT_EVENT",
			},
			wantErr: false,
		},
		{
			name: "Valid request with ADMIN actor",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     v1models.StatusSuccess,
				ActorType:  "ADMIN",
				ActorID:    "admin@example.com",
				TargetType: "RESOURCE",
				TargetID:   v1testutil.StringPtr("user-123"),
				Action:     "CREATE",
			},
			wantErr: false,
		},
		{
			name: "Valid request with trace ID",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     v1models.StatusSuccess,
				ActorType:  "SERVICE",
				ActorID:    "service-1",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-2"),
				TraceID:    v1testutil.StringPtr(uuid.New().String()),
			},
			wantErr: false,
		},
		{
			name: "Invalid actor type",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     v1models.StatusSuccess,
				ActorType:  "INVALID",
				ActorID:    "actor-1",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-1"),
			},
			wantErr: true,
		},
		{
			name: "Missing actor ID",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     v1models.StatusSuccess,
				ActorType:  "SERVICE",
				ActorID:    "",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-1"),
			},
			wantErr: true,
		},
		{
			name: "Invalid event type",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     v1models.StatusSuccess,
				ActorType:  "SERVICE",
				ActorID:    "service-1",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-2"),
				EventType:  "INVALID_EVENT",
			},
			wantErr: true,
		},
		{
			name: "Missing timestamp",
			req: &v1models.CreateAuditLogRequest{
				Status:     v1models.StatusSuccess,
				ActorType:  "SERVICE",
				ActorID:    "service-1",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-1"),
			},
			wantErr: true,
		},
		{
			name: "Invalid timestamp format",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  "invalid-timestamp",
				Status:     v1models.StatusSuccess,
				ActorType:  "SERVICE",
				ActorID:    "service-1",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-1"),
			},
			wantErr: true,
		},
		{
			name: "Invalid target type",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     v1models.StatusSuccess,
				ActorType:  "SERVICE",
				ActorID:    "service-1",
				TargetType: "INVALID",
				TargetID:   v1testutil.StringPtr("service-1"),
			},
			wantErr: true,
		},
		{
			name: "Invalid event action",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     v1models.StatusSuccess,
				ActorType:  "SERVICE",
				ActorID:    "service-1",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-1"),
				Action:     "INVALID_ACTION",
			},
			wantErr: true,
		},
		{
			name: "Invalid status",
			req: &v1models.CreateAuditLogRequest{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Status:     "INVALID_STATUS",
				ActorType:  "SERVICE",
				ActorID:    "service-1",
				TargetType: "SERVICE",
				TargetID:   v1testutil.StringPtr("service-1"),
			},
			wantErr: true,
		},
		{
			name: "Missing required fields - targetType",
			req: &v1models.CreateAuditLogRequest{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Status:    v1models.StatusSuccess,
				ActorType: "SERVICE",
				ActorID:   "service-1",
				// Missing TargetType
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := service.CreateAuditLog(context.Background(), tt.req)
			if tt.wantErr {
				assert.Error(t, err, "Expected validation error")
				assert.Nil(t, log)
			} else {
				assert.NoError(t, err, "Expected no validation error")
				assert.NotNil(t, log)
				assert.NotEmpty(t, log.ID)
				assert.Equal(t, tt.req.Status, log.Status)
				assert.Equal(t, tt.req.ActorType, log.ActorType)
				assert.Equal(t, tt.req.ActorID, log.ActorID)
			}
		})
	}
}

func TestAuditService_GetAuditLogs(t *testing.T) {
	mockRepo := v1testutil.NewMockRepository()
	mgr := pipeline.NewManager(nil, mockRepo)
	service := NewAuditService(mgr, mockRepo, nil)

	tests := []struct {
		name      string
		traceID   *string
		eventType *string
		limit     int
		offset    int
		wantErr   bool
	}{
		{
			name:    "Get all logs",
			traceID: nil,
			limit:   10,
			offset:  0,
			wantErr: false,
		},
		{
			name:    "Get logs by trace ID",
			traceID: v1testutil.StringPtr(uuid.New().String()),
			limit:   10,
			offset:  0,
			wantErr: false,
		},
		{
			name:      "Get logs by event type",
			eventType: v1testutil.StringPtr("MANAGEMENT_EVENT"),
			limit:     10,
			offset:    0,
			wantErr:   false,
		},
		{
			name:    "Pagination",
			limit:   5,
			offset:  10,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs, total, err := service.GetAuditLogs(context.Background(), tt.traceID, tt.eventType, tt.limit, tt.offset, false)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logs)
				assert.GreaterOrEqual(t, total, int64(0))
			}
		})
	}
}

func TestAuditService_GetAuditLogByID(t *testing.T) {
	mockRepo := v1testutil.NewMockRepository()
	mgr := pipeline.NewManager(nil, mockRepo)
	service := NewAuditService(mgr, mockRepo, nil)
	ctx := context.Background()

	// Create a test log
	log := &v1models.AuditLog{
		ID:         uuid.New(),
		Timestamp:  time.Now(),
		Status:     v1models.StatusSuccess,
		ActorType:  "SERVICE",
		ActorID:    "test-service",
		TargetType: "SERVICE",
	}
	_, _ = mockRepo.CreateAuditLog(ctx, log)

	t.Run("RecordFound", func(t *testing.T) {
		result, err := service.GetAuditLogByID(ctx, log.ID)
		assert.NoError(t, err)
		assert.Equal(t, log.ID, result.ID)
	})

	t.Run("RecordNotFound", func(t *testing.T) {
		_, err := service.GetAuditLogByID(ctx, uuid.New())
		assert.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})
}

func TestAuditService_GetAuditLogsByTraceID(t *testing.T) {
	mockRepo := v1testutil.NewMockRepository()
	mgr := pipeline.NewManager(nil, mockRepo)
	service := NewAuditService(mgr, mockRepo, nil)

	traceID := uuid.New().String()

	logs, err := service.GetAuditLogsByTraceID(context.Background(), traceID)
	require.NoError(t, err)
	assert.NotNil(t, logs)
}

func TestAuditService_CreateAuditLog_InvalidTraceID(t *testing.T) {
	v1testutil.SetupTestEnums()
	mockRepo := v1testutil.NewMockRepository()
	mgr := pipeline.NewManager(nil, mockRepo)
	service := NewAuditService(mgr, mockRepo, nil)

	req := &v1models.CreateAuditLogRequest{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Status:     v1models.StatusSuccess,
		ActorType:  "SERVICE",
		ActorID:    "service-1",
		TargetType: "SERVICE",
		TargetID:   v1testutil.StringPtr("service-2"),
		TraceID:    v1testutil.StringPtr("invalid-uuid"),
	}

	_, err := service.CreateAuditLog(context.Background(), req)
	assert.Error(t, err)
	assert.True(t, IsValidationError(err))
}

func TestAuditService_GetAuditSummary(t *testing.T) {
	mockRepo := v1testutil.NewMockRepository()
	mgr := pipeline.NewManager(nil, mockRepo)
	service := NewAuditService(mgr, mockRepo, nil)
	ctx := context.Background()

	// Insert some test logs for the current day
	now := time.Now().UTC()
	logs := []*v1models.AuditLog{
		{
			ID:        uuid.New(),
			Timestamp: now,
			ActorID:   "actor-1",
			ActorType: "SERVICE",
			Action:    "CREATE",
			EventType: "RESOURCE_EVENT",
			Status:    v1models.StatusSuccess,
		},
		{
			ID:        uuid.New(),
			Timestamp: now,
			ActorID:   "actor-2",
			ActorType: "USER",
			Action:    "DELETE",
			EventType: "RESOURCE_EVENT",
			Status:    v1models.StatusFailure,
		},
	}

	for _, log := range logs {
		_ = mockRepo.Write(ctx, log)
	}

	t.Run("Success", func(t *testing.T) {
		summary, err := service.GetAuditSummary(ctx)
		require.NoError(t, err)
		assert.NotNil(t, summary)
		assert.Equal(t, now.Format("2006-01-02"), summary.Date)
		assert.Contains(t, summary.Summary, now.Format("January 02, 2006"))

		// 2 logs created today
		assert.Len(t, summary.RuntimeActivity, 2)

		// Logs order might be sorted by timestamp depending on the mock,
		// but let's just check the properties are correctly populated
		foundActor1 := false
		for _, item := range summary.RuntimeActivity {
			if item.Actor == "actor-1" {
				foundActor1 = true
				assert.Equal(t, "SERVICE", item.ActorType)
				assert.Equal(t, "CREATE", item.Action)
				assert.Equal(t, "RESOURCE_EVENT", item.EventType)
				assert.Equal(t, v1models.StatusSuccess, item.Status)
			}
		}
		assert.True(t, foundActor1, "Expected to find actor-1 in the summary")
	})

	t.Run("Failure_GetAuditLogsError", func(t *testing.T) {
		mockRepo.InjectError = errors.New("database connection failed")
		defer func() { mockRepo.InjectError = nil }()

		summary, err := service.GetAuditSummary(ctx)
		require.Error(t, err)
		assert.Nil(t, summary)
		assert.Contains(t, err.Error(), "failed to fetch logs for summary")
		assert.Contains(t, err.Error(), "database connection failed")
	})
}
