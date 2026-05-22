package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1models "github.com/LSFLK/argus/internal/api/v1/models"
	v1services "github.com/LSFLK/argus/internal/api/v1/services"
	v1testutil "github.com/LSFLK/argus/internal/api/v1/testutil"
	"github.com/LSFLK/argus/internal/pipeline"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditHandler_CreateAuditLog(t *testing.T) {
	v1testutil.SetupTestEnums()

	mockRepo := v1testutil.NewMockRepository()
	mgr := pipeline.NewManager(nil, mockRepo)
	service := v1services.NewAuditService(mgr, mockRepo, nil)
	handler := NewAuditHandler(service)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
	}{
		{
			name: "Valid request",
			requestBody: map[string]interface{}{
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
				"status":     v1models.StatusSuccess,
				"actorType":  "SERVICE",
				"actorId":    "service-a",
				"targetType": "SERVICE",
				"targetId":   "service-b",
				"eventType":  "MANAGEMENT_EVENT",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Missing status",
			requestBody: map[string]interface{}{
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
				"actorType":  "SERVICE",
				"actorId":    "service-1",
				"targetType": "SERVICE",
				"targetId":   "service-2",
			},
			expectedStatus: http.StatusBadRequest, // Validation error from service layer
		},
		{
			name: "Missing actorId",
			requestBody: map[string]interface{}{
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
				"status":     v1models.StatusSuccess,
				"actorType":  "SERVICE",
				"targetType": "SERVICE",
				"targetId":   "service-2",
			},
			expectedStatus: http.StatusBadRequest, // Validation error from service layer
		},
		{
			name: "Invalid actor type",
			requestBody: map[string]interface{}{
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
				"status":     v1models.StatusSuccess,
				"actorType":  "INVALID",
				"actorId":    "actor-1",
				"targetType": "SERVICE",
				"targetId":   "service-1",
			},
			expectedStatus: http.StatusBadRequest, // Validation error from service layer
		},
		{
			name: "Invalid event type",
			requestBody: map[string]interface{}{
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
				"status":     v1models.StatusSuccess,
				"actorType":  "SERVICE",
				"actorId":    "service-1",
				"targetType": "SERVICE",
				"targetId":   "service-2",
				"eventType":  "INVALID_EVENT",
			},
			expectedStatus: http.StatusBadRequest, // Validation error from service layer
		},
		{
			name: "Missing timestamp",
			requestBody: map[string]interface{}{
				"status":     v1models.StatusSuccess,
				"actorType":  "SERVICE",
				"actorId":    "service-1",
				"targetType": "SERVICE",
				"targetId":   "service-2",
			},
			expectedStatus: http.StatusBadRequest, // Validation error - timestamp is required
		},
		{
			name: "Invalid timestamp format",
			requestBody: map[string]interface{}{
				"timestamp":  "invalid-timestamp",
				"status":     v1models.StatusSuccess,
				"actorType":  "SERVICE",
				"actorId":    "service-1",
				"targetType": "SERVICE",
				"targetId":   "service-2",
			},
			expectedStatus: http.StatusBadRequest, // Validation error - invalid timestamp format
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/audit-logs", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.CreateAuditLog(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusCreated {
				var response v1models.AuditLog
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)
				assert.NotEmpty(t, response.ID)
				assert.Equal(t, tt.requestBody["status"], response.Status)
			}
		})
	}
}

func TestAuditHandler_GetAuditLogs(t *testing.T) {
	mockRepo := v1testutil.NewMockRepository()
	mgr := pipeline.NewManager(nil, mockRepo)
	service := v1services.NewAuditService(mgr, mockRepo, nil)
	handler := NewAuditHandler(service)

	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		validateResp   func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:           "InvalidTraceID",
			queryParams:    "?traceId=invalid",
			expectedStatus: http.StatusBadRequest,
			validateResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var errorResp v1models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResp)
				assert.NoError(t, err)
				assert.Contains(t, errorResp.Error, "Invalid traceId format")
			},
		},
		{
			name:           "ValidTraceID",
			queryParams:    "?traceId=" + uuid.New().String(),
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response v1models.GetAuditLogsResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, int64(0), response.Total)
				assert.Empty(t, response.Logs)
			},
		},
		{
			name:           "NoTraceID",
			queryParams:    "",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response v1models.GetAuditLogsResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
			},
		},
		{
			name:           "WithEventType",
			queryParams:    "?eventType=MANAGEMENT_EVENT",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response v1models.GetAuditLogsResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
			},
		},
		{
			name:           "WithPagination",
			queryParams:    "?limit=10&offset=0",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response v1models.GetAuditLogsResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/audit-logs"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			handler.GetAuditLogs(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.validateResp != nil {
				tt.validateResp(t, w)
			}
		})
	}
}

func TestAuditHandler_GetAuditSummary(t *testing.T) {
	mockRepo := v1testutil.NewMockRepository()

	// Add a dummy log to the mock repository
	now := time.Now().UTC()
	targetID := "target-1"
	mockRepo.Write(context.Background(), &v1models.AuditLog{
		Timestamp:  now,
		ActorID:    "actor-1",
		ActorType:  "USER",
		TargetType: "RESOURCE",
		TargetID:   &targetID,
		Status:     v1models.StatusSuccess,
	})

	mgr := pipeline.NewManager(nil, mockRepo)
	service := v1services.NewAuditService(mgr, mockRepo, nil)
	handler := NewAuditHandler(service)

	t.Run("Valid request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/audit-summary", nil)
		w := httptest.NewRecorder()

		handler.GetAuditSummary(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response v1models.AuditSummaryResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotEmpty(t, response.Date)
		assert.NotEmpty(t, response.Summary)
		// Based on the mock data, there should be at least one item in RuntimeActivity
		assert.NotEmpty(t, response.RuntimeActivity)
		assert.Equal(t, "actor-1", response.RuntimeActivity[0].Actor)
		assert.Equal(t, "USER", response.RuntimeActivity[0].ActorType)
	})

	t.Run("Method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/audit-summary", nil)
		w := httptest.NewRecorder()

		handler.GetAuditSummary(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}
