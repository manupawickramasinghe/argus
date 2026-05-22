package audit

import (
	"context"
	"crypto"
	"sync"
	"testing"
)

// mockAuditor implements Auditor interface for testing
type mockAuditor struct {
	enabled bool
}

func (m *mockAuditor) LogEvent(ctx context.Context, event *AuditLogRequest) bool {
	return true
}

func (m *mockAuditor) SignEvent(ctx context.Context, event *AuditLogRequest) error {
	return nil
}

func (m *mockAuditor) LogSignedEvent(ctx context.Context, event *AuditLogRequest) {}

func (m *mockAuditor) VerifyIntegrity(event *AuditLogRequest, publicKey crypto.PublicKey) (bool, error) {
	return true, nil
}

func (m *mockAuditor) IsEnabled() bool {
	return m.enabled
}

func (m *mockAuditor) Close(ctx context.Context) error {
	return nil
}

func TestInitializeGlobalAudit(t *testing.T) {
	t.Run("Initialize with valid client", func(t *testing.T) {
		globalAuditOnce = sync.Once{}
		globalAuditMiddleware = nil
		defer func() {
			globalAuditOnce = sync.Once{}
			globalAuditMiddleware = nil
		}()

		client := &mockAuditor{enabled: true}
		InitializeGlobalAudit(client)

		if globalAuditMiddleware == nil {
			t.Fatalf("Expected global middleware to be initialized, got nil")
		}
		if globalAuditMiddleware.client != client {
			t.Errorf("Expected client to match, got %v", globalAuditMiddleware.client)
		}
	})

	t.Run("Initialize with nil client", func(t *testing.T) {
		globalAuditOnce = sync.Once{}
		globalAuditMiddleware = nil
		defer func() {
			globalAuditOnce = sync.Once{}
			globalAuditMiddleware = nil
		}()

		InitializeGlobalAudit(nil)

		if globalAuditMiddleware == nil {
			t.Fatalf("Expected global middleware to be initialized, got nil")
		}
		if globalAuditMiddleware.client != nil {
			t.Errorf("Expected nil client, got %v", globalAuditMiddleware.client)
		}
	})

	t.Run("Multiple calls (idempotency)", func(t *testing.T) {
		globalAuditOnce = sync.Once{}
		globalAuditMiddleware = nil
		defer func() {
			globalAuditOnce = sync.Once{}
			globalAuditMiddleware = nil
		}()

		client1 := &mockAuditor{enabled: true}
		client2 := &mockAuditor{enabled: false}

		// First call should set the client
		InitializeGlobalAudit(client1)

		// Second call should be ignored
		InitializeGlobalAudit(client2)

		if globalAuditMiddleware == nil {
			t.Fatalf("Expected global middleware to be initialized, got nil")
		}
		if globalAuditMiddleware.client != client1 {
			t.Errorf("Expected client to match first initialization, got %v", globalAuditMiddleware.client)
		}
	})

	t.Run("Concurrent initialization", func(t *testing.T) {
		globalAuditOnce = sync.Once{}
		globalAuditMiddleware = nil
		defer func() {
			globalAuditOnce = sync.Once{}
			globalAuditMiddleware = nil
		}()

		var wg sync.WaitGroup
		concurrency := 10

		client := &mockAuditor{enabled: true}

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				InitializeGlobalAudit(client)
			}()
		}

		wg.Wait()

		if globalAuditMiddleware == nil {
			t.Fatalf("Expected global middleware to be initialized, got nil")
		}
		if globalAuditMiddleware.client != client {
			t.Errorf("Expected client to match, got %v", globalAuditMiddleware.client)
		}
	})
}
