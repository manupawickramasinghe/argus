package audit

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// AuditLogsEndpoint is the API endpoint for creating audit logs
	AuditLogsEndpoint = "/api/audit-logs"
	// DefaultHTTPTimeout is the default timeout for HTTP requests to the audit service
	DefaultHTTPTimeout = 10 * time.Second
	// MaxRetries is the maximum number of retries for sending a batch
	MaxRetries = 3
	// InitialBackoff is the initial backoff duration for retries
	InitialBackoff = 500 * time.Millisecond
)

// Config defines the configuration for the Audit Client
type Config struct {
	BaseURL            string
	Signer             SignPayloadFunc
	PublicKeyID        string
	SignatureAlgorithm string        // e.g. "RS256", "EdDSA"
	WorkerCount        int           // Number of background workers, defaults to 5
	QueueSize          int           // Size of the internal channel, defaults to 100
	BatchSize          int           // Number of logs to send in one batch, defaults to 20
	BatchInterval      time.Duration // Max time to wait before sending a batch, defaults to 1s
	HTTPTimeout        time.Duration // Defaults to 10s
	AuthToken          string        // Bearer token for authentication
	SpoolDir           string        // Directory for spooling failed batches (empty = disabled)
}

// Client is a client for sending audit events to the audit service
type Client struct {
	baseURL            string
	httpClient         *http.Client
	enabled            bool
	signer             SignPayloadFunc
	publicKeyID        string
	signatureAlgorithm string
	queue              chan *AuditLogRequest
	quit               chan struct{}
	wg                 sync.WaitGroup
	batchSize          int
	batchInterval      time.Duration
	authToken          string
	spoolDir           string

	// closed is an atomic flag to prevent sending on a closed queue.
	// In Go, sending on a closed channel panics. Instead of closing the channel,
	// we use this flag to reject new events gracefully during shutdown.
	closed atomic.Bool

	// shutdownCtx carries the context of Close() during shutdown to background workers
	shutdownCtx context.Context
}

// NewClient creates a new audit client using the provided configuration.
// Audit can be disabled by:
//   - Setting ENABLE_AUDIT=false environment variable
//   - Providing an empty baseURL in config
//
// When disabled, all LogEvent calls will be no-ops.
func NewClient(cfg Config) *Client {
	enabled := isAuditEnabled(cfg.BaseURL)

	if !enabled {
		slog.Info("Audit client disabled",
			"reason", "ENABLE_AUDIT=false or audit service URL not configured",
			"impact", "Services will continue running but audit events will not be logged")
		return &Client{
			enabled: false,
		}
	}

	// Algorithm Hardening: Validate SignatureAlgorithm if a signer is provided
	if cfg.Signer != nil {
		switch cfg.SignatureAlgorithm {
		case "RS256", "EdDSA":
			// Valid
		default:
			slog.Error("Unsupported signature algorithm", "algorithm", cfg.SignatureAlgorithm)
			return &Client{
				enabled: false,
			}
		}
	}

	workerCount := cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = 5
	}

	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = 100
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 20
	}

	batchInterval := cfg.BatchInterval
	if batchInterval <= 0 {
		batchInterval = 1 * time.Second
	}

	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}

	// Initialize spool directory if configured
	if cfg.SpoolDir != "" {
		if err := os.MkdirAll(cfg.SpoolDir, 0o750); err != nil {
			slog.Error("Failed to create spool directory, spooling disabled", "dir", cfg.SpoolDir, "error", err)
			cfg.SpoolDir = ""
		}
	}

	c := &Client{
		baseURL: cfg.BaseURL,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
			},
		},
		enabled:            true,
		signer:             cfg.Signer,
		publicKeyID:        cfg.PublicKeyID,
		signatureAlgorithm: cfg.SignatureAlgorithm,
		queue:              make(chan *AuditLogRequest, queueSize),
		quit:               make(chan struct{}),
		batchSize:          batchSize,
		batchInterval:      batchInterval,
		authToken:          cfg.AuthToken,
		spoolDir:           cfg.SpoolDir,
	}

	// Start background workers
	for i := 0; i < workerCount; i++ {
		c.wg.Add(1)
		go c.worker()
	}

	slog.Info("Audit client initialized with async workers and batching",
		"baseURL", cfg.BaseURL,
		"workers", workerCount,
		"batchSize", batchSize,
		"batchInterval", batchInterval,
		"queueSize", queueSize,
		"spoolDir", cfg.SpoolDir)

	return c
}

// IsEnabled returns whether the audit client is enabled
func (c *Client) IsEnabled() bool {
	return c.enabled
}

// LogEvent sends an audit event to the audit service asynchronously via worker queue.
// Returns false if the client is shutting down or the queue is full.
func (c *Client) LogEvent(ctx context.Context, event *AuditLogRequest) bool {
	// Skip if audit client is not enabled
	if !c.enabled {
		return false
	}

	// CRITICAL: Check the shutdown flag BEFORE sending on the channel.
	// In Go, sending on a closed channel panics. We never close c.queue;
	// instead we use this atomic flag to reject new events gracefully.
	if c.closed.Load() {
		slog.Warn("Audit client is shutting down, rejecting event", "action", event.Action)
		return false
	}

	// Push to queue with backpressure — block up to the request context deadline
	// rather than silently dropping the event.
	select {
	case c.queue <- event:
		return true
	case <-ctx.Done():
		slog.Warn("Audit queue full and context expired, dropping event", "action", event.Action)
		return false
	}
}

// LogSignedEvent logs an audit event that has already been signed.
// This is an alias for LogEvent intended for semantically clearer logging of signed events.
func (c *Client) LogSignedEvent(ctx context.Context, event *AuditLogRequest) {
	c.LogEvent(ctx, event)
}

// SignEvent generates a cryptographic signature for the given request
// using the registered SignPayloadFunc.
func (c *Client) SignEvent(ctx context.Context, event *AuditLogRequest) error {
	if c.signer == nil {
		return fmt.Errorf("no signer registered with the client")
	}

	payload, err := CanonicalizeRequest(event)
	if err != nil {
		return fmt.Errorf("failed to canonicalize event: %w", err)
	}

	// Propagate the provided context to the signer function (such as KMS/HSM integration)
	// to prevent infinite hangs or leaks.
	sigBase64, err := c.signer(ctx, payload)
	if err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}

	event.Signature = sigBase64
	event.SignatureAlgorithm = c.signatureAlgorithm
	event.PublicKeyID = c.publicKeyID

	return nil
}

// Close gracefully shuts down the client, flushing the queue.
// It signals workers to stop accepting new work, drains remaining events,
// and waits for all workers to finish (or for ctx to expire).
func (c *Client) Close(ctx context.Context) error {
	if !c.enabled {
		return nil
	}

	// Mark as closed first so no new events are accepted.
	// This MUST happen before signaling quit to prevent the panic anti-pattern.
	c.closed.Store(true)

	// Propagate the shutdown context to background workers safely before closing c.quit
	c.shutdownCtx = ctx

	// Signal workers to begin draining and shutting down.
	// We do NOT close c.queue — the garbage collector will reclaim it.
	// Closing a channel with concurrent senders causes a panic in Go.
	close(c.quit)

	// Wait for workers to finish, but honor context timeout if provided
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// VerifyIntegrity verifies the signature of a log request.
// It uses the public key provided by the caller to verify the signature.
func (c *Client) VerifyIntegrity(event *AuditLogRequest, publicKey crypto.PublicKey) (bool, error) {
	if event.Signature == "" {
		return false, fmt.Errorf("event has no signature")
	}

	payload, err := CanonicalizeRequest(event)
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize event: %w", err)
	}

	err = VerifyPayload(payload, event.Signature, event.SignatureAlgorithm, publicKey)
	if err != nil {
		return false, fmt.Errorf("verification failed: %w", err)
	}

	return true, nil
}

func (c *Client) worker() {
	defer c.wg.Done()

	buffer := make([]*AuditLogRequest, 0, c.batchSize)
	ticker := time.NewTicker(c.batchInterval)
	defer ticker.Stop()

	flush := func(fCtx context.Context) {
		if len(buffer) == 0 {
			return
		}

		c.logBatch(fCtx, buffer)
		buffer = make([]*AuditLogRequest, 0, c.batchSize)
	}

	for {
		select {
		case event := <-c.queue:
			if event == nil {
				// Channel was drained or nil received; skip
				continue
			}

			// Automatic signing if required
			if event.ShouldSign {
				var signErr error
				for attempt := 1; attempt <= 3; attempt++ {
					// Create a timeout context for signing to avoid unbounded KMS/HSM hangs
					signCtx, signCancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)
					signErr = c.SignEvent(signCtx, event)
					signCancel()
					if signErr == nil {
						break
					}
					slog.Warn("Failed to sign event in worker, retrying",
						"attempt", attempt,
						"maxAttempts", 3,
						"error", signErr)
					time.Sleep(100 * time.Millisecond)
				}

				if signErr != nil {
					slog.Error("Failed to sign event in worker after retries, dropping event", "error", signErr)
					continue
				}
			}

			buffer = append(buffer, event)
			if len(buffer) >= c.batchSize {
				flush(context.Background())
			}
		case <-ticker.C:
			flush(context.Background())
		case <-c.quit:
			// Retrieve the shutdown context passed during Close()
			shutdownCtx := c.shutdownCtx
			if shutdownCtx == nil {
				shutdownCtx = context.Background()
			}

			// Drain remaining events from the queue before exiting
			for {
				select {
				case event := <-c.queue:
					if event == nil {
						continue
					}
					buffer = append(buffer, event)
				default:
					// Queue is empty
					flush(shutdownCtx)
					return
				}
			}
		}
	}
}

// logBatch sends a batch of audit events to the audit service API.
// On final failure after all retries, it spools the batch to disk if SpoolDir is configured.
func (c *Client) logBatch(parentCtx context.Context, events []*AuditLogRequest) {
	if c.httpClient == nil || len(events) == 0 {
		return
	}

	// For now, we'll use a new bulk endpoint if it exists, or just loop if not.
	// But the requirement says "send to the server in bulk rather than via individual HTTP requests".
	// So I should implement the bulk endpoint on the server.
	payloadBytes, err := json.Marshal(events)
	if err != nil {
		slog.Error("Failed to marshal audit batch", "error", err)
		return
	}

	var lastErr error
	backoff := InitialBackoff

	targetURL := c.baseURL + "/api/audit-logs/bulk"
	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			slog.Info("Retrying audit batch send", "attempt", attempt, "backoff", backoff)
			select {
			case <-time.After(backoff):
				backoff *= 2 // Exponential backoff
			case <-parentCtx.Done():
				slog.Error("Parent context cancelled during retry wait", "error", parentCtx.Err())
				c.spoolToDisk(payloadBytes)
				return
			}
		}

		// Create a timeout context for this specific attempt to avoid timeout context exhaustion
		attemptCtx, attemptCancel := context.WithTimeout(parentCtx, c.httpClient.Timeout)

		req, err := http.NewRequestWithContext(attemptCtx, "POST", targetURL, strings.NewReader(string(payloadBytes)))
		if err != nil {
			attemptCancel()
			slog.Error("Failed to create audit request", "error", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		if c.authToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.authToken)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			attemptCancel()
			lastErr = err
			slog.Warn("Failed to send audit batch", "error", err, "attempt", attempt)
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		attemptCancel()

		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMultiStatus {
			lastErr = fmt.Errorf("server returned %d: %s", resp.StatusCode, string(bodyBytes))
			slog.Warn("Audit service returned error for batch", "status", resp.StatusCode, "body", string(bodyBytes), "attempt", attempt)
			continue
		}

		slog.Info("Audit batch logged successfully", "count", len(events), "status", resp.StatusCode)
		return
	}

	slog.Error("Audit batch failed after maximum retries", "error", lastErr, "count", len(events))
	c.spoolToDisk(payloadBytes)
}

// spoolToDisk writes a failed batch payload to the spool directory as a fallback
// to prevent permanent data loss when the audit service is unreachable.
// A background cron or operator can retry these files later.
func (c *Client) spoolToDisk(payload []byte) {
	if c.spoolDir == "" {
		slog.Error("Audit batch permanently lost: spool directory not configured. Set Config.SpoolDir to prevent data loss.")
		return
	}

	// Generate a cryptographically secure random suffix to prevent file overwrite race conditions under high throughput
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		slog.Error("CRITICAL: Failed to generate cryptographically secure random suffix for spool file", "error", err)
		return
	}
	filename := fmt.Sprintf("argus-spool-%d-%s.json", time.Now().UnixNano(), hex.EncodeToString(randomBytes))
	path := filepath.Join(c.spoolDir, filename)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		slog.Error("CRITICAL: Failed to create spool file — DATA LOSS", "error", err, "path", path)
		return
	}
	defer f.Close()

	if _, err := f.Write(payload); err != nil {
		slog.Error("CRITICAL: Failed to write audit batch to disk — DATA LOSS",
			"error", err, "path", path, "bytes", len(payload))
		return
	}

	slog.Warn("Audit batch spooled to disk for later retry",
		"path", path, "bytes", len(payload))
}

// isAuditEnabled checks if audit logging is enabled via environment variable
// Audit is enabled by default unless explicitly disabled via ENABLE_AUDIT=false
// or if baseURL is empty
func isAuditEnabled(baseURL string) bool {
	// If URL is explicitly empty, audit is disabled
	if baseURL == "" {
		return false
	}

	// Check ENABLE_AUDIT environment variable (default: true)
	enableAudit := os.Getenv("ENABLE_AUDIT")
	if enableAudit == "" {
		// Default to enabled if URL is provided
		return true
	}

	// Parse boolean value (case-insensitive)
	enableAuditLower := strings.ToLower(strings.TrimSpace(enableAudit))
	return enableAuditLower == "true" || enableAuditLower == "1" || enableAuditLower == "yes"
}
