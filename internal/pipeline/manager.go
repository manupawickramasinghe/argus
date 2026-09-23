package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/LSFLK/argus/internal/api/v1/models"
	"github.com/LSFLK/argus/internal/pipeline/sinks"
)

const (
	DefaultAsyncQueueSize = 1000
	DefaultWorkerCount    = 5
)

// Config defines the configuration for the Pipeline Manager.
type Config struct {
	AsyncQueueSize int
	WorkerCount    int
}

// Manager coordinates the fan-out of audit logs to multiple registered sinks.
// It supports both synchronous and asynchronous dispatching.
type Manager struct {
	sinks      []sinks.Sink
	asyncQueue chan asyncTask
	wg         sync.WaitGroup
	closed     bool
	mu         sync.RWMutex
}

type asyncTask struct {
	ctx  context.Context
	log  *models.AuditLog
	logs []models.AuditLog
}

// SinkError wraps an error encountered by a specific sink to enable type-safe checking.
type SinkError struct {
	SinkName string
	Err      error
}

func (e *SinkError) Error() string {
	return fmt.Sprintf("sink %s failed: %v", e.SinkName, e.Err)
}

func (e *SinkError) Unwrap() error {
	return e.Err
}

// NewManager creates a new pipeline manager and starts background workers for async dispatch.
func NewManager(cfg *Config, sinks ...sinks.Sink) *Manager {
	if cfg == nil {
		cfg = &Config{
			AsyncQueueSize: DefaultAsyncQueueSize,
			WorkerCount:    DefaultWorkerCount,
		}
	}
	if cfg.AsyncQueueSize <= 0 {
		cfg.AsyncQueueSize = DefaultAsyncQueueSize
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = DefaultWorkerCount
	}

	m := &Manager{
		sinks:      sinks,
		asyncQueue: make(chan asyncTask, cfg.AsyncQueueSize),
	}

	// Start a pool of background workers for fire-and-forget sinks
	for i := 0; i < cfg.WorkerCount; i++ {
		m.wg.Add(1)
		go m.worker()
	}

	return m
}

func (m *Manager) worker() {
	defer m.wg.Done()
	for task := range m.asyncQueue {
		if task.log != nil {
			_ = m.Dispatch(task.ctx, task.log)
		} else if task.logs != nil {
			_ = m.DispatchBatch(task.ctx, task.logs)
		}
	}
}

// Dispatch fans out an audit log to all registered sinks concurrently.
// It returns a slice of errors encountered during the dispatch process.
// If one sink fails, it does not prevent others from attempting to write.
//
// IMPORTANT (Goroutine Leak Risk): If ctx times out, the wg.Wait() goroutine
// will persist until ALL sink goroutines return. This is safe ONLY if every
// registered Sink implementation respects ctx.Done() and returns promptly.
// If you add a new Sink that does not natively support context cancellation
// (e.g., an S3Sink using a non-context-aware SDK), you MUST wrap it with
// a context-aware adapter to prevent goroutine accumulation.
func (m *Manager) Dispatch(ctx context.Context, log *models.AuditLog) []error {
	// Implement an internal watchdog to prevent goroutine accumulation
	// if the parent context doesn't have a deadline and a sink hangs.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	var (
		wg    sync.WaitGroup
		errs  []error
		errMu sync.Mutex
	)

	wg.Add(len(m.sinks))
	for _, sink := range m.sinks {
		go func(s sinks.Sink) {
			defer wg.Done()
			if err := s.Write(ctx, log); err != nil {
				errMu.Lock()
				errs = append(errs, &SinkError{SinkName: s.Name(), Err: err})
				errMu.Unlock()
			}
		}(sink)
	}

	// Use a channel to wait for all sinks to finish or for the context to time out.
	// This prevents goroutine leaks if a sink hangs indefinitely.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return errs
	case <-ctx.Done():
		return append(errs, ctx.Err())
	}
}

// DispatchBatch fans out a batch of audit logs to all registered sinks concurrently.
func (m *Manager) DispatchBatch(ctx context.Context, logs []models.AuditLog) []error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	var (
		wg    sync.WaitGroup
		errs  []error
		errMu sync.Mutex
	)

	wg.Add(len(m.sinks))
	for _, sink := range m.sinks {
		go func(s sinks.Sink) {
			defer wg.Done()
			if err := s.WriteBatch(ctx, logs); err != nil {
				errMu.Lock()
				errs = append(errs, &SinkError{SinkName: s.Name(), Err: err})
				errMu.Unlock()
			}
		}(sink)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return errs
	case <-ctx.Done():
		return append(errs, ctx.Err())
	}
}

// DispatchAsync submits a log for background fan-out.
// Instead of silently dropping logs when the queue is full (data loss),
// this now applies backpressure by blocking until the queue has space
// or a 5-second timeout expires. Callers receiving an error should
// return HTTP 503 to signal the client to hold onto the data.
func (m *Manager) DispatchAsync(ctx context.Context, log *models.AuditLog) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return fmt.Errorf("pipeline manager is closed")
	}

	// Detach context to ensure background workers don't fail when HTTP request completes
	detachedCtx := context.WithoutCancel(ctx)

	// Apply backpressure instead of dropping: block for up to 5 seconds.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case m.asyncQueue <- asyncTask{ctx: detachedCtx, log: log}:
		return nil
	case <-timer.C:
		slog.Error("Pipeline async queue full after backpressure timeout, rejecting log", "id", log.ID)
		return fmt.Errorf("async pipeline queue full: backpressure timeout exceeded")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DispatchBatchAsync submits a batch of logs for background fan-out.
// Applies backpressure instead of silently dropping data.
func (m *Manager) DispatchBatchAsync(ctx context.Context, logs []models.AuditLog) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return fmt.Errorf("pipeline manager is closed")
	}

	detachedCtx := context.WithoutCancel(ctx)

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case m.asyncQueue <- asyncTask{ctx: detachedCtx, logs: logs}:
		return nil
	case <-timer.C:
		slog.Error("Pipeline async queue full after backpressure timeout, rejecting batch", "count", len(logs))
		return fmt.Errorf("async pipeline queue full: backpressure timeout exceeded")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Sinks returns the list of registered sinks.
func (m *Manager) Sinks() []sinks.Sink {
	return m.sinks
}

// Close gracefully shuts down all registered sinks and the worker pool.
func (m *Manager) Close() []error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.asyncQueue)
	m.mu.Unlock()

	m.wg.Wait()

	var errs []error
	for _, sink := range m.sinks {
		if err := sink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// isCriticalSink checks if a sink with the given name is critical.
func (m *Manager) isCriticalSink(name string) bool {
	for _, s := range m.sinks {
		if s.Name() == name && s.IsCritical() {
			return true
		}
	}
	return false
}

// HasCriticalFailure returns true if any of the provided errors originated from a critical sink.
func (m *Manager) HasCriticalFailure(errs []error) bool {
	for _, err := range errs {
		if err == nil {
			continue
		}
		var sinkErr *SinkError
		if errors.As(err, &sinkErr) && m.isCriticalSink(sinkErr.SinkName) {
			return true
		}
	}
	return false
}
