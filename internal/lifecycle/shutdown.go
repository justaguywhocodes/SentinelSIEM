// Package lifecycle provides production-grade graceful shutdown coordination.
//
// ShutdownManager registers named cleanup functions and executes them in order
// when a termination signal is received. It enforces a configurable deadline
// (default 10s), supports a second-signal force exit, and logs each phase
// with elapsed timing.
package lifecycle

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ShutdownFunc is a cleanup function called during shutdown.
// It receives a context that will be cancelled when the deadline expires.
type ShutdownFunc func(ctx context.Context) error

// phase represents a named shutdown step.
type phase struct {
	name string
	fn   ShutdownFunc
}

// ShutdownManager coordinates ordered graceful shutdown of application components.
type ShutdownManager struct {
	phases   []phase
	deadline time.Duration
	mu       sync.Mutex
	done     chan struct{}
}

// NewShutdownManager creates a shutdown manager with the given deadline.
// If deadline is 0, defaults to 10 seconds.
func NewShutdownManager(deadline time.Duration) *ShutdownManager {
	if deadline <= 0 {
		deadline = 10 * time.Second
	}
	return &ShutdownManager{
		deadline: deadline,
		done:     make(chan struct{}),
	}
}

// Register adds a named cleanup function to the shutdown sequence.
// Functions are called in the order they are registered.
func (sm *ShutdownManager) Register(name string, fn ShutdownFunc) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.phases = append(sm.phases, phase{name: name, fn: fn})
}

// WaitForSignal blocks until SIGTERM or SIGINT is received, then executes
// all registered shutdown phases in order. A second signal forces immediate exit.
//
// Returns nil if all phases completed successfully, or the first error encountered.
func (sm *ShutdownManager) WaitForSignal() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("[shutdown] received %s, starting graceful shutdown (deadline: %s)", sig, sm.deadline)

	return sm.execute(sigCh)
}

// Shutdown triggers the shutdown sequence programmatically (for testing).
func (sm *ShutdownManager) Shutdown() error {
	return sm.execute(nil)
}

// Done returns a channel that is closed when shutdown completes.
func (sm *ShutdownManager) Done() <-chan struct{} {
	return sm.done
}

// execute runs all registered phases in order within the deadline.
func (sm *ShutdownManager) execute(sigCh <-chan os.Signal) error {
	defer close(sm.done)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), sm.deadline)
	defer cancel()

	// Second signal = force exit.
	if sigCh != nil {
		go func() {
			select {
			case sig := <-sigCh:
				log.Printf("[shutdown] received second signal (%s), forcing exit", sig)
				os.Exit(1)
			case <-ctx.Done():
			}
		}()
	}

	sm.mu.Lock()
	phases := make([]phase, len(sm.phases))
	copy(phases, sm.phases)
	sm.mu.Unlock()

	var firstErr error
	for i, p := range phases {
		if ctx.Err() != nil {
			err := fmt.Errorf("deadline exceeded before phase %q", p.name)
			log.Printf("[shutdown] %v", err)
			if firstErr == nil {
				firstErr = err
			}
			break
		}

		phaseStart := time.Now()
		log.Printf("[shutdown] [%d/%d] %s ...", i+1, len(phases), p.name)

		if err := p.fn(ctx); err != nil {
			elapsed := time.Since(phaseStart)
			log.Printf("[shutdown] [%d/%d] %s FAILED (%s): %v", i+1, len(phases), p.name, elapsed.Round(time.Millisecond), err)
			if firstErr == nil {
				firstErr = err
			}
			// Continue with remaining phases even on error.
		} else {
			elapsed := time.Since(phaseStart)
			log.Printf("[shutdown] [%d/%d] %s OK (%s)", i+1, len(phases), p.name, elapsed.Round(time.Millisecond))
		}
	}

	total := time.Since(start)
	if firstErr != nil {
		log.Printf("[shutdown] completed with errors in %s", total.Round(time.Millisecond))
	} else {
		log.Printf("[shutdown] clean shutdown in %s", total.Round(time.Millisecond))
	}

	return firstErr
}
