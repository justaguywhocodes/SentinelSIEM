package lifecycle

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestShutdownManagerOrderedExecution(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	var order []int
	for i := 0; i < 4; i++ {
		idx := i
		sm.Register("phase", func(_ context.Context) error {
			order = append(order, idx)
			return nil
		})
	}

	if err := sm.Shutdown(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(order) != 4 {
		t.Fatalf("expected 4 phases, got %d", len(order))
	}
	for i, v := range order {
		if v != i {
			t.Errorf("phase %d executed at position %d", v, i)
		}
	}
}

func TestShutdownManagerErrorContinues(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	var executed []string
	sm.Register("phase-1", func(_ context.Context) error {
		executed = append(executed, "phase-1")
		return errors.New("phase-1 failed")
	})
	sm.Register("phase-2", func(_ context.Context) error {
		executed = append(executed, "phase-2")
		return nil
	})
	sm.Register("phase-3", func(_ context.Context) error {
		executed = append(executed, "phase-3")
		return nil
	})

	err := sm.Shutdown()
	if err == nil {
		t.Fatal("expected error from failed phase")
	}
	if err.Error() != "phase-1 failed" {
		t.Fatalf("expected first error, got: %v", err)
	}

	// All phases should still execute despite the error.
	if len(executed) != 3 {
		t.Fatalf("expected 3 phases executed, got %d: %v", len(executed), executed)
	}
}

func TestShutdownManagerDeadlineEnforced(t *testing.T) {
	sm := NewShutdownManager(100 * time.Millisecond)

	var phase2Ran atomic.Bool

	sm.Register("slow-phase", func(ctx context.Context) error {
		// Block until context deadline.
		<-ctx.Done()
		return ctx.Err()
	})
	sm.Register("phase-2", func(_ context.Context) error {
		phase2Ran.Store(true)
		return nil
	})

	start := time.Now()
	err := sm.Shutdown()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from deadline")
	}

	// Should complete within a reasonable margin of the deadline.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("took too long: %s", elapsed)
	}
}

func TestShutdownManagerDefaultDeadline(t *testing.T) {
	sm := NewShutdownManager(0) // should default to 10s
	if sm.deadline != 10*time.Second {
		t.Fatalf("expected 10s default, got %s", sm.deadline)
	}
}

func TestShutdownManagerDoneChannel(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)
	sm.Register("fast", func(_ context.Context) error { return nil })

	// Done channel should not be closed before shutdown.
	select {
	case <-sm.Done():
		t.Fatal("done channel closed before shutdown")
	default:
	}

	sm.Shutdown()

	// Done channel should be closed after shutdown.
	select {
	case <-sm.Done():
		// expected
	case <-time.After(time.Second):
		t.Fatal("done channel not closed after shutdown")
	}
}

func TestShutdownManagerEmptyPhases(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	err := sm.Shutdown()
	if err != nil {
		t.Fatalf("unexpected error with no phases: %v", err)
	}
}

func TestShutdownManagerContextPassedToPhases(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	var ctxReceived context.Context
	sm.Register("capture-ctx", func(ctx context.Context) error {
		ctxReceived = ctx
		return nil
	})

	sm.Shutdown()

	if ctxReceived == nil {
		t.Fatal("context not passed to phase function")
	}
}
