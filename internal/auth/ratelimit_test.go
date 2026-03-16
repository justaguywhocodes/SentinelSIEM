package auth

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewLoginRateLimiter(5, 30*time.Second)

	for i := 0; i < 5; i++ {
		if !rl.Allow("192.168.1.1") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
		rl.Record("192.168.1.1")
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewLoginRateLimiter(5, 30*time.Second)

	// Record 5 failed attempts.
	for i := 0; i < 5; i++ {
		rl.Record("192.168.1.1")
	}

	// 6th attempt should be blocked.
	if rl.Allow("192.168.1.1") {
		t.Fatal("6th attempt should be blocked")
	}
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := NewLoginRateLimiter(5, 30*time.Second)

	// Exhaust IP1.
	for i := 0; i < 5; i++ {
		rl.Record("192.168.1.1")
	}

	// IP2 should still be allowed.
	if !rl.Allow("192.168.1.2") {
		t.Fatal("different IP should not be rate limited")
	}
}

func TestRateLimiter_ResetClearsAttempts(t *testing.T) {
	rl := NewLoginRateLimiter(5, 30*time.Second)

	// Record 5 failed attempts.
	for i := 0; i < 5; i++ {
		rl.Record("192.168.1.1")
	}

	// Should be blocked.
	if rl.Allow("192.168.1.1") {
		t.Fatal("should be blocked after 5 attempts")
	}

	// Reset (successful login).
	rl.Reset("192.168.1.1")

	// Should be allowed again.
	if !rl.Allow("192.168.1.1") {
		t.Fatal("should be allowed after reset")
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	// Use a very short window for testing.
	rl := NewLoginRateLimiter(2, 50*time.Millisecond)

	rl.Record("10.0.0.1")
	rl.Record("10.0.0.1")

	if rl.Allow("10.0.0.1") {
		t.Fatal("should be blocked")
	}

	// Wait for window to expire.
	time.Sleep(60 * time.Millisecond)

	if !rl.Allow("10.0.0.1") {
		t.Fatal("should be allowed after window expires")
	}
}
