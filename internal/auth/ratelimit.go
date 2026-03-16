package auth

import (
	"net/http"
	"sync"
	"time"
)

// LoginRateLimiter tracks failed login attempts per IP address.
// After maxAttempts within the window, subsequent requests are rejected with 429.
type LoginRateLimiter struct {
	mu          sync.Mutex
	attempts    map[string][]time.Time
	maxAttempts int
	window      time.Duration
}

// NewLoginRateLimiter creates a rate limiter for login attempts.
func NewLoginRateLimiter(maxAttempts int, window time.Duration) *LoginRateLimiter {
	rl := &LoginRateLimiter{
		attempts:    make(map[string][]time.Time),
		maxAttempts: maxAttempts,
		window:      window,
	}
	// Background cleanup of stale entries every 5 minutes.
	go rl.cleanup()
	return rl
}

// Allow checks if the IP is allowed to attempt a login.
// Returns true if under the rate limit, false if blocked.
func (rl *LoginRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter to only recent attempts within the window.
	recent := rl.filterRecent(rl.attempts[ip], cutoff)
	rl.attempts[ip] = recent

	return len(recent) < rl.maxAttempts
}

// Record adds a failed login attempt for the given IP.
func (rl *LoginRateLimiter) Record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

// Reset clears all attempts for an IP (called on successful login).
func (rl *LoginRateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.attempts, ip)
}

// filterRecent returns only timestamps after the cutoff.
func (rl *LoginRateLimiter) filterRecent(times []time.Time, cutoff time.Time) []time.Time {
	var result []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			result = append(result, t)
		}
	}
	return result
}

// cleanup periodically removes stale IP entries.
func (rl *LoginRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-rl.window)
		for ip, times := range rl.attempts {
			recent := rl.filterRecent(times, cutoff)
			if len(recent) == 0 {
				delete(rl.attempts, ip)
			} else {
				rl.attempts[ip] = recent
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware wraps a login handler with rate limiting.
func RateLimitMiddleware(limiter *LoginRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr

			if !limiter.Allow(ip) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error": "too many login attempts, try again later",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
