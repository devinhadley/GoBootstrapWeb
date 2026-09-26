package ratelimit

import (
	"testing"
	"time"
)

func TestAllowTrueWithinBurst(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now, 1000)
	policy := Policy{Count: 3, Per: time.Minute}

	for i := range 3 {
		allowed, err := limiter.Allow("key", policy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("occurrence %d: got not allowed, want allowed", i)
		}
	}
}

func TestAllowFalseAfterBurstExhausted(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now, 1000)
	policy := Policy{Count: 3, Per: time.Minute}

	for range 3 {
		if _, err := limiter.Allow("key", policy); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	allowed, err := limiter.Allow("key", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("got allowed after exhausting the burst, want not allowed")
	}
}

func TestAllowRefillsOverTime(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now, 1000)
	policy := Policy{Count: 3, Per: time.Minute}

	for range 3 {
		if _, err := limiter.Allow("key", policy); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// One refill interval (Per/Count) worth of time passing should hand
	// back exactly one more token.
	clock.Advance(policy.Per/time.Duration(policy.Count) + time.Second)

	allowed, err := limiter.Allow("key", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatal("got not allowed after a refill interval elapsed, want allowed")
	}

	// The bucket should be empty again immediately after consuming that
	// refilled token.
	allowed, err = limiter.Allow("key", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("got allowed immediately after consuming the one refilled token, want not allowed")
	}
}

func TestAllowKeysAreIndependent(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now, 1000)
	policy := Policy{Count: 1, Per: time.Minute}

	if _, err := limiter.Allow("key-a", policy); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := limiter.Allow("key-a", policy); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	allowed, err := limiter.Allow("key-b", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatal("got key-b denied by an occurrence recorded against key-a")
	}
}

type fakeClock struct {
	someTime time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{someTime: time.Now()}
}

func (c *fakeClock) Now() time.Time {
	return c.someTime
}

func (c *fakeClock) Advance(d time.Duration) {
	c.someTime = c.someTime.Add(d)
}
