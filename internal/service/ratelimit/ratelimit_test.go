package ratelimit

import (
	"testing"
	"time"
)

func TestIsLimitedFalseBeforeThresholdReached(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now)
	policy := Policy{Count: 3, Per: time.Minute}

	for i := range 2 {
		limited, err := limiter.IsLimited("key", policy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if limited {
			t.Fatalf("occurrence %d: got limited, want not limited", i)
		}

		if err := limiter.AddOccurrence("key"); err != nil {
			t.Fatalf("unexpected error adding occurrence: %v", err)
		}
	}
}

func TestIsLimitedTrueAtThreshold(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now)
	policy := Policy{Count: 3, Per: time.Minute}

	for range 3 {
		if err := limiter.AddOccurrence("key"); err != nil {
			t.Fatalf("unexpected error adding occurrence: %v", err)
		}
	}

	limited, err := limiter.IsLimited("key", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !limited {
		t.Fatal("got not limited after reaching Count occurrences, want limited")
	}
}

func TestIsLimitedDecaysAfterWindowElapses(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now)
	policy := Policy{Count: 3, Per: time.Minute}

	for range 3 {
		if err := limiter.AddOccurrence("key"); err != nil {
			t.Fatalf("unexpected error adding occurrence: %v", err)
		}
	}

	limited, err := limiter.IsLimited("key", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !limited {
		t.Fatal("got not limited after reaching Count occurrences, want limited")
	}

	clock.Advance(policy.Per + time.Second)

	limited, err = limiter.IsLimited("key", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limited {
		t.Fatal("got limited after the window elapsed, want not limited")
	}
}

func TestIsLimitedPartialDecay(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now)
	policy := Policy{Count: 2, Per: time.Minute}

	if err := limiter.AddOccurrence("key"); err != nil {
		t.Fatalf("unexpected error adding occurrence: %v", err)
	}

	clock.Advance(policy.Per + time.Second)

	for range 2 {
		if err := limiter.AddOccurrence("key"); err != nil {
			t.Fatalf("unexpected error adding occurrence: %v", err)
		}
	}

	limited, err := limiter.IsLimited("key", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !limited {
		t.Fatal("got not limited with 2 occurrences in-window at Count 2, want limited")
	}
}

func TestIsLimitedFalseForUnknownKey(t *testing.T) {
	limiter := NewInMemoryLimiter(time.Now)

	limited, err := limiter.IsLimited("never-seen", Policy{Count: 1, Per: time.Minute})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limited {
		t.Fatal("got limited for a key with no occurrences, want not limited")
	}
}

func TestIsLimitedKeysAreIndependent(t *testing.T) {
	clock := newFakeClock()
	limiter := NewInMemoryLimiter(clock.Now)
	policy := Policy{Count: 1, Per: time.Minute}

	if err := limiter.AddOccurrence("key-a"); err != nil {
		t.Fatalf("unexpected error adding occurrence: %v", err)
	}

	limited, err := limiter.IsLimited("key-b", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limited {
		t.Fatal("got key-b limited by an occurrence recorded against key-a")
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
