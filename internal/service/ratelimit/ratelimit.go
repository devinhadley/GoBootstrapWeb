// Package ratelimit provides a generic, in-memory rate limiter keyed by an
// arbitrary string, called directly from handlers.

// Note that this rate limiting is for business-logic concern (e.g. "don't let
// this email guess passwords 1000 times an hour"), distinct from a web
// application firewall's job of blocking volumetric/DoS traffic by IP. Usage of
// this package should never be used for the latter use case, and should only handle rate
// limiting based things only the application has access to i.e. the logged in user.

// It is by no means perfect, as it limits all attempts the same regardless of
// success or failure. But it is simple to reason about, and when balanced
// with good limits shouldn't hurt UX.
package ratelimit

import (
	"slices"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	maxCount    = 1000   // Max number of occurrences to store per key.
	retainCount = 200    // When freeing space per key, how many of the most recent occurrences to keep.
	numKeys     = 10_000 // Number of keys in the LRU before eviction kicks in.
)

// Policy is a rate limit: at most Count occurrences of a key within Per.
type Policy struct {
	Count int
	Per   time.Duration
}

type Occurrences struct {
	mu    sync.RWMutex
	times []time.Time
}

// now must be after all previous occurances...
func (o *Occurrences) addOccurrenceAt(now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Preserve only the most recent (retainCount) items, since that's what rate limiting usually cares about anyway.
	if len(o.times) >= maxCount {
		retained := make(
			[]time.Time,
			retainCount,
			maxCount,
		)

		copy(
			retained,
			o.times[len(o.times)-retainCount:],
		)

		o.times = retained
	}

	o.times = append(o.times, now)
}

// countFrom reports how many occurrences fall within per, counting back from now.
// Split out from InMemoryLimiter.IsLimited so tests can control the clock.
func (o *Occurrences) countFrom(now time.Time, per time.Duration) int {
	o.mu.RLock()
	defer o.mu.RUnlock()

	startingAt := now.Add(-per)

	// The equivalent of bisect left...
	i, _ := slices.BinarySearchFunc(o.times, startingAt, time.Time.Compare)

	return len(o.times) - i
}

type InMemoryLimiter struct {
	lruCache *lru.Cache[string, *Occurrences]
	now      func() time.Time
}

// NewInMemoryLimiter creates a limiter that measures elapsed time via now.
// Pass time.Now in production; tests (including outside this package, e.g.
// integration tests) can pass a fake clock to control window expiry without
// sleeping for real.
func NewInMemoryLimiter(now func() time.Time) *InMemoryLimiter {
	entries, err := lru.New[string, *Occurrences](numKeys)
	if err != nil {
		panic(err) // Initialized at application startup, so a fine panic.
	}

	return &InMemoryLimiter{
		lruCache: entries,
		now:      now,
	}
}

// AddOccurrence adds an occurrence of key now. If the number of occurrences for
// key exceeds maxCount, it retains only the most recent retainCount and
// discards the rest.
func (s *InMemoryLimiter) AddOccurrence(key string) error {
	occurrences, ok := s.lruCache.Get(key)
	if !ok {
		occurrences = &Occurrences{
			times: make([]time.Time, 0, maxCount),
		}
	}

	occurrences.addOccurrenceAt(s.now())

	s.lruCache.Add(key, occurrences)

	return nil
}

// IsLimited reports whether key has had p.Count or more occurrences within
// p.Per. Callers should not expect to see more than retainCount past
// occurrences for a key due to the eviction policy above.
func (s *InMemoryLimiter) IsLimited(key string, p Policy) (bool, error) {
	occurrences, ok := s.lruCache.Get(key)
	if !ok {
		return false, nil
	}

	return occurrences.countFrom(s.now(), p.Per) >= p.Count, nil
}
