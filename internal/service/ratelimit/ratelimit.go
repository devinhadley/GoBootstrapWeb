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
	"log"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

// evictionWarnInterval throttles the eviction warning so a thrashing cache
// can't flood the logs.
const evictionWarnInterval = 30 * time.Second

// Policy is a rate limit: at most Count occurrences of a key within Per.
// Count must be > 0.
type Policy struct {
	Count int
	Per   time.Duration
}

type InMemoryLimiter struct {
	lruCache *lru.Cache[string, *rate.Limiter]
	now      func() time.Time
}

func NewInMemoryLimiter(now func() time.Time, size int) *InMemoryLimiter {
	warnEvict := createThrottle(evictionWarnInterval, now)

	onEvict := func(key string, limiter *rate.Limiter) {
		tokens := limiter.TokensAt(now())
		if tokens == float64(limiter.Burst()) {
			return
		}

		// Rate limits exist to track spent tokens. If we're losing this insight, we need to right size the store...
		warnEvict(func() {
			log.Printf("ratelimit: WARNING evicted %q with %.1f/%d tokens left; LRU of %d keys may be undersized",
				key, tokens, limiter.Burst(), size)
		})
	}

	entries, err := lru.NewWithEvict(size, onEvict)
	if err != nil {
		panic(err) // Initialized at application startup, so a fine panic.
	}

	return &InMemoryLimiter{
		lruCache: entries,
		now:      now,
	}
}

func createThrottle(every time.Duration, now func() time.Time) func(work func()) {
	var mu sync.Mutex
	var nextRun time.Time // Zero value => the first call always runs.

	return func(work func()) {
		mu.Lock()
		defer mu.Unlock()

		t := now()
		if t.Before(nextRun) {
			return
		}
		work()
		nextRun = t.Add(every)
	}
}

func (s *InMemoryLimiter) Allow(key string, p Policy) (bool, error) {

	if limiter, ok := s.lruCache.Get(key); ok {
		return limiter.AllowN(s.now(), 1), nil
	}

	candidate := rate.NewLimiter(rate.Every(p.Per/time.Duration(p.Count)), p.Count)

	// To add new limiters, key must not already be in the LRU (dont wan't to overwrite anything added after get).
	// Whether its in there or not could have changed from when we get.
	existing, ok, _ := s.lruCache.PeekOrAdd(key, candidate)

	limiter := candidate
	if ok {
		limiter = existing
	}

	return limiter.AllowN(s.now(), 1), nil
}
