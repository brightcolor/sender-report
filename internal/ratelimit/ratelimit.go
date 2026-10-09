package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu      sync.Mutex
	window  time.Duration
	maxHits int
	hits    map[string][]time.Time
}

func New(window time.Duration, maxHits int) *Limiter {
	return &Limiter{
		window:  window,
		maxHits: maxHits,
		hits:    make(map[string][]time.Time),
	}
}

func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	entries := l.hits[key]
	cutoff := now.Add(-l.window)
	kept := entries[:0]
	for _, t := range entries {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.maxHits {
		l.hits[key] = kept
		return false
	}
	kept = append(kept, now)
	l.hits[key] = kept
	return true
}

// RetryAfter is the time until Allow lets key through again: zero while key
// is below the limit, otherwise the time until enough of its hits have left
// the window.
func (l *Limiter) RetryAfter(key string) time.Duration {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.maxHits <= 0 {
		return l.window
	}
	cutoff := now.Add(-l.window)
	var kept []time.Time
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) < l.maxHits {
		return 0
	}
	// Hits are stored in the order they happened; the next one fits once
	// this hit has left the window.
	return kept[len(kept)-l.maxHits].Add(l.window).Sub(now)
}
