package ratelimit

import (
	"testing"
	"time"
)

func TestAllowEnforcesWindowLimit(t *testing.T) {
	l := New(40*time.Millisecond, 2)

	if !l.Allow("ip:1") {
		t.Fatal("first hit should be allowed")
	}
	if !l.Allow("ip:1") {
		t.Fatal("second hit should be allowed")
	}
	if l.Allow("ip:1") {
		t.Fatal("third hit in window should be blocked")
	}

	time.Sleep(60 * time.Millisecond)
	if !l.Allow("ip:1") {
		t.Fatal("hit after window should be allowed again")
	}
}

func TestRetryAfterNamesTheEndOfTheBlock(t *testing.T) {
	for _, maxHits := range []int{1, 3} {
		l := New(time.Hour, maxHits)
		if got := l.RetryAfter("ip:1"); got != 0 {
			t.Fatalf("limit %d: RetryAfter for an unused key = %s, want 0", maxHits, got)
		}
		for i := 0; i < maxHits; i++ {
			if !l.Allow("ip:1") {
				t.Fatalf("limit %d: hit %d should be allowed", maxHits, i+1)
			}
		}
		if l.Allow("ip:1") {
			t.Fatalf("limit %d: hit %d should be blocked", maxHits, maxHits+1)
		}
		got := l.RetryAfter("ip:1")
		if got <= 59*time.Minute || got > time.Hour {
			t.Fatalf("limit %d: RetryAfter = %s, want just under an hour", maxHits, got)
		}
		if other := l.RetryAfter("ip:2"); other != 0 {
			t.Fatalf("limit %d: RetryAfter for another key = %s, want 0", maxHits, other)
		}
	}
}

func TestRetryAfterEndsWithTheWindow(t *testing.T) {
	l := New(40*time.Millisecond, 1)
	l.Allow("ip:1")
	if l.RetryAfter("ip:1") <= 0 {
		t.Fatal("RetryAfter should be positive while the key is blocked")
	}
	time.Sleep(60 * time.Millisecond)
	if got := l.RetryAfter("ip:1"); got != 0 {
		t.Fatalf("RetryAfter after the window = %s, want 0", got)
	}
	if !l.Allow("ip:1") {
		t.Fatal("hit after the window should be allowed again")
	}
}

func TestAllowIsPerKey(t *testing.T) {
	l := New(time.Minute, 1)

	if !l.Allow("a") {
		t.Fatal("first hit for key a should pass")
	}
	if l.Allow("a") {
		t.Fatal("second hit for key a should fail")
	}
	if !l.Allow("b") {
		t.Fatal("first hit for key b should still pass")
	}
}
