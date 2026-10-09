package web

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/ipt"
)

var hexToken = regexp.MustCompile(`^[0-9a-f]+$`)

func TestNewPlacementTokenHasTheConfiguredLength(t *testing.T) {
	for _, n := range []int{config.MinIPTTokenLength, 17, config.DefaultIPTTokenLength, 41, config.MaxIPTTokenLength} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			srv := &Server{cfg: config.Config{IPTTokenLength: n}}
			first, err := srv.newPlacementToken()
			if err != nil {
				t.Fatalf("newPlacementToken: %v", err)
			}
			second, err := srv.newPlacementToken()
			if err != nil {
				t.Fatalf("newPlacementToken: %v", err)
			}
			for _, tok := range []string{first, second} {
				if len(tok) != n || !hexToken.MatchString(tok) {
					t.Errorf("token %q: want %d hexadecimal characters", tok, n)
				}
			}
			if first == second {
				t.Errorf("two tokens are equal: %q", first)
			}
		})
	}
}

func TestNewPlacementTokenRefusesLengthsOutsideTheBounds(t *testing.T) {
	for _, n := range []int{0, 6, config.MinIPTTokenLength - 1, config.MaxIPTTokenLength + 1} {
		srv := &Server{cfg: config.Config{IPTTokenLength: n}}
		if tok, err := srv.newPlacementToken(); err == nil {
			t.Errorf("IPT_TOKEN_LENGTH=%d gave the token %q", n, tok)
		}
	}
}

func TestShorterPlacementTokensOpenTheirTestUntilItExpires(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	running := ipt.PlacementTest{ExpiresAt: now.Add(5 * time.Minute)}
	expired := ipt.PlacementTest{ExpiresAt: now.Add(-time.Second)}
	cases := []struct {
		setting, tokenLength int
		test                 ipt.PlacementTest
		want                 bool
	}{
		{32, 6, running, true},
		{32, 6, expired, false},
		{32, 31, expired, false},
		{32, 32, expired, true},
		{32, 48, expired, true},
		{20, 19, running, true},
		{20, 19, expired, false},
		{20, 20, expired, true},
		{20, 32, expired, true},
	}
	for _, tc := range cases {
		srv := &Server{cfg: config.Config{IPTTokenLength: tc.setting}}
		token := strings.Repeat("a", tc.tokenLength)
		if got := srv.placementTokenAccepted(token, tc.test, now); got != tc.want {
			t.Errorf("setting %d, token of %d characters, expires %s: accepted = %v, want %v",
				tc.setting, tc.tokenLength, tc.test.ExpiresAt.Sub(now), got, tc.want)
		}
	}
}
