package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/i18n"
)

func TestWaitTextRoundsUpToWholeUnits(t *testing.T) {
	cases := []struct {
		wait   time.Duration
		de, en string
	}{
		{0, "1 Sekunde", "1 second"},
		{300 * time.Millisecond, "1 Sekunde", "1 second"},
		{1500 * time.Millisecond, "2 Sekunden", "2 seconds"},
		{59 * time.Second, "59 Sekunden", "59 seconds"},
		{59*time.Second + 500*time.Millisecond, "1 Minute", "1 minute"},
		{61 * time.Second, "2 Minuten", "2 minutes"},
		{23*time.Minute + 5*time.Second, "24 Minuten", "24 minutes"},
		{time.Hour, "60 Minuten", "60 minutes"},
	}
	for _, tc := range cases {
		if got := waitText(i18n.DE, tc.wait); got != tc.de {
			t.Errorf("waitText(de, %s) = %q, want %q", tc.wait, got, tc.de)
		}
		if got := waitText(i18n.EN, tc.wait); got != tc.en {
			t.Errorf("waitText(en, %s) = %q, want %q", tc.wait, got, tc.en)
		}
	}
}

func TestWaitSecondsIsAtLeastOne(t *testing.T) {
	for _, tc := range []struct {
		wait time.Duration
		want int
	}{
		{-time.Second, 1}, {0, 1}, {time.Millisecond, 1}, {time.Second, 1}, {1001 * time.Millisecond, 2}, {time.Hour, 3600},
	} {
		if got := waitSeconds(tc.wait); got != tc.want {
			t.Errorf("waitSeconds(%s) = %d, want %d", tc.wait, got, tc.want)
		}
	}
}

// decodeJSON reads the JSON object of a recorded response.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response %q is no JSON object: %v", rr.Body.String(), err)
	}
	return body
}

func TestPlacementRateLimitNamesTheConfiguredLimit(t *testing.T) {
	cases := []struct {
		limit                  int
		wantError              string
		lang                   string
		wantParts, absentParts []string
	}{
		{2, "rate limit: max 2 placement tests per hour", "de",
			[]string{"schon 2 Platzierungstests gestartet", "Obergrenze dieses Servers", "in 24 Minuten starten"}, []string{"3"}},
		{2, "rate limit: max 2 placement tests per hour", "en",
			[]string{"already started 2 placement tests in the last hour", "limit on this server", "in 24 minutes"}, []string{"3"}},
		{1, "rate limit: max 1 placement test per hour", "de",
			[]string{"schon 1 Platzierungstest gestartet"}, nil},
		{12, "rate limit: max 12 placement tests per hour", "en",
			[]string{"already started 12 placement tests"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.lang+"/"+tc.wantError, func(t *testing.T) {
			srv := &Server{cfg: config.Config{IPTRateLimitPerHour: tc.limit}}
			req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/abc/ipt/start", nil)
			req.Header.Set("Accept-Language", tc.lang)
			rr := httptest.NewRecorder()

			srv.placementRateLimited(rr, req, 23*time.Minute+5*time.Second)

			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", rr.Code)
			}
			if got := rr.Header().Get("Retry-After"); got != "1385" {
				t.Errorf("Retry-After = %q, want 1385", got)
			}
			body := decodeJSON(t, rr)
			if body["error"] != tc.wantError {
				t.Errorf("error = %q, want %q", body["error"], tc.wantError)
			}
			msg, _ := body["message"].(string)
			for _, part := range tc.wantParts {
				if !strings.Contains(msg, part) {
					t.Errorf("message %q lacks %q", msg, part)
				}
			}
			for _, part := range tc.absentParts {
				if strings.Contains(msg, part) {
					t.Errorf("message %q names %q", msg, part)
				}
			}
		})
	}
}

func TestNewWiresTheConfiguredRequestLimits(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	for _, tc := range []struct{ payload, ipt int }{
		{config.DefaultPayloadRateLimitPerMin, config.DefaultIPTRateLimitPerHour},
		{2, 1},
		{45, 7},
	} {
		srv, err := New(config.Config{UIDefaultTheme: "auto", WebRateLimitPerMin: 60, WebBurstPer10Sec: 20,
			PayloadRateLimitPerMin: tc.payload, IPTRateLimitPerHour: tc.ipt}, nil, nil, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		for i := 0; i < tc.payload; i++ {
			if !srv.payloadLimiter.Allow("payload:203.0.113.7") {
				t.Fatalf("payload limit %d: fetch %d was blocked", tc.payload, i+1)
			}
		}
		if srv.payloadLimiter.Allow("payload:203.0.113.7") {
			t.Errorf("payload limit %d: fetch %d went through", tc.payload, tc.payload+1)
		}
		for i := 0; i < tc.ipt; i++ {
			if !srv.iptLimiter.Allow("ipt:203.0.113.7") {
				t.Fatalf("placement limit %d: start %d was blocked", tc.ipt, i+1)
			}
		}
		if srv.iptLimiter.Allow("ipt:203.0.113.7") {
			t.Errorf("placement limit %d: start %d went through", tc.ipt, tc.ipt+1)
		}
	}
}
