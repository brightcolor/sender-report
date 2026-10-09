//go:build cgo
// +build cgo

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/db"
	"github.com/brightcolor/sender-report/internal/store"
)

// newStoreTestServer builds a server on a fresh database with placement tests
// switched on for one seed provider ("Testmail"). The seed account points to
// a closed local port, so a started test finds nothing and contacts no
// provider. mutate adjusts the configuration before the server is built.
func newStoreTestServer(t *testing.T, mutate func(*config.Config)) (*Server, *store.Store) {
	t.Helper()
	restoreWD := chdirToRepoRoot(t)
	t.Cleanup(restoreWD)

	tmp := t.TempDir()
	sqlDB, err := db.Open(filepath.Join(tmp, "limits.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	seeds := filepath.Join(tmp, "seeds.json")
	seedJSON := `{"providers":[{"name":"Testmail","imap":"127.0.0.1:1","accounts":[{"user":"seed@example.test","pass":"seed-test-pass"}]}]}`
	if err := os.WriteFile(seeds, []byte(seedJSON), 0o600); err != nil {
		t.Fatalf("write seeds: %v", err)
	}

	cfg := config.Config{
		AppName:                "Sender-Report",
		PublicBaseURL:          "http://localhost:8080",
		SMTPDomain:             "example.test",
		MailboxTTL:             time.Hour,
		WebRateLimitPerMin:     1000,
		WebBurstPer10Sec:       1000,
		PayloadRateLimitPerMin: config.DefaultPayloadRateLimitPerMin,
		IPTRateLimitPerHour:    config.DefaultIPTRateLimitPerHour,
		EnableInboxPlacement:   true,
		SeedAccountsFile:       seeds,
		UIDefaultTheme:         "auto",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	st := store.New(sqlDB)
	srv, err := New(cfg, st, nil, nil)
	if err != nil {
		t.Fatalf("new web server: %v", err)
	}
	if srv.seeds == nil {
		t.Fatal("seed accounts were not loaded")
	}
	return srv, st
}

// serve sends one request from the given client IP through the full handler.
func serve(srv *Server, method, path, body, ip, lang string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("Accept-Language", lang)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

func TestPayloadFetchesFollowTheConfiguredLimit(t *testing.T) {
	for _, limit := range []int{2, 5, config.DefaultPayloadRateLimitPerMin} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			srv, _ := newStoreTestServer(t, func(c *config.Config) { c.PayloadRateLimitPerMin = limit })
			for i := 1; i <= limit; i++ {
				if rr := serve(srv, http.MethodGet, "/api/payload/nosuchbox/ref", "", "203.0.113.7", "en"); rr.Code != http.StatusNotFound {
					t.Fatalf("fetch %d: status %d, want 404 below the limit", i, rr.Code)
				}
			}
			if rr := serve(srv, http.MethodGet, "/api/payload/nosuchbox/ref", "", "203.0.113.7", "en"); rr.Code != http.StatusTooManyRequests {
				t.Fatalf("fetch %d: status %d, want 429", limit+1, rr.Code)
			}
			if rr := serve(srv, http.MethodGet, "/api/payload/nosuchbox/ref", "", "203.0.113.8", "en"); rr.Code != http.StatusNotFound {
				t.Fatalf("another IP: status %d, want 404", rr.Code)
			}
		})
	}
}

func TestPlacementStartsFollowTheConfiguredLimit(t *testing.T) {
	for _, limit := range []int{1, 2, config.DefaultIPTRateLimitPerHour} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			srv, _ := newStoreTestServer(t, func(c *config.Config) { c.IPTRateLimitPerHour = limit })
			// An unknown mailbox answers 404 after the limit check, so these
			// requests count without starting a test.
			const path = "/api/mailboxes/nosuchbox/ipt/start"
			for i := 1; i <= limit; i++ {
				if rr := serve(srv, http.MethodPost, path, `{"selected_providers":["Testmail"]}`, "203.0.113.7", "de"); rr.Code != http.StatusNotFound {
					t.Fatalf("start %d: status %d, want 404 below the limit", i, rr.Code)
				}
			}
			rr := serve(srv, http.MethodPost, path, `{"selected_providers":["Testmail"]}`, "203.0.113.7", "de")
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("start %d: status %d, want 429", limit+1, rr.Code)
			}
			secs, err := strconv.Atoi(rr.Header().Get("Retry-After"))
			if err != nil || secs < 3500 || secs > 3600 {
				t.Errorf("Retry-After = %q, want close to an hour", rr.Header().Get("Retry-After"))
			}
			msg, _ := decodeJSON(t, rr)["message"].(string)
			want := "schon " + countNoun(limit, "Platzierungstest", "Platzierungstests") + " gestartet"
			if !strings.Contains(msg, want) || !strings.Contains(msg, "in 60 Minuten starten") {
				t.Errorf("message %q should contain %q and the wait", msg, want)
			}
		})
	}
}

func TestPlacementStartExplainsWhatToDo(t *testing.T) {
	srv, st := newStoreTestServer(t, nil)
	mb, err := st.CreateMailbox(context.Background(), "m4ilb0x01", "m4ilb0x01@example.test", "", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}
	cases := []struct {
		name, path, body, lang string
		status                 int
		reason, message        string
	}{
		{"unknown mailbox", "/api/mailboxes/nosuchbox/ipt/start", `{}`, "de", http.StatusNotFound,
			"mailbox not found", "Legen Sie auf der Startseite ein neues an"},
		{"unknown mailbox, English", "/api/mailboxes/nosuchbox/ipt/start", `{}`, "en", http.StatusNotFound,
			"mailbox not found", "Create a new one on the home page"},
		{"unreadable request", "/api/mailboxes/" + mb.Token + "/ipt/start", `{`, "de", http.StatusBadRequest,
			"invalid body", "Laden Sie die Seite neu"},
		{"unknown provider", "/api/mailboxes/" + mb.Token + "/ipt/start", `{"selected_providers":["Nomail"]}`, "en", http.StatusBadRequest,
			"no valid providers selected", "Select at least one of the providers shown"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Each case comes from its own address, so the limit stays out of the way.
			rr := serve(srv, http.MethodPost, tc.path, tc.body, "198.51.100."+strconv.Itoa(i+1), tc.lang)
			if rr.Code != tc.status {
				t.Fatalf("status = %d, want %d", rr.Code, tc.status)
			}
			body := decodeJSON(t, rr)
			if body["error"] != tc.reason {
				t.Errorf("error = %q, want %q", body["error"], tc.reason)
			}
			if msg, _ := body["message"].(string); !strings.Contains(msg, tc.message) {
				t.Errorf("message %q lacks %q", msg, tc.message)
			}
		})
	}
}
