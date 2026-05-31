//go:build cgo
// +build cgo

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/db"
	"github.com/brightcolor/sender-report/internal/model"
	"github.com/brightcolor/sender-report/internal/store"
)

func TestReportUsesTokenURLAndInlineRawAccordion(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, st, mb, msg, rep := prepareWebTestFixture(t)
	h := srv.Handler()

	msgRef := messageReference(mb.Token, msg.ID)
	req := httptest.NewRequest(http.MethodGet, "/report/"+mb.Token+"?msg="+msgRef, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "rawAccordion") {
		t.Fatalf("expected inline raw accordion in report page")
	}
	if !strings.Contains(body, "Plaintext-Ansicht") || !strings.Contains(body, "HTML Quelltext") {
		t.Fatalf("expected plaintext/html sections in report page")
	}
	if !strings.Contains(body, msg.HeaderBlock) {
		t.Fatalf("expected header block in report page")
	}
	if !strings.Contains(body, msg.RawSource) {
		t.Fatalf("expected raw source in report page")
	}

	req = httptest.NewRequest(http.MethodGet, "/raw/"+mb.Token+"/"+msgRef+"/headers", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Subject: Demo") {
		t.Fatalf("expected tokenized raw header download, code=%d body=%q", rr.Code, rr.Body.String())
	}

	// Numeric report IDs should no longer be directly routable.
	req = httptest.NewRequest(http.MethodGet, "/report/"+itoa(rep.ID), nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for numeric report URL, got %d", rr.Code)
	}

	_ = st
}

// TestHomeRendersWithoutServerSideMailbox verifies that since Phase 2 the home
// page no longer creates a mailbox server-side or sets a mailbox cookie.
// Mailbox creation is now delegated to the browser (client-side crypto).
func TestHomeRendersWithoutServerSideMailbox(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "home.db")
	sqlDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	st := store.New(sqlDB)
	cfg := config.Config{
		AppName:              "Sender-Report",
		PublicBaseURL:        "http://localhost:8080",
		SMTPDomain:           "example.test",
		MailboxTTL:           time.Hour,
		MaxActivePerIP:       100,
		MaxActiveGlobal:      1000,
		WebRateLimitPerMin:   1000,
		WebBurstPer10Sec:     1000,
		SMTPRateLimitPerHour: 1000,
	}
	srv, err := New(cfg, st, nil, nil)
	if err != nil {
		t.Fatalf("new web server: %v", err)
	}
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("home request expected 200, got %d", rr.Code)
	}
	// Phase 2: no server-side mailbox creation, so no mailbox cookie is set.
	for _, c := range rr.Result().Cookies() {
		if c.Name == "mailprobe_mailbox" {
			t.Fatalf("unexpected mailbox cookie on home response (Phase 2 uses client-side creation)")
		}
	}
}

func TestCreateMailboxJSONReturnsNewAddressWithoutRedirect(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "create-json.db")
	sqlDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	st := store.New(sqlDB)
	cfg := config.Config{
		AppName:              "Sender-Report",
		PublicBaseURL:        "http://localhost:8080",
		SMTPDomain:           "example.test",
		MailboxTTL:           time.Hour,
		MaxActivePerIP:       100,
		MaxActiveGlobal:      1000,
		WebRateLimitPerMin:   1000,
		WebBurstPer10Sec:     1000,
		SMTPRateLimitPerHour: 1000,
	}
	srv, err := New(cfg, st, nil, nil)
	if err != nil {
		t.Fatalf("new web server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:12345"
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%q", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json payload: %v", err)
	}
	if payload["token"] == "" || payload["address"] == "" || payload["mailbox_url"] == "" {
		t.Fatalf("missing mailbox fields: %#v", payload)
	}
	// Phase 2: JSON API (legacy empty-body path) no longer sets a cookie.
	// Cookie is only set on the form-POST fallback path.
}

func TestMailboxStatusReturnsTokenizedReportPath(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, _, mb, msg, _ := prepareWebTestFixture(t)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes/"+mb.Token+"/status", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json payload: %v", err)
	}
	got, _ := payload["latest_report_path"].(string)
	want := "/report/" + mb.Token + "?msg=" + messageReference(mb.Token, msg.ID)
	if got != want {
		t.Fatalf("latest_report_path mismatch: got %q want %q", got, want)
	}
}

func TestReportAPIReturnsJSONForTokenizedMessageRef(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, _, mb, msg, _ := prepareWebTestFixture(t)
	h := srv.Handler()
	msgRef := messageReference(mb.Token, msg.ID)

	req := httptest.NewRequest(http.MethodGet, "/api/reports/"+mb.Token+"/"+msgRef, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json payload: %v", err)
	}
	message, ok := payload["message"].(map[string]any)
	if !ok {
		t.Fatalf("expected message object in payload: %#v", payload)
	}
	if message["reference"] != msgRef || message["subject"] != "Demo" {
		t.Fatalf("unexpected message metadata: %#v", message)
	}
	report, ok := payload["report"].(map[string]any)
	if !ok {
		t.Fatalf("expected report object in payload: %#v", payload)
	}
	if report["score_label"] != "Good" {
		t.Fatalf("unexpected report payload: %#v", report)
	}
}

func TestMailboxPageRendersMessageList(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, _, mb, msg, rep := prepareWebTestFixture(t)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/mailbox/"+mb.Token, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, mb.Address) {
		t.Fatalf("expected mailbox address in page")
	}
	if !strings.Contains(body, msg.Subject) {
		t.Fatalf("expected message subject in page")
	}
	msgRef := messageReference(mb.Token, msg.ID)
	if !strings.Contains(body, msgRef) {
		t.Fatalf("expected message reference link in page")
	}
	_ = rep
}

func TestDeleteMailboxAPI(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, st, mb, _, _ := prepareWebTestFixture(t)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mb.Token+"/delete", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on delete, got %d body=%q", rr.Code, rr.Body.String())
	}

	// Mailbox should be gone
	if _, err := st.GetMailboxByToken(context.Background(), mb.Token); err == nil {
		t.Fatal("expected mailbox to be deleted, but it still exists")
	}
}

func TestReportScoreHeroClassThreshold(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, _, mb, msg, _ := prepareWebTestFixture(t)
	h := srv.Handler()

	msgRef := messageReference(mb.Token, msg.ID)
	req := httptest.NewRequest(http.MethodGet, "/report/"+mb.Token+"?msg="+msgRef, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	body := rr.Body.String()
	// fixture score is 8.8 which is ≥7.5 → "pass"
	if !strings.Contains(body, "status-pass") {
		t.Fatalf("expected status-pass class for score 8.8 (≥7.5), got body length %d", len(body))
	}
}

func prepareWebTestFixture(t *testing.T) (*Server, *store.Store, model.Mailbox, model.Message, model.AnalysisReport) {
	t.Helper()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "test.db")
	sqlDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	st := store.New(sqlDB)
	ctx := context.Background()

	mb, err := st.CreateMailbox(ctx, "rk3ee85g6", "rk3ee85g6@example.test", "", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}

	msg, err := st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    "sender@example.org",
		RCPTTo:      mb.Address,
		RemoteIP:    "203.0.113.20",
		HELO:        "mx.example.org",
		ReceivedAt:  time.Now().UTC(),
		RawSource:   "From: sender@example.org\r\nSubject: Demo\r\n\r\nHello world",
		HeaderBlock: "From: sender@example.org\r\nSubject: Demo",
		Subject:     "Demo",
		SizeBytes:   64,
	})
	if err != nil {
		t.Fatalf("save message: %v", err)
	}

	rep, err := st.SaveReport(ctx, model.AnalysisReport{
		MessageID:  msg.ID,
		CreatedAt:  time.Now().UTC(),
		Score:      8.8,
		ScoreLabel: "Good",
		Checks: []model.CheckResult{
			{ID: "spf", Name: "SPF", Status: "pass", ScoreDelta: 0.4, Summary: "ok"},
			{ID: "dkim", Name: "DKIM", Status: "warn", ScoreDelta: -0.4, Summary: "warn"},
		},
		RawHeaders: map[string][]string{"From": {"sender@example.org"}},
	})
	if err != nil {
		t.Fatalf("save report: %v", err)
	}

	cfg := config.Config{
		AppName:            "Sender-Report",
		PublicBaseURL:      "http://localhost:8080",
		SMTPDomain:         "example.test",
		MailboxTTL:         time.Hour,
		WebRateLimitPerMin: 1000,
		WebBurstPer10Sec:   1000,
	}
	srv, err := New(cfg, st, nil, nil)
	if err != nil {
		t.Fatalf("new web server: %v", err)
	}

	return srv, st, mb, msg, rep
}

func chdirToRepoRoot(t *testing.T) func() {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir to repo root: %v", err)
	}
	return func() {
		_ = os.Chdir(prevWD)
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
