//go:build cgo
// +build cgo

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/brightcolor/sender-report/internal/db"
	"github.com/brightcolor/sender-report/internal/model"
)

func TestStoreMailboxMessageReportLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	mb, err := st.CreateMailbox(ctx, "tok123", "tok123@example.test", "", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}

	if _, err := st.GetMailboxByToken(ctx, mb.Token); err != nil {
		t.Fatalf("GetMailboxByToken: %v", err)
	}
	if _, err := st.GetMailboxByAddress(ctx, "TOK123@example.test"); err != nil {
		t.Fatalf("GetMailboxByAddress case-insensitive: %v", err)
	}
	if _, err := st.GetMailboxByID(ctx, mb.ID); err != nil {
		t.Fatalf("GetMailboxByID: %v", err)
	}

	active, err := st.CountActiveMailboxesByIP(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("CountActiveMailboxesByIP: %v", err)
	}
	if active != 1 {
		t.Fatalf("expected 1 active mailbox, got %d", active)
	}
	activeGlobal, err := st.CountActiveMailboxes(ctx)
	if err != nil {
		t.Fatalf("CountActiveMailboxes: %v", err)
	}
	if activeGlobal != 1 {
		t.Fatalf("expected 1 active mailbox globally, got %d", activeGlobal)
	}

	msg1, err := st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    "alice@example.org",
		RCPTTo:      mb.Address,
		RemoteIP:    "203.0.113.10",
		HELO:        "mx1.example.org",
		ReceivedAt:  time.Now().UTC().Add(-2 * time.Minute),
		RawSource:   "raw-1",
		HeaderBlock: "hdr-1",
		Subject:     "First",
		SizeBytes:   10,
	})
	if err != nil {
		t.Fatalf("SaveMessage #1: %v", err)
	}
	msg2, err := st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    "bob@example.org",
		RCPTTo:      mb.Address,
		RemoteIP:    "203.0.113.20",
		HELO:        "mx2.example.org",
		ReceivedAt:  time.Now().UTC(),
		RawSource:   "raw-2",
		HeaderBlock: "hdr-2",
		Subject:     "Second",
		SizeBytes:   20,
	})
	if err != nil {
		t.Fatalf("SaveMessage #2: %v", err)
	}

	got2, err := st.GetMessage(ctx, msg2.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if got2.Subject != "Second" {
		t.Fatalf("unexpected message subject: %q", got2.Subject)
	}

	list, err := st.ListMessagesByMailbox(ctx, mb.ID, 10)
	if err != nil {
		t.Fatalf("ListMessagesByMailbox: %v", err)
	}
	if len(list) != 2 || list[0].ID != msg2.ID || list[1].ID != msg1.ID {
		t.Fatalf("unexpected message order/list: %#v", list)
	}

	rep, err := st.SaveReport(ctx, model.AnalysisReport{
		MessageID:  msg2.ID,
		CreatedAt:  time.Now().UTC(),
		Score:      7.2,
		ScoreLabel: "Good",
		Checks: []model.CheckResult{
			{ID: "spf", Name: "SPF", Status: "pass", ScoreDelta: 0.4, Summary: "ok"},
		},
		Suggestions: []string{"Set DMARC"},
		RawHeaders:  map[string][]string{"From": {"bob@example.org"}},
		Links:       []string{"https://example.org"},
		SpamSignals: []string{"shortener"},
	})
	if err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
	if rep.ID == 0 {
		t.Fatal("expected report ID to be set")
	}

	// Upsert same message report should keep report reachable with updated score.
	rep.Score = 8.1
	rep.ScoreLabel = "Excellent"
	rep, err = st.SaveReport(ctx, rep)
	if err != nil {
		t.Fatalf("SaveReport upsert: %v", err)
	}
	if rep.ID == 0 {
		t.Fatal("expected upserted report ID to be preserved")
	}

	gotRep, err := st.GetReportByMessageID(ctx, msg2.ID)
	if err != nil {
		t.Fatalf("GetReportByMessageID: %v", err)
	}
	if gotRep.Score != 8.1 || gotRep.ScoreLabel != "Excellent" {
		t.Fatalf("report not updated: %+v", gotRep)
	}

	withReports, err := st.ListMessagesWithReports(ctx, mb.ID, 10)
	if err != nil {
		t.Fatalf("ListMessagesWithReports: %v", err)
	}
	if len(withReports) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(withReports))
	}
	if withReports[0].Report == nil {
		t.Fatal("latest message should have report")
	}
	if withReports[1].Report != nil {
		t.Fatal("older message should not have report")
	}

	if err := st.DeleteMailboxByToken(ctx, mb.Token); err != nil {
		t.Fatalf("DeleteMailboxByToken: %v", err)
	}
	if _, err := st.GetMailboxByToken(ctx, mb.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after mailbox delete, got %v", err)
	}
	if _, err := st.GetMessage(ctx, msg2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected message cascade delete, got %v", err)
	}
}

func TestStoreCleanupKeepsExpiredMailboxUntilRetentionElapsed(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	mb, err := st.CreateMailbox(ctx, "tok-clean", "tok-clean@example.test", "", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}

	oldMsg, err := st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    "a@example.org",
		RCPTTo:      mb.Address,
		RemoteIP:    "203.0.113.1",
		HELO:        "mx.example.org",
		ReceivedAt:  time.Now().UTC().Add(-48 * time.Hour),
		RawSource:   "old",
		HeaderBlock: "old",
		Subject:     "old",
		SizeBytes:   1,
	})
	if err != nil {
		t.Fatalf("SaveMessage old: %v", err)
	}

	newMsg, err := st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    "b@example.org",
		RCPTTo:      mb.Address,
		RemoteIP:    "203.0.113.2",
		HELO:        "mx2.example.org",
		ReceivedAt:  time.Now().UTC(),
		RawSource:   "new",
		HeaderBlock: "new",
		Subject:     "new",
		SizeBytes:   1,
	})
	if err != nil {
		t.Fatalf("SaveMessage new: %v", err)
	}

	// The mailbox stopped accepting mail a minute ago, but the retention window
	// has not elapsed — its reports must stay reachable.
	forceMailboxExpiry(t, st, mb.ID, time.Now().UTC().Add(-time.Minute))

	deletedMailboxes, deletedMessages, err := st.Cleanup(ctx, time.Now().UTC(), 24*time.Hour)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if deletedMailboxes != 0 {
		t.Fatalf("expected the mailbox to survive its expiry, got %d deleted", deletedMailboxes)
	}
	if deletedMessages != 1 {
		t.Fatalf("expected exactly the out-of-retention message to be deleted, got %d", deletedMessages)
	}

	if _, err := st.GetMailboxByID(ctx, mb.ID); err != nil {
		t.Fatalf("expected expired mailbox to be kept within retention, got %v", err)
	}
	if _, err := st.GetMessage(ctx, oldMsg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected old message to be removed, got %v", err)
	}
	if _, err := st.GetMessage(ctx, newMsg.ID); err != nil {
		t.Fatalf("expected recent message to be kept, got %v", err)
	}
}

func TestStoreCleanupDeletesMailboxOnceRetentionElapsed(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	mb, err := st.CreateMailbox(ctx, "tok-gone", "tok-gone@example.test", "", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}

	msg, err := st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    "c@example.org",
		RCPTTo:      mb.Address,
		RemoteIP:    "203.0.113.3",
		HELO:        "mx3.example.org",
		ReceivedAt:  time.Now().UTC(),
		RawSource:   "recent",
		HeaderBlock: "recent",
		Subject:     "recent",
		SizeBytes:   1,
	})
	if err != nil {
		t.Fatalf("SaveMessage: %v", err)
	}

	// Expired longer ago than the retention window — mailbox and everything
	// hanging off it (messages, reports) go.
	forceMailboxExpiry(t, st, mb.ID, time.Now().UTC().Add(-25*time.Hour))

	deletedMailboxes, _, err := st.Cleanup(ctx, time.Now().UTC(), 24*time.Hour)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if deletedMailboxes != 1 {
		t.Fatalf("expected 1 deleted mailbox, got %d", deletedMailboxes)
	}
	if _, err := st.GetMailboxByID(ctx, mb.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mailbox to be removed, got %v", err)
	}
	if _, err := st.GetMessage(ctx, msg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected message to be removed by cascade, got %v", err)
	}
}

func forceMailboxExpiry(t *testing.T, st *Store, id int64, expiresAt time.Time) {
	t.Helper()
	if _, err := st.db.ExecContext(context.Background(),
		`UPDATE mailboxes SET expires_at = ? WHERE id = ?`, expiresAt, id); err != nil {
		t.Fatalf("force expire mailbox: %v", err)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "store.db")
	sqlDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return New(sqlDB)
}
