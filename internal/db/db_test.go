package db

import (
	"path/filepath"
	"testing"
)

// Note: no cgo build tag — the project uses modernc.org/sqlite (pure Go,
// CGO_ENABLED=0), so these tests must run in the default build.

func TestOpenCreatesSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mailprobe.db")
	sqlDB, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer sqlDB.Close()

	tables := []string{"mailboxes", "messages", "reports", "counters"}
	for _, tbl := range tables {
		var name string
		err := sqlDB.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", tbl, err)
		}
	}
}

// TestOpenIdempotent guards against the regression where the counters backfill
// in migrate() used a plain INSERT. Because COUNT(*)/SUM() always return one
// row, the second Open() on an existing database failed with
// "UNIQUE constraint failed: counters.key". Opening repeatedly must succeed and
// leave exactly one row per counter key.
func TestOpenIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	for i := 0; i < 3; i++ {
		db, err := Open(path)
		if err != nil {
			t.Fatalf("Open #%d failed: %v", i+1, err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("Close #%d failed: %v", i+1, err)
		}
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("final Open failed: %v", err)
	}
	defer db.Close()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM counters`).Scan(&n); err != nil {
		t.Fatalf("count counters: %v", err)
	}
	if n != 4 {
		t.Fatalf("expected 4 counter rows after repeated opens, got %d", n)
	}
}

// TestCounterBackfillOnUpgrade simulates upgrading a pre-counters database:
// drop the counters table, add rows to the live tables, reopen, and verify the
// backfill seeds each counter from the current table state.
func TestCounterBackfillOnUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// Simulate the old schema (no counters table) with two existing mailboxes.
	if _, err := db1.Exec(`DROP TABLE counters`); err != nil {
		t.Fatalf("drop counters: %v", err)
	}
	for _, tok := range []string{"a", "b"} {
		if _, err := db1.Exec(`INSERT INTO mailboxes(token, address, created_ip, created_at, expires_at, last_seen_at)
			VALUES(?,?,?,?,?,?)`, tok, tok+"@x.test", "127.0.0.1", "2026-01-01", "2026-01-02", "2026-01-01"); err != nil {
			t.Fatalf("seed mailbox %s: %v", tok, err)
		}
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("close db1: %v", err)
	}

	// Reopen = upgrade. Backfill should seed mailboxes_created from COUNT(*).
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen (upgrade) failed: %v", err)
	}
	defer db2.Close()

	var v float64
	if err := db2.QueryRow(`SELECT value FROM counters WHERE key='mailboxes_created'`).Scan(&v); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if v != 2 {
		t.Fatalf("expected mailboxes_created=2 after backfill, got %v", v)
	}
}
