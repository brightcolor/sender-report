package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	// modernc.org/sqlite registers as "sqlite" (pure Go, no CGO required).
	// DSN parameters like _foreign_keys are mattn-specific and not supported by
	// modernc — set pragmas explicitly via SQL instead.
	dsn := fmt.Sprintf("file:%s", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Apply pragmas that modernc does not honour from the DSN.
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("db pragma %q: %w", p, err)
		}
	}

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    address TEXT NOT NULL UNIQUE,
    created_ip TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mailboxes_token ON mailboxes(token);
CREATE INDEX IF NOT EXISTS idx_mailboxes_expires ON mailboxes(expires_at);
CREATE INDEX IF NOT EXISTS idx_mailboxes_created_ip ON mailboxes(created_ip);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL,
    smtp_from TEXT NOT NULL,
    rcpt_to TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    helo TEXT NOT NULL,
    received_at DATETIME NOT NULL,
    raw_source TEXT NOT NULL,
    header_block TEXT NOT NULL,
    subject TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL UNIQUE,
    created_at DATETIME NOT NULL,
    score REAL NOT NULL,
    score_label TEXT NOT NULL,
    checks_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL,
    suggestions_json TEXT NOT NULL,
    headers_json TEXT NOT NULL,
    links_json TEXT NOT NULL,
    spam_signals_json TEXT NOT NULL,
    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reports_message_id ON reports(message_id);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// Phase-2 migration: add public_key column (idempotent).
	_, _ = db.Exec(`ALTER TABLE mailboxes ADD COLUMN public_key TEXT`)
	// Phase-3 migration: add payload_enc column to messages for E2E encryption.
	_, _ = db.Exec(`ALTER TABLE messages ADD COLUMN payload_enc TEXT`)

	// Phase-5 migration: cumulative counters that survive cleanup and expiry.
	// Unlike COUNT(*) over the live tables (which shrinks when rows are deleted),
	// these values only ever increase — one tick per creation event.
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS counters (
    key   TEXT PRIMARY KEY,
    value REAL NOT NULL DEFAULT 0
);`); err != nil {
		return err
	}
	// One-time backfill: seed each counter from the current table state so the
	// switch from live COUNT(*) to cumulative counters is seamless. The
	// NOT EXISTS guard makes this idempotent — it runs once, then no-ops.
	backfill := []string{
		`INSERT INTO counters(key, value) SELECT 'mailboxes_created', COUNT(*) FROM mailboxes
		   WHERE NOT EXISTS(SELECT 1 FROM counters WHERE key='mailboxes_created')`,
		`INSERT INTO counters(key, value) SELECT 'messages_received', COUNT(*) FROM messages
		   WHERE NOT EXISTS(SELECT 1 FROM counters WHERE key='messages_received')`,
		`INSERT INTO counters(key, value) SELECT 'reports_generated', COUNT(*) FROM reports
		   WHERE NOT EXISTS(SELECT 1 FROM counters WHERE key='reports_generated')`,
		`INSERT INTO counters(key, value) SELECT 'score_sum', COALESCE(SUM(score),0) FROM reports
		   WHERE NOT EXISTS(SELECT 1 FROM counters WHERE key='score_sum')`,
	}
	for _, q := range backfill {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}
