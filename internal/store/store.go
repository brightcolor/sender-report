package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/brightcolor/sender-report/internal/model"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// CreateMailbox inserts a new mailbox. publicKey is the hex-encoded X25519
// public key supplied by the client (Phase 2+); pass "" for legacy creation.
func (s *Store) CreateMailbox(ctx context.Context, token, address, publicKey, ip string, ttl time.Duration) (model.Mailbox, error) {
	now := time.Now().UTC()
	expires := now.Add(ttl)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO mailboxes(token, address, public_key, created_ip, created_at, expires_at, last_seen_at)
		VALUES(?,?,?,?,?,?,?)
	`, token, address, publicKey, ip, now, expires, now)
	if err != nil {
		return model.Mailbox{}, err
	}
	id, _ := res.LastInsertId()
	return model.Mailbox{
		ID:         id,
		Token:      token,
		Address:    address,
		PublicKey:  publicKey,
		CreatedIP:  ip,
		CreatedAt:  now,
		ExpiresAt:  expires,
		LastSeenAt: now,
	}, nil
}

func (s *Store) CountActiveMailboxesByIP(ctx context.Context, ip string) (int, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM mailboxes WHERE created_ip = ? AND expires_at > ?
	`, ip, time.Now().UTC())
	var c int
	if err := row.Scan(&c); err != nil {
		return 0, err
	}
	return c, nil
}

func (s *Store) CountActiveMailboxes(ctx context.Context) (int, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM mailboxes WHERE expires_at > ?
	`, time.Now().UTC())
	var c int
	if err := row.Scan(&c); err != nil {
		return 0, err
	}
	return c, nil
}

func (s *Store) GetMailboxByToken(ctx context.Context, token string) (model.Mailbox, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token, address, COALESCE(public_key,''), created_ip, created_at, expires_at, last_seen_at
		FROM mailboxes WHERE token = ?
	`, token)
	return scanMailbox(row)
}

func (s *Store) GetMailboxByAddress(ctx context.Context, address string) (model.Mailbox, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token, address, COALESCE(public_key,''), created_ip, created_at, expires_at, last_seen_at
		FROM mailboxes WHERE lower(address) = lower(?)
	`, address)
	return scanMailbox(row)
}

func (s *Store) GetMailboxByID(ctx context.Context, id int64) (model.Mailbox, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token, address, COALESCE(public_key,''), created_ip, created_at, expires_at, last_seen_at
		FROM mailboxes WHERE id = ?
	`, id)
	return scanMailbox(row)
}

func scanMailbox(row *sql.Row) (model.Mailbox, error) {
	var mb model.Mailbox
	if err := row.Scan(&mb.ID, &mb.Token, &mb.Address, &mb.PublicKey, &mb.CreatedIP, &mb.CreatedAt, &mb.ExpiresAt, &mb.LastSeenAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Mailbox{}, ErrNotFound
		}
		return model.Mailbox{}, err
	}
	return mb, nil
}

func (s *Store) TouchMailbox(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mailboxes SET last_seen_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return err
}

func (s *Store) ExtendMailbox(ctx context.Context, token string, newExpiresAt time.Time) (model.Mailbox, error) {
	_, err := s.db.ExecContext(ctx,
		`UPDATE mailboxes SET expires_at = ? WHERE token = ?`,
		newExpiresAt.UTC(), token,
	)
	if err != nil {
		return model.Mailbox{}, err
	}
	return s.GetMailboxByToken(ctx, token)
}

func (s *Store) SaveMessage(ctx context.Context, m model.Message) (model.Message, error) {
	if m.ReceivedAt.IsZero() {
		m.ReceivedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO messages(mailbox_id, smtp_from, rcpt_to, remote_ip, helo, received_at, raw_source, header_block, subject, size_bytes, payload_enc)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
	`, m.MailboxID, m.SMTPFrom, m.RCPTTo, m.RemoteIP, m.HELO, m.ReceivedAt, m.RawSource, m.HeaderBlock, m.Subject, m.SizeBytes, m.PayloadEnc)
	if err != nil {
		return model.Message{}, err
	}
	m.ID, _ = res.LastInsertId()
	return m, nil
}

func (s *Store) GetMessage(ctx context.Context, id int64) (model.Message, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, mailbox_id, smtp_from, rcpt_to, remote_ip, helo, received_at, raw_source, header_block, subject, size_bytes, COALESCE(payload_enc,'')
		FROM messages WHERE id = ?
	`, id)
	return scanMessage(row)
}

func scanMessage(row *sql.Row) (model.Message, error) {
	var m model.Message
	if err := row.Scan(&m.ID, &m.MailboxID, &m.SMTPFrom, &m.RCPTTo, &m.RemoteIP, &m.HELO, &m.ReceivedAt, &m.RawSource, &m.HeaderBlock, &m.Subject, &m.SizeBytes, &m.PayloadEnc); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Message{}, ErrNotFound
		}
		return model.Message{}, err
	}
	return m, nil
}

func (s *Store) ListMessagesByMailbox(ctx context.Context, mailboxID int64, limit int) ([]model.Message, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, mailbox_id, smtp_from, rcpt_to, remote_ip, helo, received_at, raw_source, header_block, subject, size_bytes, COALESCE(payload_enc,'')
		FROM messages WHERE mailbox_id = ? ORDER BY received_at DESC LIMIT ?
	`, mailboxID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.Message, 0)
	for rows.Next() {
		var m model.Message
		if err := rows.Scan(&m.ID, &m.MailboxID, &m.SMTPFrom, &m.RCPTTo, &m.RemoteIP, &m.HELO, &m.ReceivedAt, &m.RawSource, &m.HeaderBlock, &m.Subject, &m.SizeBytes, &m.PayloadEnc); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) SaveReport(ctx context.Context, report model.AnalysisReport) (model.AnalysisReport, error) {
	checksJSON, _ := json.Marshal(report.Checks)
	warningsJSON, _ := json.Marshal(report.Warnings)
	suggestionsJSON, _ := json.Marshal(report.Suggestions)
	headersJSON, _ := json.Marshal(report.RawHeaders)
	linksJSON, _ := json.Marshal(report.Links)
	spamJSON, _ := json.Marshal(report.SpamSignals)

	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now().UTC()
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO reports(message_id, created_at, score, score_label, checks_json, warnings_json, suggestions_json, headers_json, links_json, spam_signals_json)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(message_id) DO UPDATE SET
		created_at=excluded.created_at,
		score=excluded.score,
		score_label=excluded.score_label,
		checks_json=excluded.checks_json,
		warnings_json=excluded.warnings_json,
		suggestions_json=excluded.suggestions_json,
		headers_json=excluded.headers_json,
		links_json=excluded.links_json,
		spam_signals_json=excluded.spam_signals_json
	`, report.MessageID, report.CreatedAt, report.Score, report.ScoreLabel, string(checksJSON), string(warningsJSON), string(suggestionsJSON), string(headersJSON), string(linksJSON), string(spamJSON))
	if err != nil {
		return model.AnalysisReport{}, err
	}
	id, _ := res.LastInsertId()
	if id > 0 {
		report.ID = id
	} else {
		r, err := s.GetReportByMessageID(ctx, report.MessageID)
		if err == nil {
			report.ID = r.ID
		}
	}
	return report, nil
}

func (s *Store) GetReport(ctx context.Context, reportID int64) (model.AnalysisReport, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, message_id, created_at, score, score_label, checks_json, warnings_json, suggestions_json, headers_json, links_json, spam_signals_json
		FROM reports WHERE id = ?
	`, reportID)
	return scanReport(row)
}

func (s *Store) GetReportByMessageID(ctx context.Context, messageID int64) (model.AnalysisReport, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, message_id, created_at, score, score_label, checks_json, warnings_json, suggestions_json, headers_json, links_json, spam_signals_json
		FROM reports WHERE message_id = ?
	`, messageID)
	return scanReport(row)
}

func scanReport(row *sql.Row) (model.AnalysisReport, error) {
	var r model.AnalysisReport
	var checksJSON, warningsJSON, suggestionsJSON, headersJSON, linksJSON, spamJSON string
	if err := row.Scan(&r.ID, &r.MessageID, &r.CreatedAt, &r.Score, &r.ScoreLabel, &checksJSON, &warningsJSON, &suggestionsJSON, &headersJSON, &linksJSON, &spamJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.AnalysisReport{}, ErrNotFound
		}
		return model.AnalysisReport{}, err
	}
	_ = json.Unmarshal([]byte(checksJSON), &r.Checks)
	_ = json.Unmarshal([]byte(warningsJSON), &r.Warnings)
	_ = json.Unmarshal([]byte(suggestionsJSON), &r.Suggestions)
	_ = json.Unmarshal([]byte(headersJSON), &r.RawHeaders)
	_ = json.Unmarshal([]byte(linksJSON), &r.Links)
	_ = json.Unmarshal([]byte(spamJSON), &r.SpamSignals)
	return r, nil
}

// ListMessagesWithReports fetches messages and their reports in a single LEFT JOIN
// query, replacing the previous N+1 query pattern.
func (s *Store) ListMessagesWithReports(ctx context.Context, mailboxID int64, limit int) ([]model.MessageWithReport, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			m.id, m.mailbox_id, m.smtp_from, m.rcpt_to, m.remote_ip, m.helo,
			m.received_at, m.raw_source, m.header_block, m.subject, m.size_bytes,
			COALESCE(m.payload_enc,''),
			r.id, r.created_at, r.score, r.score_label,
			r.checks_json, r.warnings_json, r.suggestions_json,
			r.headers_json, r.links_json, r.spam_signals_json
		FROM messages m
		LEFT JOIN reports r ON r.message_id = m.id
		WHERE m.mailbox_id = ?
		ORDER BY m.received_at DESC
		LIMIT ?
	`, mailboxID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.MessageWithReport
	for rows.Next() {
		var m model.Message
		var rID sql.NullInt64
		var rCreatedAt sql.NullTime
		var rScore sql.NullFloat64
		var rLabel, rChecks, rWarnings, rSuggestions, rHeaders, rLinks, rSpam sql.NullString

		if err := rows.Scan(
			&m.ID, &m.MailboxID, &m.SMTPFrom, &m.RCPTTo, &m.RemoteIP, &m.HELO,
			&m.ReceivedAt, &m.RawSource, &m.HeaderBlock, &m.Subject, &m.SizeBytes,
			&m.PayloadEnc,
			&rID, &rCreatedAt, &rScore, &rLabel,
			&rChecks, &rWarnings, &rSuggestions, &rHeaders, &rLinks, &rSpam,
		); err != nil {
			return nil, err
		}

		mwr := model.MessageWithReport{Message: m}
		if rID.Valid {
			r := model.AnalysisReport{
				ID:         rID.Int64,
				MessageID:  m.ID,
				CreatedAt:  rCreatedAt.Time,
				Score:      rScore.Float64,
				ScoreLabel: rLabel.String,
			}
			_ = json.Unmarshal([]byte(rChecks.String), &r.Checks)
			_ = json.Unmarshal([]byte(rWarnings.String), &r.Warnings)
			_ = json.Unmarshal([]byte(rSuggestions.String), &r.Suggestions)
			_ = json.Unmarshal([]byte(rHeaders.String), &r.RawHeaders)
			_ = json.Unmarshal([]byte(rLinks.String), &r.Links)
			_ = json.Unmarshal([]byte(rSpam.String), &r.SpamSignals)
			mwr.Report = &r
		}
		out = append(out, mwr)
	}
	return out, rows.Err()
}

func (s *Store) DeleteMailboxByToken(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM mailboxes WHERE token = ?`, token)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// GlobalStats holds aggregated platform statistics shown on the home page.
type GlobalStats struct {
	TotalMailboxes  int64   `json:"total_mailboxes"`
	ActiveMailboxes int64   `json:"active_mailboxes"`
	TotalMessages   int64   `json:"total_messages"`
	TotalReports    int64   `json:"total_reports"`
	AvgScore        float64 `json:"avg_score"`
}

// GetGlobalStats returns platform-wide counters from SQLite.
// Uses simple COUNT/AVG queries – fast on typical self-hosted instance sizes.
func (s *Store) GetGlobalStats(ctx context.Context) (GlobalStats, error) {
	var st GlobalStats
	now := time.Now().UTC()

	row := s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(1),
			SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END)
		FROM mailboxes`, now)
	if err := row.Scan(&st.TotalMailboxes, &st.ActiveMailboxes); err != nil {
		return st, err
	}

	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM messages`).Scan(&st.TotalMessages)

	var avgNull sql.NullFloat64
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(1), AVG(score) FROM reports`).
		Scan(&st.TotalReports, &avgNull)
	if avgNull.Valid {
		st.AvgScore = avgNull.Float64
	}
	return st, nil
}

func (s *Store) Cleanup(ctx context.Context, now time.Time, retention time.Duration) (deletedMailboxes, deletedMessages int64, err error) {
	cutoff := now.UTC().Add(-retention)

	resMsg, err := s.db.ExecContext(ctx, `DELETE FROM messages WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, 0, err
	}
	deletedMessages, _ = resMsg.RowsAffected()

	resBox, err := s.db.ExecContext(ctx, `DELETE FROM mailboxes WHERE expires_at < ?`, now.UTC())
	if err != nil {
		return deletedMailboxes, deletedMessages, err
	}
	deletedMailboxes, _ = resBox.RowsAffected()
	return deletedMailboxes, deletedMessages, nil
}
