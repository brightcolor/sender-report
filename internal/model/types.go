package model

import "time"

type Mailbox struct {
	ID         int64
	Token      string
	Address    string
	PublicKey  string // hex-encoded X25519 public key; empty for legacy mailboxes
	CreatedIP  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	// Per-mailbox opt-in for third-party reputation checks (group C). Chosen by
	// the user on the home page; default false. See analyzer.Input.
	CheckDomainAge       bool
	CheckDomainBlocklist bool
}

type Message struct {
	ID          int64
	MailboxID   int64
	SMTPFrom    string
	RCPTTo      string
	RemoteIP    string
	HELO        string
	ReceivedAt  time.Time
	RawSource   string
	HeaderBlock string
	Subject     string
	SizeBytes   int64
	PayloadEnc  string // hex-encoded sealed blob (Phase 3); empty for legacy messages
}

// Encrypted returns true if the message content is E2E-encrypted.
func (m *Message) Encrypted() bool { return m.PayloadEnc != "" }

// DocLink is a labelled reference shown below a check recommendation.
type DocLink struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type CheckResult struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Status           string            `json:"status"`
	ScoreDelta       float64           `json:"score_delta"`
	Summary          string            `json:"summary"`
	Suggestion       string            `json:"suggestion"`
	TechnicalDetails map[string]string `json:"technical_details,omitempty"`
	Explanation      string            `json:"explanation,omitempty"`
	Recommendation   string            `json:"recommendation,omitempty"`
	DocLinks         []DocLink         `json:"doc_links,omitempty"`
	Severity         string            `json:"severity,omitempty"`
	Category         string            `json:"category,omitempty"`
	Importance       string            `json:"importance,omitempty"` // Kritisch | Wichtig | Empfohlen | Optional

	// English variants — populated by the analyzer so reports can be rendered
	// in English without re-analysis. Empty for legacy/pre-i18n reports.
	NameEN           string `json:"name_en,omitempty"`
	SummaryEN        string `json:"summary_en,omitempty"`
	ExplanationEN    string `json:"explanation_en,omitempty"`
	RecommendationEN string `json:"recommendation_en,omitempty"`
}

type AnalysisReport struct {
	ID          int64               `json:"id"`
	MessageID   int64               `json:"message_id"`
	CreatedAt   time.Time           `json:"created_at"`
	Score       float64             `json:"score"`
	ScoreLabel  string              `json:"score_label"`
	MailType    string              `json:"mail_type,omitempty"` // "personal" | "transactional" | "bulk" | "unknown"
	Checks      []CheckResult       `json:"checks"`
	Warnings    []string            `json:"warnings"`
	Suggestions []string            `json:"suggestions"`
	RawHeaders  map[string][]string `json:"raw_headers"`
	Links       []string            `json:"links"`
	SpamSignals []string            `json:"spam_signals"`
}

type MessageWithReport struct {
	Message Message
	Report  *AnalysisReport
}
