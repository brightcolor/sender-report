package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brightcolor/sender-report/internal/analyzer"
	"github.com/brightcolor/sender-report/internal/cleanup"
	"github.com/brightcolor/sender-report/internal/statsfiles"
	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/envmigrate"
	"github.com/brightcolor/sender-report/internal/db"
	"github.com/brightcolor/sender-report/internal/model"
	"github.com/brightcolor/sender-report/internal/ratelimit"
	"github.com/brightcolor/sender-report/internal/sealedbox"
	"github.com/brightcolor/sender-report/internal/smtp"
	"github.com/brightcolor/sender-report/internal/store"
	"github.com/brightcolor/sender-report/internal/telemetry"
	"github.com/brightcolor/sender-report/internal/tlscert"
	"github.com/brightcolor/sender-report/internal/web"
)

func main() {
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slogLogger := slog.New(slogHandler)
	logger := slog.NewLogLogger(slogHandler, slog.LevelInfo)

	// Env migration: append any missing variables to the mounted .env before
	// loading config so that operators see them on the very next restart.
	if envFile := strings.TrimSpace(os.Getenv("ENV_FILE")); envFile != "" {
		added, migrateErr := envmigrate.MigrateFile(envFile)
		if migrateErr != nil {
			slogLogger.Warn("env migration failed", "file", envFile, "error", migrateErr)
		} else if len(added) > 0 {
			slogLogger.Info("env migration: new variables appended to .env — review and restart to apply",
				"file", envFile, "count", len(added), "vars", added)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		slogLogger.Error("config error", "error", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		slogLogger.Error("data dir error", "error", err)
		os.Exit(1)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		slogLogger.Error("db open error", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	st := store.New(database)
	metrics := telemetry.New()
	alerter := telemetry.NewAlerter(cfg.AlertWebhookURL)
	engine := analyzer.New(analyzer.Options{
		EnableRBLChecks:      cfg.EnableRBLChecks,
		RBLProviders:         cfg.RBLProviders,
		EnableSpamAssassin:   cfg.EnableSpamAssassin,
		SpamAssassinHostPort: cfg.SpamAssassinHostPort,
		EnableRspamd:         cfg.EnableRspamd,
		RspamdURL:            cfg.RspamdURL,
		RspamdPassword:       cfg.RspamdPassword,
		EnableDomainAge:          cfg.EnableDomainAge,
		EnableDomainBlocklist:    cfg.EnableDomainBlocklist,
		DomainBlocklistProviders: cfg.DomainBlocklistProviders,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cleanup.Start(ctx, logger, st, cfg.CleanupInterval, cfg.RetentionTTL)
	statsfiles.StartWriter(ctx, logger, st, cfg.DataDir)

	webServer, err := web.New(cfg, st, logger, metrics)
	if err != nil {
		slogLogger.Error("web init error", "error", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTPListenAddr,
		Handler:           webServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	smtpLimiter := ratelimit.New(time.Hour, cfg.SMTPRateLimitPerHour)
	smtpBurstLimiter := ratelimit.New(time.Minute, cfg.SMTPBurstPerMin)
	// STARTTLS-Zertifikat: beim ersten Start generieren, danach wiederverwenden.
	smtpTLS, tlsErr := tlscert.EnsureAndLoad(cfg.DataDir, smtpGreetingDomain(cfg), logger)
	if tlsErr != nil {
		logger.Printf("smtp: TLS-Zertifikat nicht verfügbar (%v) — STARTTLS deaktiviert", tlsErr)
		smtpTLS = nil
	}

	smtpSrv := &smtp.Server{
		Addr:            cfg.SMTPListenAddr,
		Domain:          smtpGreetingDomain(cfg),
		MaxMessageBytes: cfg.MaxMessageBytes,
		TLSConfig:       smtpTLS,
		RateLimiter:     smtpLimiter,
		BurstLimiter:    smtpBurstLimiter,
		OnRateLimited: func(remoteIP string) {
			metrics.IncSMTPRateLimited()
			logger.Printf("smtp rate limited remote_ip=%s", remoteIP)
		},
		Logger: logger,
		AllowRecipient: func(ctx context.Context, rcpt string) bool {
			return isAllowedRecipient(ctx, st, cfg, rcpt)
		},
		HandleMail: func(ctx context.Context, rm smtp.ReceivedMail) error {
			if err := processInbound(ctx, st, engine, cfg, logger, metrics, alerter, rm); err != nil {
				metrics.IncInboundErrors()
				_ = alerter.Send(ctx, "error", "inbound_processing_failed", "Inbound processing failed", map[string]any{
					"remote_ip": rm.RemoteIP,
					"mail_from": rm.MailFrom,
					"rcpt_to":   rm.RcptTo,
					"error":     err.Error(),
				})
				return err
			}
			return nil
		},
	}

	errCh := make(chan error, 2)
	go func() {
		var err error
		if cfg.EnableTLS {
			slogLogger.Info("https listening", "addr", cfg.HTTPListenAddr, "cert", cfg.TLSCertFile)
			err = httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			slogLogger.Info("http listening", "addr", cfg.HTTPListenAddr)
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	go func() {
		if err := smtpSrv.Start(ctx); err != nil && ctx.Err() == nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slogLogger.Info("shutdown signal received")
	case err := <-errCh:
		slogLogger.Error("fatal service error", "error", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	cancel()
	smtpSrv.Wait()
	slogLogger.Info("shutdown complete")
}

func processInbound(ctx context.Context, st *store.Store, engine *analyzer.Engine, cfg config.Config, logger *log.Logger, metrics *telemetry.Counters, alerter *telemetry.Alerter, rm smtp.ReceivedMail) error {
	rcpt := strings.ToLower(strings.TrimSpace(rm.RcptTo))
	if !matchesConfiguredDomain(cfg, rcpt) {
		return nil
	}
	mb, err := st.GetMailboxByAddress(ctx, rcpt)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if time.Now().UTC().After(mb.ExpiresAt) {
		return nil
	}

	raw := string(rm.Data)
	raw = enrichWithReceiverAuthHeaders(ctx, cfg, rm, raw)
	headers := headerBlock(raw)
	subject := headerField(headers, "Subject")

	// Phase 3: run analysis on plaintext before any encryption.
	// The analyzer needs cleartext; we encrypt only at storage time.
	tmpMsg := model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    rm.MailFrom,
		RCPTTo:      rcpt,
		RemoteIP:    rm.RemoteIP,
		HELO:        rm.HELO,
		ReceivedAt:  time.Now().UTC(),
		RawSource:   raw,
		HeaderBlock: headers,
		Subject:     subject,
		SizeBytes:   int64(len(rm.Data)),
	}
	report := engine.Analyze(ctx, analyzer.Input{Message: tmpMsg, SMTPDomain: cfg.SMTPDomain})

	// Phase 3: if the mailbox has an E2E public key, encrypt all sensitive content
	// into a single sealed payload and clear the plaintext fields before storage.
	storeMsg := tmpMsg
	if mb.PublicKey != "" {
		pubBytes, hexErr := hex.DecodeString(mb.PublicKey)
		if hexErr == nil && len(pubBytes) == 32 {
			payload, encErr := buildEncryptedPayload(raw, headers, subject, tmpMsg, report, pubBytes)
			if encErr == nil {
				storeMsg.PayloadEnc  = payload
				storeMsg.RawSource   = "[encrypted]"
				storeMsg.HeaderBlock = "[encrypted]"
				storeMsg.Subject     = "[encrypted]"
				storeMsg.SMTPFrom    = "[encrypted]"
				storeMsg.RemoteIP    = "[encrypted]"
				storeMsg.HELO        = "[encrypted]"
				storeMsg.ReceivedAt  = time.Time{} // zero — real time in payload
				// Strip sensitive check details; keep score cleartext via report.Score.
				report = stripReportForStorage(report)
			} else {
				logger.Printf("smtp: encryption failed mailbox=%s: %v — storing plaintext", mb.Token, encErr)
			}
		}
	}

	msg, err := st.SaveMessage(ctx, storeMsg)
	if err != nil {
		return err
	}
	report.MessageID = msg.ID
	metrics.IncMailsReceived()

	if _, err := st.SaveReport(ctx, report); err != nil {
		metrics.IncAnalyzerErrors()
		logger.Printf("analyze/store report error msg=%d: %v", msg.ID, err)
		_ = alerter.Send(ctx, "warn", "report_store_failed", "Analyzer report persistence failed", map[string]any{
			"message_id": msg.ID,
			"mailbox_id": mb.ID,
			"error":      err.Error(),
		})
	} else {
		metrics.IncReportsGenerated()
	}
	_ = st.TouchMailbox(ctx, mb.ID)
	logger.Printf("smtp: received message mailbox=%s msg=%d size=%d encrypted=%v", mb.Token, msg.ID, len(rm.Data), storeMsg.PayloadEnc != "")
	return nil
}

// encryptedPayload is the JSON structure sealed into messages.payload_enc.
type encryptedPayload struct {
	RawSource   string               `json:"raw_source"`
	HeaderBlock string               `json:"header_block"`
	Subject     string               `json:"subject"`
	SMTPFrom    string               `json:"smtp_from"`
	RemoteIP    string               `json:"remote_ip"`
	HELO        string               `json:"helo"`
	ReceivedAt  string               `json:"received_at"` // RFC3339
	Report      model.AnalysisReport `json:"report"`
}

// buildEncryptedPayload seals all sensitive message + report content with the
// mailbox public key. Returns a base64url-encoded sealed blob (no padding).
// base64url uses ~33% less space than hex and matches the JS _fromBase64url helper.
func buildEncryptedPayload(raw, headers, subject string, msg model.Message, report model.AnalysisReport, pubKey []byte) (string, error) {
	p := encryptedPayload{
		RawSource:   raw,
		HeaderBlock: headers,
		Subject:     subject,
		SMTPFrom:    msg.SMTPFrom,
		RemoteIP:    msg.RemoteIP,
		HELO:        msg.HELO,
		ReceivedAt:  msg.ReceivedAt.Format(time.RFC3339),
		Report:      report,
	}
	plainJSON, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	blob, err := sealedbox.Seal(plainJSON, pubKey)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

// stripReportForStorage removes sensitive check details from the report before
// it is stored in cleartext. Score + score_label are preserved for display.
func stripReportForStorage(r model.AnalysisReport) model.AnalysisReport {
	stripped := model.AnalysisReport{
		ID:         r.ID,
		MessageID:  r.MessageID,
		CreatedAt:  r.CreatedAt,
		Score:      r.Score,
		ScoreLabel: r.ScoreLabel,
	}
	// Keep minimal check status for the summary badges (pass/warn/fail counts).
	for _, c := range r.Checks {
		stripped.Checks = append(stripped.Checks, model.CheckResult{
			ID:     c.ID,
			Name:   c.Name,
			Status: c.Status,
			// ScoreDelta, Summary, Explanation, Recommendation, TechnicalDetails → encrypted
		})
	}
	return stripped
}

func isAllowedRecipient(ctx context.Context, st *store.Store, cfg config.Config, rcpt string) bool {
	rcpt = strings.ToLower(strings.TrimSpace(rcpt))
	if !matchesConfiguredDomain(cfg, rcpt) {
		return false
	}
	mb, err := st.GetMailboxByAddress(ctx, rcpt)
	if err != nil {
		return false
	}
	return time.Now().UTC().Before(mb.ExpiresAt)
}

func matchesConfiguredDomain(cfg config.Config, rcpt string) bool {
	domain := strings.ToLower(strings.TrimSpace(cfg.SMTPDomain))
	if domain == "" {
		return true
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(rcpt)), "@"+domain)
}

func smtpGreetingDomain(cfg config.Config) string {
	if domain := strings.TrimSpace(cfg.SMTPDomain); domain != "" {
		return domain
	}
	return "sender-report.local"
}

func headerBlock(raw string) string {
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.SplitN(norm, "\n\n", 2)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func headerField(headerBlock, key string) string {
	lines := strings.Split(headerBlock, "\n")
	prefix := strings.ToLower(key) + ":"
	for i, l := range lines {
		line := strings.TrimRight(l, "\r")
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), prefix) {
			value := strings.TrimSpace(line[len(prefix):])
			for _, next := range lines[i+1:] {
				next = strings.TrimRight(next, "\r")
				if !strings.HasPrefix(next, " ") && !strings.HasPrefix(next, "\t") {
					break
				}
				value += " " + strings.TrimSpace(next)
			}
			decoded, err := new(mime.WordDecoder).DecodeHeader(value)
			if err == nil {
				return strings.TrimSpace(decoded)
			}
			return strings.TrimSpace(value)
		}
	}
	return ""
}
