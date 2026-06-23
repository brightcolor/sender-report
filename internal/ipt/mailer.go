package ipt

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// MailerConfig holds outbound SMTP settings for IPT alert emails.
type MailerConfig struct {
	Addr           string // host:port — port 465 uses implicit TLS, all others use STARTTLS
	From           string // envelope + From header
	User, Pass     string // SMTP AUTH (optional)
	IncludeRawErrs bool   // embed raw IMAP error strings in the email body
}

// Mailer sends IPT health-alert emails.
type Mailer struct{ cfg MailerConfig }

func NewMailer(cfg MailerConfig) *Mailer { return &Mailer{cfg: cfg} }

// Enabled returns true when both Addr and From are configured.
func (m *Mailer) Enabled() bool {
	return m != nil && m.cfg.Addr != "" && m.cfg.From != ""
}

// SendIPTAlert sends one email listing all failed AccountStatus entries.
// If IncludeRawErrs is true the raw IMAP error text is included.
func (m *Mailer) SendIPTAlert(to string, failed []AccountStatus) error {
	if !m.Enabled() || len(failed) == 0 || to == "" {
		return nil
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	var body bytes.Buffer
	body.WriteString("From: sender.report <" + m.cfg.From + ">\r\n")
	body.WriteString("To: " + to + "\r\n")
	body.WriteString("Subject: [sender.report] IPT seed account failure (" + fmt.Sprintf("%d", len(failed)) + " account(s))\r\n")
	body.WriteString("MIME-Version: 1.0\r\n")
	body.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	body.WriteString("\r\n")
	body.WriteString("sender.report – Inbox Placement Testing alert\r\n")
	body.WriteString("Checked: " + now + "\r\n")
	body.WriteString(strings.Repeat("-", 60) + "\r\n\r\n")
	body.WriteString(fmt.Sprintf("%d seed account(s) failed connectivity/auth check:\r\n\r\n", len(failed)))

	for _, s := range failed {
		body.WriteString(fmt.Sprintf("  Provider : %s\r\n", s.Provider))
		body.WriteString(fmt.Sprintf("  Account  : %s\r\n", s.User))
		body.WriteString(fmt.Sprintf("  IMAP     : %s\r\n", s.IMAP))
		body.WriteString(fmt.Sprintf("  Checked  : %s\r\n", s.CheckedAt.Format("2006-01-02 15:04:05 UTC")))
		if m.cfg.IncludeRawErrs && s.ErrRaw != "" {
			body.WriteString(fmt.Sprintf("  Error    : %s\r\n", s.ErrRaw))
		}
		body.WriteString("\r\n")
	}

	body.WriteString(strings.Repeat("-", 60) + "\r\n")
	body.WriteString("Action: check the account credentials and IMAP host in seeds.json.\r\n")
	body.WriteString("Users selecting these providers will see them as unavailable.\r\n")

	return m.send(to, body.Bytes())
}

func (m *Mailer) send(to string, msg []byte) error {
	host, port, err := net.SplitHostPort(m.cfg.Addr)
	if err != nil {
		return fmt.Errorf("ipt mailer: invalid SMTP addr %q: %w", m.cfg.Addr, err)
	}

	var auth smtp.Auth
	if m.cfg.User != "" {
		auth = smtp.PlainAuth("", m.cfg.User, m.cfg.Pass, host)
	}

	if port == "465" {
		// Implicit TLS (SMTPS).
		tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		conn, err := tls.Dial("tcp", m.cfg.Addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("ipt mailer: TLS dial: %w", err)
		}
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("ipt mailer: SMTP client: %w", err)
		}
		defer c.Quit()
		if auth != nil {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("ipt mailer: SMTP auth: %w", err)
			}
		}
		return sendViaClient(c, m.cfg.From, to, msg)
	}

	// STARTTLS (port 587 or plain 25).
	c, err := smtp.Dial(m.cfg.Addr)
	if err != nil {
		return fmt.Errorf("ipt mailer: dial: %w", err)
	}
	defer c.Quit()
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("ipt mailer: STARTTLS: %w", err)
		}
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("ipt mailer: SMTP auth: %w", err)
		}
	}
	return sendViaClient(c, m.cfg.From, to, msg)
}

func sendViaClient(c *smtp.Client, from, to string, msg []byte) error {
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}
