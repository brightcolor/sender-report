package analyzer

import (
	"io"
	"net/mail"
	"strings"
	"testing"
)

// buildMail turns a raw message into the (header, body) pair inspectBody takes.
func buildMail(t *testing.T, raw string) (mail.Header, []byte) {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("could not parse test mail: %v", err)
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatalf("could not read body: %v", err)
	}
	return msg.Header, body
}

// TestNestedMIMEIsUnpacked covers the two most common real-world layouts. Before
// the parser recursed, neither produced any HTML at all — so every HTML-based
// check reported all-clear on an empty string.
//
// Remove the multipart branch from walkMIMEParts and both subtests turn red.
func TestNestedMIMEIsUnpacked(t *testing.T) {
	t.Run("mixed wrapping alternative (mail with an attachment)", func(t *testing.T) {
		raw := "From: a@example.org\r\n" +
			"Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n" +
			"\r\n" +
			"--OUTER\r\n" +
			"Content-Type: multipart/alternative; boundary=\"INNER\"\r\n" +
			"\r\n" +
			"--INNER\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"\r\n" +
			"Guten Tag, hier ist der Text.\r\n" +
			"--INNER\r\n" +
			"Content-Type: text/html; charset=utf-8\r\n" +
			"\r\n" +
			"<html><body><p>Guten Tag</p><img src=\"cid:logo\"></body></html>\r\n" +
			"--INNER--\r\n" +
			"--OUTER\r\n" +
			"Content-Type: application/pdf; name=\"Rechnung.pdf\"\r\n" +
			"Content-Disposition: attachment; filename=\"Rechnung.pdf\"\r\n" +
			"\r\n" +
			"%PDF-1.4 fake\r\n" +
			"--OUTER--\r\n"

		_, pb := inspectBody(buildMail(t, raw))

		if !pb.HasHTMLPart {
			t.Error("HasHTMLPart = false — the HTML part inside the nested alternative was dropped")
		}
		if !strings.Contains(pb.HTML, "Guten Tag") {
			t.Errorf("HTML body not collected, got %q", pb.HTML)
		}
		if !pb.HasTextPart {
			t.Error("HasTextPart = false — the plain text part was dropped")
		}
		if pb.Attachments != 1 {
			t.Errorf("Attachments = %d, want 1", pb.Attachments)
		}
		if pb.Images != 1 {
			t.Errorf("Images = %d, want 1", pb.Images)
		}
		if pb.Charset != "utf-8" {
			t.Errorf("Charset = %q, want utf-8 — in multipart mail the charset lives on the parts", pb.Charset)
		}
	})

	t.Run("alternative wrapping related (HTML with embedded images)", func(t *testing.T) {
		raw := "From: a@example.org\r\n" +
			"Content-Type: multipart/alternative; boundary=\"ALT\"\r\n" +
			"\r\n" +
			"--ALT\r\n" +
			"Content-Type: text/plain; charset=iso-8859-1\r\n" +
			"\r\n" +
			"Nur Text.\r\n" +
			"--ALT\r\n" +
			"Content-Type: multipart/related; boundary=\"REL\"\r\n" +
			"\r\n" +
			"--REL\r\n" +
			"Content-Type: text/html; charset=utf-8\r\n" +
			"\r\n" +
			"<html><body><a href=\"https://example.org/x\">Link</a><img src=\"cid:a\"><img src=\"cid:b\"></body></html>\r\n" +
			"--REL\r\n" +
			"Content-Type: image/png; name=\"logo.png\"\r\n" +
			"\r\n" +
			"PNGDATA\r\n" +
			"--REL--\r\n" +
			"--ALT--\r\n"

		_, pb := inspectBody(buildMail(t, raw))

		if !pb.HasHTMLPart {
			t.Error("HasHTMLPart = false — the HTML inside multipart/related was dropped")
		}
		if !strings.Contains(pb.HTML, "example.org/x") {
			t.Errorf("HTML body not collected, got %q", pb.HTML)
		}
		if pb.Images != 2 {
			t.Errorf("Images = %d, want 2", pb.Images)
		}
		if pb.Charset != "iso-8859-1" {
			t.Errorf("Charset = %q, want iso-8859-1 (first declaring part wins)", pb.Charset)
		}
	})

	t.Run("flat multipart still works", func(t *testing.T) {
		raw := "From: a@example.org\r\n" +
			"Content-Type: multipart/alternative; boundary=\"B\"\r\n" +
			"\r\n" +
			"--B\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"Text\r\n" +
			"--B\r\n" +
			"Content-Type: text/html\r\n" +
			"\r\n" +
			"<p>HTML</p>\r\n" +
			"--B--\r\n"

		_, pb := inspectBody(buildMail(t, raw))

		if !pb.HasTextPart || !pb.HasHTMLPart {
			t.Errorf("flat multipart broke: text=%v html=%v", pb.HasTextPart, pb.HasHTMLPart)
		}
		if pb.PartCount != 2 {
			t.Errorf("PartCount = %d, want 2", pb.PartCount)
		}
	})

	t.Run("deep nesting terminates", func(t *testing.T) {
		// Well past maxMIMEDepth: the parser must stop, not recurse or hang.
		var b strings.Builder
		b.WriteString("From: a@example.org\r\nContent-Type: multipart/mixed; boundary=\"L0\"\r\n\r\n")
		const levels = 30
		for i := 0; i < levels; i++ {
			b.WriteString("--L" + itoa(i) + "\r\nContent-Type: multipart/mixed; boundary=\"L" + itoa(i+1) + "\"\r\n\r\n")
		}
		b.WriteString("--L" + itoa(levels) + "\r\nContent-Type: text/plain\r\n\r\ndeep\r\n--L" + itoa(levels) + "--\r\n")
		for i := levels - 1; i >= 0; i-- {
			b.WriteString("--L" + itoa(i) + "--\r\n")
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = inspectBody(buildMail(t, b.String()))
		}()
		<-done
	})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
