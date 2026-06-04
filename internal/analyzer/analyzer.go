package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/miekg/dns"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"

	"github.com/brightcolor/sender-report/internal/model"
)

type Options struct {
	EnableRBLChecks      bool
	RBLProviders         []string
	EnableSpamAssassin   bool
	SpamAssassinHostPort string
	EnableRspamd         bool
	RspamdURL            string
	RspamdPassword       string
	// Group C — opt-in third-party reputation checks (off by default).
	EnableDomainAge          bool
	EnableDomainBlocklist    bool
	DomainBlocklistProviders []string
}

type Input struct {
	Message    model.Message
	SMTPDomain string
	// Per-request opt-in for third-party reputation checks (group C). These are
	// chosen by the individual user on the home page and stored on the mailbox.
	// They are OR-combined with the operator-level Options defaults, so an
	// operator can force a check on globally while users can additionally enable
	// it for their own mailbox.
	EnableDomainAge       bool
	EnableDomainBlocklist bool
}

type Engine struct {
	opts Options
}

func New(opts Options) *Engine {
	return &Engine{opts: opts}
}

// RecheckInput carries the minimal, externally-observable data a single check
// needs to be re-run on demand (after the operator fixed a DNS record), without
// re-sending a mail. It is supplied by the client from the decrypted report.
type RecheckInput struct {
	FromDomain     string
	EnvelopeDomain string
	ReturnDomain   string
	RemoteIP       string
	HELO           string
	DKIMSignature  string
	Links          []string
}

// Recheckable reports whether a check ID can be re-run live. These are the
// DNS/RDAP/blocklist-based checks. The core SPF/DKIM/DMARC *verdicts* verify the
// original message and can't be re-derived without it, so only their DNS-record
// aspects (SPF/DMARC record presence) are offered for recheck; DKIM falls back to
// its key-length check.
func Recheckable(id string) bool {
	switch id {
	case "spf", "dmarc", "mx_records", "address_records", "dkim_keylength",
		"envelope_mx", "mta_sts", "tls_rpt", "bimi", "dnssec", "dane_tlsa",
		"ptr", "ptr_pattern", "domain_age", "domain_blocklist", "link_blocklist":
		return true
	}
	return false
}

// Recheck re-runs a single external-dependent check and returns the fresh,
// enriched result. ok=false for unsupported IDs.
func (e *Engine) Recheck(ctx context.Context, id string, in RecheckInput) (res model.CheckResult, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			res, ok = errorCheck(id, fmt.Sprintf("%v", r)), true
		}
	}()

	primary := firstNonEmpty(in.FromDomain, in.EnvelopeDomain)
	switch id {
	case "spf":
		res = spfRecordRecheck(ctx, firstNonEmpty(in.EnvelopeDomain, in.FromDomain))
	case "dmarc":
		res = dmarcRecordRecheck(ctx, in.FromDomain)
	case "mx_records":
		res = mxRecordCheck(ctx, primary)
	case "address_records":
		res = addressRecordCheck(ctx, primary)
	case "dkim_keylength":
		res = dkimKeyLengthCheck(ctx, in.DKIMSignature)
	case "envelope_mx":
		res = envelopeBounceMXCheck(ctx, firstNonEmpty(in.ReturnDomain, in.EnvelopeDomain))
	case "mta_sts":
		res = mtaStsCheck(ctx, primary)
	case "tls_rpt":
		res = tlsRptCheck(ctx, primary)
	case "bimi":
		res = bimiCheck(ctx, primary)
	case "dnssec":
		res = dnssecCheck(ctx, primary)
	case "dane_tlsa":
		res = daneCheck(ctx, primary)
	case "ptr":
		res = ptrPlausibility(ctx, in.RemoteIP, in.HELO)
	case "ptr_pattern":
		res = ptrPatternCheck(ctx, in.RemoteIP)
	case "domain_age":
		res = domainAgeCheck(ctx, primary)
	case "domain_blocklist":
		res = domainBlocklistCheck(ctx, primary, e.opts.DomainBlocklistProviders)
	case "link_blocklist":
		res = linkBlocklistCheck(ctx, in.Links, e.opts.DomainBlocklistProviders)
	default:
		return model.CheckResult{}, false
	}
	res = enrichCheckResult(res, checkContext{
		FromDomain:     in.FromDomain,
		EnvelopeDomain: in.EnvelopeDomain,
		ReturnDomain:   in.ReturnDomain,
		Links:          in.Links,
		Message:        model.Message{RemoteIP: in.RemoteIP, HELO: in.HELO},
	})
	return res, true
}

// spfRecordRecheck re-looks up the SPF TXT record (used after a DNS fix). It
// reports record presence/strictness; the actual SPF pass against the sending IP
// is only verified when a real mail is received.
func spfRecordRecheck(ctx context.Context, domain string) model.CheckResult {
	domain = normDomain(domain)
	if domain == "" {
		return info("spf", "SPF", 0, "Keine Domain für den SPF-Recheck ermittelbar.", "")
	}
	recs, _ := net.DefaultResolver.LookupTXT(ctx, domain)
	spf := ""
	for _, r := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=spf1") {
			spf = strings.TrimSpace(r)
		}
	}
	if spf == "" {
		return info("spf", "SPF", 0, fmt.Sprintf("Kein SPF-Record (v=spf1) für %s gefunden.", domain), "TXT-Record mit v=spf1 auf der Envelope-From-Domain veröffentlichen.")
	}
	return pass("spf", "SPF", 0, fmt.Sprintf("SPF-Record für %s vorhanden: %s. Der tatsächliche SPF-Pass wird beim nächsten echten Versand gegen die sendende IP geprüft.", domain, spf), "")
}

// dmarcRecordRecheck re-looks up the _dmarc TXT record (used after a DNS fix).
func dmarcRecordRecheck(ctx context.Context, fromDomain string) model.CheckResult {
	fromDomain = normDomain(fromDomain)
	if fromDomain == "" {
		return info("dmarc", "DMARC", 0, "Keine From-Domain für den DMARC-Recheck ermittelbar.", "")
	}
	recs, _ := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+fromDomain)
	policy := ""
	found := false
	for _, r := range recs {
		lr := strings.ToLower(strings.TrimSpace(r))
		if strings.HasPrefix(lr, "v=dmarc1") {
			found = true
			policy = extractTagValue(lr, "p")
		}
	}
	if !found {
		return fail("dmarc", "DMARC", 0, fmt.Sprintf("Kein DMARC-Record für %s gefunden.", fromDomain), "_dmarc."+fromDomain+" TXT mit v=DMARC1 veröffentlichen.")
	}
	return pass("dmarc", "DMARC", 0, fmt.Sprintf("DMARC-Record für %s gefunden (p=%s). Das vollständige Alignment wird beim nächsten echten Versand geprüft.", fromDomain, emptyFallback(policy, "none")), "")
}

func (e *Engine) Analyze(ctx context.Context, in Input) (report model.AnalysisReport) {
	report = model.AnalysisReport{
		MessageID:  in.Message.ID,
		CreatedAt:  time.Now().UTC(),
		Score:      10.0,
		RawHeaders: map[string][]string{},
	}

	// Bound the whole analysis so a slow or unreachable DNS / third-party service
	// can never hang the SMTP worker indefinitely.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Safety net: a panic in any single check (e.g. an unexpected parse edge case)
	// must never crash the process or drop the message. Recover, record an error
	// check, and finalise a valid (partial) report.
	defer func() {
		if r := recover(); r != nil {
			report.Checks = append(report.Checks, errorCheck("analyze", fmt.Sprintf("%v", r)))
			report.Score = 10.0
			for _, c := range report.Checks {
				report.Score += c.ScoreDelta
			}
			report.Score = clampScore(report.Score)
			assignLabel(&report)
		}
	}()

	parsed, parseErr := mail.ReadMessage(strings.NewReader(in.Message.RawSource))
	if parseErr != nil {
		parseCheck := fail("mime_parse", "MIME/Message Parsing", -2.0, "Rohmail konnte nicht korrekt geparst werden.", "Sende eine RFC-konforme MIME-Mail und prüfe den Mailer.")
		parseCheck.Category = "Header und Rohdaten"
		parseCheck.Severity = "high"
		parseCheck.TechnicalDetails = map[string]string{
			"remote_ip":   emptyFallback(in.Message.RemoteIP, "unknown"),
			"helo_ehlo":   emptyFallback(in.Message.HELO, "unknown"),
			"raw_bytes":   strconv.Itoa(len(in.Message.RawSource)),
			"parse_error": parseErr.Error(),
		}
		parseCheck.Explanation = "Eine RFC-konforme Message-Struktur ist Voraussetzung für alle weiteren Authentifizierungs-, Header- und Inhaltsprüfungen. Kaputte Rohmails werden von Providern schlechter bewertet oder direkt abgelehnt."
		parseCheck.Recommendation = "Versandsoftware oder MTA so konfigurieren, dass Header und Body strikt RFC-konform erzeugt werden: gültige Header-Zeilen, leere Zeile vor Body, korrekte CRLF-Zeilenenden und saubere MIME-Boundaries."
		report.Checks = append(report.Checks, parseCheck)
		report.Warnings = append(report.Warnings, parseErr.Error())
		report.Score += parseCheck.ScoreDelta
		report.Score = clampScore(report.Score)
		assignLabel(&report)
		return report
	}
	headers := parsed.Header
	for k, v := range headers {
		report.RawHeaders[k] = append([]string(nil), v...)
	}

	bodyBytes, bodyErr := readLimited(parsed.Body, 4*1024*1024)
	if bodyErr != nil {
		report.Checks = append(report.Checks, warn("body_read", "Body Readability", -0.5, "Body konnte nicht vollständig gelesen werden.", "Nachrichtengröße und Encoding prüfen."))
	}

	fromDomain, _ := headerFromDomain(headers.Get("From"))
	envelopeDomain := domainPart(in.Message.SMTPFrom)
	returnPathDomain := domainPart(headers.Get("Return-Path"))
	authHeaderValues := headerValues(headers, "Authentication-Results")
	authResults := strings.ToLower(strings.Join(authHeaderValues, " ; "))

	spfResult := parseAuthResult(authResults, "spf")
	dkimResult := parseAuthResult(authResults, "dkim")
	dmarcResult := parseAuthResult(authResults, "dmarc")

	// SPF
	spfRecords := make([]string, 0)
	if envelopeDomain != "" {
		recs, _ := net.DefaultResolver.LookupTXT(ctx, envelopeDomain)
		for _, rec := range recs {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=spf1") {
				spfRecords = append(spfRecords, strings.TrimSpace(rec))
			}
		}
	}
	switch spfResult {
	case "pass":
		report.Checks = append(report.Checks, pass("spf", "SPF", 0.4, "SPF laut Authentication-Results bestanden.", ""))
	case "fail", "softfail":
		report.Checks = append(report.Checks, fail("spf", "SPF", -1.4, fmt.Sprintf("SPF meldet %s.", spfResult), "Envelope-From-Domain und SPF-Record korrigieren."))
	default:
		if len(spfRecords) > 0 {
			report.Checks = append(report.Checks, info("spf", "SPF", 0.0, "SPF-Record vorhanden, kein eindeutiges SPF-Ergebnis im Header.", ""))
		} else {
			report.Checks = append(report.Checks, warn("spf", "SPF", -0.8, "Kein SPF-Record erkannt oder Ergebnis fehlt.", "TXT-Record mit v=spf1 auf der Envelope-From-Domain setzen."))
		}
	}

	// DKIM
	hasDKIMSig := headers.Get("DKIM-Signature") != ""
	switch dkimResult {
	case "pass":
		report.Checks = append(report.Checks, pass("dkim", "DKIM", 0.4, "DKIM laut Authentication-Results bestanden.", ""))
	case "fail", "temperror", "permerror":
		report.Checks = append(report.Checks, fail("dkim", "DKIM", -1.4, fmt.Sprintf("DKIM meldet %s.", dkimResult), "Selector, Canonicalization und Signatur prüfen."))
	default:
		if hasDKIMSig {
			report.Checks = append(report.Checks, warn("dkim", "DKIM", -0.5, "DKIM-Signatur vorhanden, aber kein valides Ergebnis erkennbar.", "Verifizierbarkeit der DKIM-Signatur sicherstellen."))
		} else {
			report.Checks = append(report.Checks, fail("dkim", "DKIM", -1.0, "Keine DKIM-Signatur gefunden.", "Ausgehenden MTA so konfigurieren, dass DKIM signiert wird."))
		}
	}

	// DMARC
	dmarcRecords := make([]string, 0)
	dmarcPolicy := ""
	if fromDomain != "" {
		dmarcTXT, _ := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+fromDomain)
		for _, rec := range dmarcTXT {
			lr := strings.ToLower(rec)
			if strings.HasPrefix(lr, "v=dmarc1") {
				dmarcRecords = append(dmarcRecords, strings.TrimSpace(rec))
				dmarcPolicy = extractTagValue(lr, "p")
			}
		}
	}
	alignedSPF := envelopeDomain != "" && fromDomain != "" && (envelopeDomain == fromDomain || strings.HasSuffix(envelopeDomain, "."+fromDomain) || strings.HasSuffix(fromDomain, "."+envelopeDomain))
	dkimDomain := domainFromDKIM(headers.Get("DKIM-Signature"))
	alignedDKIM := dkimDomain != "" && fromDomain != "" && (dkimDomain == fromDomain || strings.HasSuffix(dkimDomain, "."+fromDomain))

	if dmarcResult == "pass" {
		report.Checks = append(report.Checks, pass("dmarc", "DMARC", 0.4, "DMARC laut Authentication-Results bestanden.", ""))
	} else if len(dmarcRecords) > 0 {
		if alignedSPF || alignedDKIM {
			report.Checks = append(report.Checks, warn("dmarc", "DMARC", -0.3, fmt.Sprintf("DMARC-Record vorhanden (p=%s), Alignment teilweise plausibel, aber kein eindeutiges pass im Header.", emptyFallback(dmarcPolicy, "none")), "DMARC-Alignment und Reporting prüfen."))
		} else {
			report.Checks = append(report.Checks, fail("dmarc", "DMARC", -1.0, fmt.Sprintf("DMARC-Record vorhanden (p=%s), aber kein SPF/DKIM-Alignment.", emptyFallback(dmarcPolicy, "none")), "From-Domain-Alignment mit SPF oder DKIM sicherstellen."))
		}
	} else {
		report.Checks = append(report.Checks, fail("dmarc", "DMARC", -1.2, "Kein DMARC-Record für die From-Domain gefunden.", "_dmarc.<domain> TXT mit v=DMARC1 veröffentlichen."))
	}

	primaryDomain := firstNonEmpty(fromDomain, envelopeDomain)
	report.Checks = append(report.Checks, spfAlignmentCheck(fromDomain, envelopeDomain, spfResult, alignedSPF))
	report.Checks = append(report.Checks, dkimAlignmentCheck(fromDomain, dkimDomain, dkimResult, alignedDKIM))
	report.Checks = append(report.Checks, dmarcAlignmentCheck(fromDomain, spfResult, dkimResult, alignedSPF, alignedDKIM))

	// Auth depth (Group A) — local, header-derived checks.
	report.Checks = append(report.Checks, dmarcPolicyCheck(dmarcRecords, dmarcPolicy))
	report.Checks = append(report.Checks, spfStrictnessCheck(spfRecords))
	report.Checks = append(report.Checks, displayNameCheck(headers.Get("From"), fromDomain))

	// NOTE: all network-bound checks (DNS, RBL, RDAP, SpamAssassin/Rspamd) are
	// collected and executed concurrently further below, so the report is not
	// gated on dozens of sequential lookups.

	// HELO/EHLO
	helo := strings.TrimSpace(in.Message.HELO)
	if helo == "" {
		report.Checks = append(report.Checks, fail("helo", "HELO/EHLO", -0.8, "HELO/EHLO fehlt.", "MTA sollte einen validen FQDN als EHLO senden."))
	} else if net.ParseIP(helo) != nil {
		report.Checks = append(report.Checks, warn("helo", "HELO/EHLO", -0.4, "HELO/EHLO ist eine IP-Literal-Angabe.", "FQDN statt IP in EHLO verwenden."))
	} else if strings.Count(helo, ".") < 1 {
		report.Checks = append(report.Checks, warn("helo", "HELO/EHLO", -0.3, "HELO/EHLO wirkt nicht wie ein FQDN.", "FQDN mit PTR-bezogener Hostkennung verwenden."))
	} else {
		report.Checks = append(report.Checks, pass("helo", "HELO/EHLO", 0.1, "HELO/EHLO sieht plausibel aus.", ""))
	}

	// Envelope/Header alignment
	if fromDomain == "" || envelopeDomain == "" {
		report.Checks = append(report.Checks, warn("from_alignment", "Envelope-From / Header-From", -0.4, "From oder Envelope-From konnte nicht sicher ermittelt werden.", "Absenderfelder konsistent setzen."))
	} else if fromDomain == envelopeDomain || strings.HasSuffix(envelopeDomain, "."+fromDomain) {
		report.Checks = append(report.Checks, pass("from_alignment", "Envelope-From / Header-From", 0.2, "Envelope-From und Header-From sind konsistent.", ""))
	} else {
		report.Checks = append(report.Checks, warn("from_alignment", "Envelope-From / Header-From", -0.7, "Envelope-From und Header-From sind nicht aligned.", "Bounce-Domain und sichtbare From-Domain besser angleichen."))
	}

	// Return-Path
	if headers.Get("Return-Path") == "" {
		report.Checks = append(report.Checks, warn("return_path", "Return-Path", -0.5, "Kein Return-Path Header sichtbar.", "Envelope-From und Return-Path klar setzen."))
	} else if returnPathDomain != "" {
		report.Checks = append(report.Checks, pass("return_path", "Return-Path", 0.1, "Return-Path ist vorhanden.", ""))
	}

	if replyTo := strings.TrimSpace(headers.Get("Reply-To")); replyTo == "" {
		report.Checks = append(report.Checks, info("reply_to", "Reply-To", 0.0, "Kein Reply-To-Header gesetzt.", "Wenn Antworten an eine andere Adresse gehen sollen, Reply-To bewusst setzen."))
	} else {
		report.Checks = append(report.Checks, pass("reply_to", "Reply-To", 0.0, "Reply-To-Header ist vorhanden.", ""))
	}

	receivedLines := headerValues(headers, "Received")
	if len(receivedLines) == 0 {
		report.Checks = append(report.Checks, fail("received_chain", "Received-Header-Kette", -1.2, "Keine Received-Header vorhanden.", "Transportpfad muss Received-Header enthalten."))
	} else {
		report.Checks = append(report.Checks, info("received_chain", "Received-Header-Kette", 0.0, fmt.Sprintf("%d Received-Header erkannt.", len(receivedLines)), ""))
	}
	report.Checks = append(report.Checks, tlsTransportCheck(receivedLines))

	if headers.Get("ARC-Seal") != "" || headers.Get("ARC-Message-Signature") != "" {
		report.Checks = append(report.Checks, info("arc", "ARC", 0.0, "ARC-Header vorhanden.", ""))
	} else {
		report.Checks = append(report.Checks, info("arc", "ARC", 0.0, "Keine ARC-Header vorhanden.", "Nur relevant bei Weiterleitungs-Szenarien."))
	}

	mimeFindings, parsedBody := inspectBody(headers, bodyBytes)
	report.Checks = append(report.Checks, mimeFindings...)

	links := extractLinks(parsedBody.AllText + "\n" + parsedBody.HTML)
	report.Links = dedupeSorted(links)
	urlFindings, spamSignals := evaluateURLs(report.Links)
	report.Checks = append(report.Checks, urlFindings...)
	report.SpamSignals = append(report.SpamSignals, spamSignals...)

	htmlFindings := htmlHeuristics(parsedBody.HTML)
	report.Checks = append(report.Checks, htmlFindings...)

	subjectChecks, subjectSignals := subjectHeuristics(headers.Get("Subject"))
	report.Checks = append(report.Checks, subjectChecks...)
	report.SpamSignals = append(report.SpamSignals, subjectSignals...)

	headChecks, headWarnings := headerHeuristics(headers)
	report.Checks = append(report.Checks, headChecks...)
	report.Warnings = append(report.Warnings, headWarnings...)

	unicodeCheck, unicodeSignal := unicodeObfuscationCheck(parsedBody.AllText)
	report.Checks = append(report.Checks, unicodeCheck)
	if unicodeSignal != "" {
		report.SpamSignals = append(report.SpamSignals, unicodeSignal)
	}

	newsletterChecks := newsletterHeuristics(headers, parsedBody)
	report.Checks = append(report.Checks, newsletterChecks...)

	// ── Network-bound checks: executed concurrently ────────────────────────────
	// Each does DNS / HTTP / TCP lookups and is independent of the others. Running
	// them in parallel (each panic-isolated) keeps the report fast, and a single
	// failing lookup can never abort the whole analysis.
	netTasks := []checkTask{
		{"mx_records", func(c context.Context) []model.CheckResult { return one(mxRecordCheck(c, primaryDomain)) }},
		{"address_records", func(c context.Context) []model.CheckResult { return one(addressRecordCheck(c, primaryDomain)) }},
		{"dkim_keylength", func(c context.Context) []model.CheckResult {
			return one(dkimKeyLengthCheck(c, headers.Get("DKIM-Signature")))
		}},
		{"envelope_mx", func(c context.Context) []model.CheckResult {
			return one(envelopeBounceMXCheck(c, firstNonEmpty(returnPathDomain, envelopeDomain)))
		}},
		{"mta_sts", func(c context.Context) []model.CheckResult { return one(mtaStsCheck(c, primaryDomain)) }},
		{"tls_rpt", func(c context.Context) []model.CheckResult { return one(tlsRptCheck(c, primaryDomain)) }},
		{"bimi", func(c context.Context) []model.CheckResult { return one(bimiCheck(c, primaryDomain)) }},
		{"dnssec", func(c context.Context) []model.CheckResult { return one(dnssecCheck(c, primaryDomain)) }},
		{"dane_tlsa", func(c context.Context) []model.CheckResult { return one(daneCheck(c, primaryDomain)) }},
		{"ptr", func(c context.Context) []model.CheckResult {
			return one(ptrPlausibility(c, in.Message.RemoteIP, in.Message.HELO))
		}},
		{"ptr_pattern", func(c context.Context) []model.CheckResult { return one(ptrPatternCheck(c, in.Message.RemoteIP)) }},
	}
	if e.opts.EnableRBLChecks {
		netTasks = append(netTasks, checkTask{"rbl", func(c context.Context) []model.CheckResult {
			return rblHeuristics(c, in.Message.RemoteIP, e.opts.RBLProviders)
		}})
	}
	if e.opts.EnableSpamAssassin && strings.TrimSpace(e.opts.SpamAssassinHostPort) != "" {
		netTasks = append(netTasks, checkTask{"spamassassin", func(c context.Context) []model.CheckResult {
			return one(spamAssassinHeuristic(c, e.opts.SpamAssassinHostPort, in.Message.RawSource))
		}})
	}
	if e.opts.EnableRspamd && strings.TrimSpace(e.opts.RspamdURL) != "" {
		netTasks = append(netTasks, checkTask{"rspamd", func(c context.Context) []model.CheckResult {
			return one(rspamdHeuristic(c, e.opts.RspamdURL, e.opts.RspamdPassword, in.Message.RawSource))
		}})
	}
	// Group C — opt-in third-party reputation checks (off by default). Enabled
	// either globally by the operator (e.opts) or per-mailbox by the user (in.*).
	if e.opts.EnableDomainAge || in.EnableDomainAge {
		netTasks = append(netTasks, checkTask{"domain_age", func(c context.Context) []model.CheckResult { return one(domainAgeCheck(c, primaryDomain)) }})
	}
	if e.opts.EnableDomainBlocklist || in.EnableDomainBlocklist {
		netTasks = append(netTasks, checkTask{"domain_blocklist", func(c context.Context) []model.CheckResult {
			return one(domainBlocklistCheck(c, primaryDomain, e.opts.DomainBlocklistProviders))
		}})
		netTasks = append(netTasks, checkTask{"link_blocklist", func(c context.Context) []model.CheckResult {
			return one(linkBlocklistCheck(c, report.Links, e.opts.DomainBlocklistProviders))
		}})
	}
	report.Checks = append(report.Checks, runChecksConcurrently(ctx, netTasks, 8)...)

	enrichCtx := checkContext{
		Message:        in.Message,
		SMTPDomain:     in.SMTPDomain,
		Headers:        headers,
		FromDomain:     fromDomain,
		EnvelopeDomain: envelopeDomain,
		ReturnPath:     headers.Get("Return-Path"),
		ReturnDomain:   returnPathDomain,
		AuthHeaders:    authHeaderValues,
		SPFResult:      spfResult,
		SPFRecords:     spfRecords,
		DKIMResult:     dkimResult,
		DKIMDomain:     dkimDomain,
		DMARCResult:    dmarcResult,
		DMARCRecords:   dmarcRecords,
		DMARCPolicy:    dmarcPolicy,
		AlignedSPF:     alignedSPF,
		AlignedDKIM:    alignedDKIM,
		ReceivedLines:  receivedLines,
		ParsedBody:     parsedBody,
		Links:          report.Links,
	}
	for i := range report.Checks {
		report.Checks[i] = enrichCheckResult(report.Checks[i], enrichCtx)
	}

	for _, c := range report.Checks {
		report.Score += c.ScoreDelta
		if c.Status == "fail" || c.Status == "warn" {
			if c.Recommendation != "" {
				report.Suggestions = append(report.Suggestions, c.Recommendation)
			} else if c.Suggestion != "" {
				report.Suggestions = append(report.Suggestions, c.Suggestion)
			}
		}
	}

	report.Score = clampScore(report.Score)
	// A perfect 10 must be earned: it requires every essential check to actually
	// pass (a clean SPF, DKIM, DMARC and PTR), not merely "not fail". This closes
	// the loophole where an unconfirmed/neutral essential (e.g. an ambiguous SPF
	// result, score delta 0) could still leave the score at a full 10.
	if report.Score > essentialPerfectCap && !essentialsAllPass(report.Checks) {
		report.Score = essentialPerfectCap
	}
	report.Suggestions = dedupeSorted(report.Suggestions)
	report.Warnings = dedupeSorted(report.Warnings)
	report.SpamSignals = dedupeSorted(report.SpamSignals)
	assignLabel(&report)
	return report
}

func pass(id, name string, delta float64, summary, suggestion string) model.CheckResult {
	return model.CheckResult{ID: id, Name: name, Status: "pass", ScoreDelta: delta, Summary: summary, Suggestion: suggestion}
}
func warn(id, name string, delta float64, summary, suggestion string) model.CheckResult {
	return model.CheckResult{ID: id, Name: name, Status: "warn", ScoreDelta: delta, Summary: summary, Suggestion: suggestion}
}
func fail(id, name string, delta float64, summary, suggestion string) model.CheckResult {
	return model.CheckResult{ID: id, Name: name, Status: "fail", ScoreDelta: delta, Summary: summary, Suggestion: suggestion}
}
func info(id, name string, delta float64, summary, suggestion string) model.CheckResult {
	return model.CheckResult{ID: id, Name: name, Status: "info", ScoreDelta: delta, Summary: summary, Suggestion: suggestion}
}

// errorCheck represents a check that could not be completed internally (panic or
// unexpected error). It is informational and never penalises the score.
func errorCheck(id, msg string) model.CheckResult {
	return model.CheckResult{
		ID:               id,
		Name:             "Prüfung nicht abgeschlossen",
		Status:           "info",
		ScoreDelta:       0,
		Summary:          "Diese Prüfung konnte intern nicht abgeschlossen werden und wurde übersprungen.",
		TechnicalDetails: map[string]string{"error": msg},
		Category:         "Header und Rohdaten",
	}
}

// one wraps a single CheckResult into a slice for the concurrent task runner.
func one(c model.CheckResult) []model.CheckResult { return []model.CheckResult{c} }

// checkTask is a named, network-bound check executed by runChecksConcurrently.
type checkTask struct {
	name string
	fn   func(context.Context) []model.CheckResult
}

// runChecksConcurrently runs tasks in parallel (bounded by limit), isolating each
// from panics, and returns their results in deterministic task order.
func runChecksConcurrently(ctx context.Context, tasks []checkTask, limit int) []model.CheckResult {
	if limit <= 0 {
		limit = 8
	}
	results := make([][]model.CheckResult, len(tasks))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, t := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t checkTask) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					results[i] = []model.CheckResult{errorCheck(t.name, fmt.Sprintf("%v", r))}
				}
			}()
			results[i] = t.fn(ctx)
		}(i, t)
	}
	wg.Wait()
	out := make([]model.CheckResult, 0, len(tasks))
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

type checkContext struct {
	Message        model.Message
	SMTPDomain     string
	Headers        mail.Header
	FromDomain     string
	EnvelopeDomain string
	ReturnPath     string
	ReturnDomain   string
	AuthHeaders    []string
	SPFResult      string
	SPFRecords     []string
	DKIMResult     string
	DKIMDomain     string
	DMARCResult    string
	DMARCRecords   []string
	DMARCPolicy    string
	AlignedSPF     bool
	AlignedDKIM    bool
	ReceivedLines  []string
	ParsedBody     parsedBody
	Links          []string
}

func mxRecordCheck(ctx context.Context, domain string) model.CheckResult {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return info("mx_records", "MX-Records", 0.0, "Keine Domain für den MX-Check ermittelbar.", "Header-From oder Envelope-From sauber setzen.")
	}
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return warn("mx_records", "MX-Records", -0.3, fmt.Sprintf("Für %s wurde kein MX-Record gefunden.", domain), fmt.Sprintf("Falls %s E-Mails empfangen soll, in der DNS-Zone einen MX-Record setzen, z. B. %s. MX 10 mail.%s.", domain, domain, domain))
	}
	values := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		values = append(values, fmt.Sprintf("%s MX %d %s", domain, mx.Pref, strings.TrimSuffix(mx.Host, ".")))
	}
	return withDetails(pass("mx_records", "MX-Records", 0.1, fmt.Sprintf("Für %s sind %d MX-Record(s) vorhanden.", domain, len(mxs)), ""), map[string]string{
		"domain":     domain,
		"mx_records": strings.Join(values, "\n"),
	})
}

func addressRecordCheck(ctx context.Context, domain string) model.CheckResult {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return info("address_records", "A/AAAA-Records", 0.0, "Keine Domain für A/AAAA-Check ermittelbar.", "Header-From oder Envelope-From sauber setzen.")
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil || len(ips) == 0 {
		return warn("address_records", "A/AAAA-Records", -0.3, fmt.Sprintf("%s löst nicht auf A/AAAA auf.", domain), fmt.Sprintf("In der DNS-Zone A/AAAA-Records für %s setzen, wenn diese Domain direkt als Hostname verwendet wird.", domain))
	}
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, ip.IP.String())
	}
	return withDetails(pass("address_records", "A/AAAA-Records", 0.1, fmt.Sprintf("%s löst auf %d Adresse(n) auf.", domain, len(ips)), ""), map[string]string{
		"domain":         domain,
		"a_aaaa_records": strings.Join(values, "\n"),
	})
}

func spfAlignmentCheck(fromDomain, envelopeDomain, spfResult string, aligned bool) model.CheckResult {
	if fromDomain == "" || envelopeDomain == "" {
		return warn("spf_alignment", "SPF Alignment", -0.4, "SPF-Alignment konnte nicht vollstaendig bewertet werden.", "Header-From und Envelope-From mit klaren Domains setzen.")
	}
	if spfResult == "pass" && aligned {
		return pass("spf_alignment", "SPF Alignment", 0.2, "SPF besteht und ist mit der sichtbaren From-Domain aligned.", "")
	}
	if spfResult == "pass" {
		return warn("spf_alignment", "SPF Alignment", -0.4, "SPF besteht, ist aber nicht mit der sichtbaren From-Domain aligned.", "Envelope-From/Bounce-Domain auf eine Subdomain der sichtbaren From-Domain umstellen oder DKIM Alignment sicherstellen.")
	}
	return warn("spf_alignment", "SPF Alignment", -0.5, "SPF liefert kein pass; dadurch kann SPF nicht für DMARC-Alignment zählen.", "SPF für die Envelope-From-Domain korrigieren.")
}

func dkimAlignmentCheck(fromDomain, dkimDomain, dkimResult string, aligned bool) model.CheckResult {
	if dkimResult != "pass" {
		return warn("dkim_alignment", "DKIM Alignment", -0.5, "DKIM liefert kein pass; DKIM kann nicht für DMARC-Alignment zählen.", "DKIM-Signatur für die sichtbare From-Domain oder eine passende Subdomain aktivieren.")
	}
	if aligned {
		return pass("dkim_alignment", "DKIM Alignment", 0.2, "DKIM besteht und ist mit der sichtbaren From-Domain aligned.", "")
	}
	return warn("dkim_alignment", "DKIM Alignment", -0.4, "DKIM besteht, aber die Signaturdomain passt nicht zur sichtbaren From-Domain.", "DKIM d= auf die From-Domain oder eine erlaubte Subdomain setzen.")
}

func dmarcAlignmentCheck(fromDomain, spfResult, dkimResult string, alignedSPF, alignedDKIM bool) model.CheckResult {
	if fromDomain == "" {
		return warn("dmarc_alignment", "DMARC Alignment", -0.5, "DMARC-Alignment konnte ohne From-Domain nicht bewertet werden.", "Einen gueltigen From-Header mit Domain setzen.")
	}
	if (spfResult == "pass" && alignedSPF) || (dkimResult == "pass" && alignedDKIM) {
		return pass("dmarc_alignment", "DMARC Alignment", 0.2, "Mindestens SPF oder DKIM ist aligned und kann DMARC tragen.", "")
	}
	return fail("dmarc_alignment", "DMARC Alignment", -0.9, "Weder SPF noch DKIM sind aligned; DMARC kann dadurch scheitern.", "SPF oder DKIM so konfigurieren, dass die authentifizierte Domain zur Header-From-Domain passt.")
}

func tlsTransportCheck(received []string) model.CheckResult {
	raw := strings.ToLower(strings.Join(received, "\n"))
	if strings.Contains(raw, "tls") || strings.Contains(raw, "esmtps") || strings.Contains(raw, "cipher") {
		return pass("tls_transport", "TLS Transport", 0.1, "Received-Header enthalten Hinweise auf verschlüsselten Transport.", "")
	}
	return info("tls_transport", "TLS Transport", 0.0, "Aus den Received-Headern ist kein TLS-Transport eindeutig erkennbar.", "TLS für SMTP aktivieren und sicherstellen, dass vorgelagerte MTAs TLS-Informationen in Received-Headern dokumentieren.")
}

// ── Group A: deeper checks derived from already-available data ──────────────

// dmarcPolicyCheck evaluates the strength of the published DMARC policy (p=).
func dmarcPolicyCheck(records []string, policy string) model.CheckResult {
	if len(records) == 0 {
		return info("dmarc_policy", "DMARC-Policy-Stärke", 0.0, "Keine DMARC-Policy auswertbar (kein DMARC-Record).", "Zuerst einen DMARC-Record veröffentlichen.")
	}
	p := strings.ToLower(strings.TrimSpace(policy))
	hasRUA := strings.Contains(strings.ToLower(strings.Join(records, " ")), "rua=")
	ruaNote := ""
	if !hasRUA {
		ruaNote = " Es ist keine rua=-Reporting-Adresse gesetzt – ohne Reports siehst du nicht, wer in deinem Namen sendet."
	}
	det := map[string]string{"policy": emptyFallback(p, "none"), "rua_present": strconv.FormatBool(hasRUA), "dmarc_records": strings.Join(records, "\n")}
	switch p {
	case "reject":
		return withDetails(pass("dmarc_policy", "DMARC-Policy-Stärke", 0.3, "DMARC p=reject – stärkster Schutz gegen Domain-Spoofing."+ruaNote, ruaOnlyRec(hasRUA)), det)
	case "quarantine":
		return withDetails(pass("dmarc_policy", "DMARC-Policy-Stärke", 0.1, "DMARC p=quarantine – mittlerer Schutz; verdächtige Mails landen im Spam."+ruaNote, "Sobald die Reports sauber sind, auf p=reject erhöhen."), det)
	case "none":
		return withDetails(warn("dmarc_policy", "DMARC-Policy-Stärke", -0.3, "DMARC p=none – nur Monitoring, kein aktiver Schutz vor Domain-Spoofing."+ruaNote, "Nach einer Monitoring-Phase auf p=quarantine und später p=reject erhöhen."), det)
	default:
		return withDetails(warn("dmarc_policy", "DMARC-Policy-Stärke", -0.2, "DMARC-Record vorhanden, aber keine gültige p=-Policy erkannt.", "Gültige Policy setzen: p=none, p=quarantine oder p=reject."), det)
	}
}

func ruaOnlyRec(hasRUA bool) string {
	if hasRUA {
		return ""
	}
	return "rua=mailto:dmarc@deine-domain für aggregierte Reports ergänzen, um Versandquellen zu überwachen."
}

// spfStrictnessCheck evaluates the SPF 'all' qualifier and the top-level DNS
// lookup count (RFC 7208 limits SPF to 10 DNS-querying mechanisms).
func spfStrictnessCheck(records []string) model.CheckResult {
	if len(records) == 0 {
		return info("spf_strictness", "SPF-Strenge", 0.0, "Kein SPF-Record auswertbar.", "Zuerst einen SPF-Record (v=spf1 …) veröffentlichen.")
	}
	rec := strings.ToLower(strings.TrimSpace(records[0]))
	lookups := 0
	for _, tok := range strings.Fields(rec) {
		t := strings.TrimLeft(tok, "+-~?")
		if strings.HasPrefix(t, "include:") || t == "a" || strings.HasPrefix(t, "a:") ||
			t == "mx" || strings.HasPrefix(t, "mx:") || strings.HasPrefix(t, "ptr") ||
			strings.HasPrefix(t, "exists:") || strings.HasPrefix(t, "redirect=") {
			lookups++
		}
	}
	all := ""
	switch {
	case strings.Contains(rec, "-all"):
		all = "-all"
	case strings.Contains(rec, "~all"):
		all = "~all"
	case strings.Contains(rec, "?all"):
		all = "?all"
	case strings.Contains(rec, "+all"):
		all = "+all"
	}
	det := map[string]string{"spf_record": records[0], "all_mechanism": emptyFallback(all, "none"), "lookup_mechanisms_toplevel": strconv.Itoa(lookups)}
	if all == "+all" {
		return withDetails(fail("spf_strictness", "SPF-Strenge", -1.5, "SPF endet auf +all – das erlaubt JEDEM Server, in deinem Namen zu senden (gefährlich).", "Sofort auf -all (hardfail) oder mindestens ~all (softfail) ändern."), det)
	}
	if lookups > 10 {
		return withDetails(warn("spf_strictness", "SPF-Strenge", -0.6, fmt.Sprintf("SPF hat schon %d Lookup-Mechanismen auf oberster Ebene – das 10-Lookup-Limit (RFC 7208) droht überschritten zu werden (PermError).", lookups), "include-Ketten reduzieren oder per SPF-Flattening zusammenfassen."), det)
	}
	switch all {
	case "-all":
		return withDetails(pass("spf_strictness", "SPF-Strenge", 0.2, "SPF endet auf -all (hardfail) – strengste und empfohlene Einstellung.", ""), det)
	case "~all":
		return withDetails(info("spf_strictness", "SPF-Strenge", 0.0, "SPF endet auf ~all (softfail) – akzeptabel, -all bietet aber stärkeren Schutz.", "Wenn alle legitimen Sendequellen erfasst sind, auf -all umstellen."), det)
	case "?all":
		return withDetails(warn("spf_strictness", "SPF-Strenge", -0.3, "SPF endet auf ?all (neutral) – bietet praktisch keinen Schutz.", "Auf -all oder ~all umstellen."), det)
	default:
		return withDetails(warn("spf_strictness", "SPF-Strenge", -0.3, "SPF-Record hat keinen abschließenden all-Mechanismus.", "Den Record mit -all (oder ~all) abschließen."), det)
	}
}

// dkimKeyLengthCheck fetches the DKIM public key via DNS and evaluates its strength.
func dkimKeyLengthCheck(ctx context.Context, dkimSig string) model.CheckResult {
	if strings.TrimSpace(dkimSig) == "" {
		return info("dkim_keylength", "DKIM-Schlüssellänge", 0.0, "Keine DKIM-Signatur vorhanden – Schlüssellänge nicht prüfbar.", "DKIM-Signierung im ausgehenden MTA aktivieren.")
	}
	selector := extractTagValue(dkimSig, "s")
	domain := extractTagValue(dkimSig, "d")
	if selector == "" || domain == "" {
		return info("dkim_keylength", "DKIM-Schlüssellänge", 0.0, "DKIM-Signatur ohne s=/d=-Tag – Schlüssel nicht auffindbar.", "DKIM-Signatur muss s= (Selector) und d= (Domain) enthalten.")
	}
	dnsName := selector + "._domainkey." + domain
	det := map[string]string{"selector": selector, "domain": domain, "dns_name": dnsName}
	txt, err := net.DefaultResolver.LookupTXT(ctx, dnsName)
	if err != nil || len(txt) == 0 {
		return withDetails(warn("dkim_keylength", "DKIM-Schlüssellänge", -0.3, "DKIM-Public-Key konnte per DNS nicht abgerufen werden.", "Prüfen, ob der DKIM-Record unter "+dnsName+" existiert."), det)
	}
	joined := strings.Join(txt, "")
	keyType := emptyFallback(extractTagValue(joined, "k"), "rsa")
	det["key_type"] = keyType
	if keyType == "ed25519" {
		return withDetails(pass("dkim_keylength", "DKIM-Schlüssellänge", 0.1, "DKIM nutzt Ed25519 – modern und sicher.", ""), det)
	}
	der, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(extractTagValue(joined, "p")))
	if derr != nil || len(der) == 0 {
		return withDetails(warn("dkim_keylength", "DKIM-Schlüssellänge", -0.3, "DKIM-Public-Key (p=) konnte nicht dekodiert werden.", "DKIM-Record auf gültiges Base64 prüfen."), det)
	}
	pub, perr := x509.ParsePKIXPublicKey(der)
	if perr != nil {
		return withDetails(warn("dkim_keylength", "DKIM-Schlüssellänge", -0.2, "DKIM-Public-Key konnte nicht geparst werden.", "Gültigen RSA- oder Ed25519-Schlüssel veröffentlichen."), det)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return withDetails(info("dkim_keylength", "DKIM-Schlüssellänge", 0.0, "DKIM-Schlüsseltyp ist kein RSA – Bit-Länge nicht bewertet.", ""), det)
	}
	bits := rsaPub.N.BitLen()
	det["key_bits"] = strconv.Itoa(bits)
	switch {
	case bits < 1024:
		return withDetails(fail("dkim_keylength", "DKIM-Schlüssellänge", -1.0, fmt.Sprintf("DKIM-RSA-Schlüssel hat nur %d Bit – unsicher und von vielen Providern abgelehnt.", bits), "Auf mindestens 2048-Bit-RSA umstellen und Selector rotieren."), det)
	case bits < 2048:
		return withDetails(warn("dkim_keylength", "DKIM-Schlüssellänge", -0.4, fmt.Sprintf("DKIM-RSA-Schlüssel hat %d Bit – Gmail & Co. empfehlen mindestens 2048 Bit.", bits), "Neuen 2048-Bit-DKIM-Schlüssel erzeugen und Selector rotieren."), det)
	default:
		return withDetails(pass("dkim_keylength", "DKIM-Schlüssellänge", 0.1, fmt.Sprintf("DKIM-RSA-Schlüssel hat %d Bit – ausreichend stark.", bits), ""), det)
	}
}

var dynamicPTRPattern = regexp.MustCompile(`(?i)(\bdynamic\b|\bdyn\b|dhcp|dialup|dial-up|broadband|\bdsl\b|\bpppoe\b|\bcable\b|\bpool\b|\bclient\b|customer|\bcpe\b|\bres\b|residential|static-?ip|\bip[\.-]?\d|\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3})`)

// ptrPatternCheck flags reverse-DNS hostnames that look generic/dynamic (a
// strong spam signal even when forward-confirmed rDNS technically passes).
func ptrPatternCheck(ctx context.Context, ip string) model.CheckResult {
	ip = strings.TrimSpace(ip)
	if ip == "" || net.ParseIP(ip) == nil {
		return info("ptr_pattern", "PTR-Hostname-Muster", 0.0, "Keine sendende IP für die PTR-Mustererkennung verfügbar.", "")
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return info("ptr_pattern", "PTR-Hostname-Muster", 0.0, "Kein PTR-Hostname auflösbar – Muster nicht bewertbar (siehe PTR/rDNS-Check).", "")
	}
	host := strings.TrimSuffix(strings.ToLower(names[0]), ".")
	det := map[string]string{"remote_ip": ip, "ptr_hostname": host}
	if dynamicPTRPattern.MatchString(host) {
		return withDetails(warn("ptr_pattern", "PTR-Hostname-Muster", -0.6, fmt.Sprintf("PTR-Hostname %q wirkt generisch/dynamisch (Endkunden-/Dynamic-IP-Muster) – ein verbreitetes Spam-Signal.", host), "Beim Hosting-Provider einen dedizierten, sprechenden Mailserver-PTR setzen, z. B. mail.deine-domain – nicht den automatischen Provider-Default."), det)
	}
	return withDetails(pass("ptr_pattern", "PTR-Hostname-Muster", 0.1, fmt.Sprintf("PTR-Hostname %q sieht nach einem dedizierten Mailserver aus.", host), ""), det)
}

var embeddedEmailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})`)

var impersonationBrands = []string{
	"paypal", "amazon", "microsoft", "office365", "apple", "icloud", "google", "gmail",
	"netflix", "paypal", "dhl", "fedex", "ups", "deutsche post", "telekom", "vodafone",
	"sparkasse", "volksbank", "postbank", "commerzbank", "deutsche bank", "ing-diba", "ing diba",
	"dkb", "n26", "klarna", "shopify", "facebook", "instagram", "whatsapp", "linkedin",
}

// displayNameCheck flags From display names that impersonate another brand or
// embed a foreign e-mail address (classic phishing pattern).
func displayNameCheck(fromHeader, fromDomain string) model.CheckResult {
	fromHeader = strings.TrimSpace(fromHeader)
	if fromHeader == "" {
		return info("display_name", "From-Anzeigename", 0.0, "Kein From-Header zur Bewertung des Anzeigenamens.", "Gültigen From-Header setzen.")
	}
	addr, perr := mail.ParseAddress(fromHeader)
	display := ""
	if perr == nil {
		display = addr.Name
	}
	if display == "" {
		return info("display_name", "From-Anzeigename", 0.0, "Kein Anzeigename im From-Header gesetzt.", "")
	}
	dlow := strings.ToLower(display)
	rdom := strings.ToLower(strings.TrimSpace(fromDomain))
	det := map[string]string{"display_name": display, "from_domain": emptyFallback(rdom, "none")}

	// (1) Embedded e-mail address with a different domain.
	if m := embeddedEmailPattern.FindStringSubmatch(display); m != nil {
		embDom := strings.ToLower(m[1])
		if rdom != "" && embDom != rdom && !strings.HasSuffix(embDom, "."+rdom) && !strings.HasSuffix(rdom, "."+embDom) {
			det["embedded_domain"] = embDom
			return withDetails(warn("display_name", "From-Anzeigename", -0.7, fmt.Sprintf("Anzeigename enthält eine fremde E-Mail-Adresse (%s), während tatsächlich von %s gesendet wird – klassisches Phishing-Muster.", m[0], rdom), "Anzeigename ohne fremde E-Mail-Adressen verwenden; Anzeigename und tatsächliche Absenderdomain konsistent halten."), det)
		}
	}
	// (2) Brand impersonation: brand word in the display name but not in the domain.
	for _, brand := range impersonationBrands {
		if strings.Contains(dlow, brand) && (rdom == "" || !strings.Contains(rdom, strings.ReplaceAll(brand, " ", ""))) {
			det["impersonated_brand"] = brand
			return withDetails(warn("display_name", "From-Anzeigename", -0.6, fmt.Sprintf("Anzeigename nennt die Marke %q, die Absenderdomain (%s) gehört aber nicht dazu – wirkt wie Markenimitation.", brand, emptyFallback(rdom, "unbekannt")), "Markennamen im Anzeigenamen nur verwenden, wenn von der passenden Domain gesendet wird."), det)
		}
	}
	return withDetails(pass("display_name", "From-Anzeigename", 0.0, "From-Anzeigename zeigt keine Spoofing-/Imitationsmuster.", ""), det)
}

// envelopeBounceMXCheck verifies the bounce (Return-Path/Envelope-From) domain
// can actually receive delivery status notifications.
func envelopeBounceMXCheck(ctx context.Context, bounceDomain string) model.CheckResult {
	bounceDomain = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(bounceDomain), "."))
	if bounceDomain == "" {
		return info("envelope_mx", "Bounce-Empfang (Envelope-MX)", 0.0, "Keine Envelope-/Return-Path-Domain für den Bounce-MX-Check ermittelbar.", "Envelope-From/Return-Path mit einer eigenen Domain setzen.")
	}
	det := map[string]string{"bounce_domain": bounceDomain}
	mxs, err := net.DefaultResolver.LookupMX(ctx, bounceDomain)
	if err != nil || len(mxs) == 0 {
		// Fall back to A/AAAA — RFC 5321 allows implicit MX.
		if ips, ierr := net.DefaultResolver.LookupIPAddr(ctx, bounceDomain); ierr == nil && len(ips) > 0 {
			return withDetails(info("envelope_mx", "Bounce-Empfang (Envelope-MX)", 0.0, fmt.Sprintf("Bounce-Domain %s hat keinen MX, aber A/AAAA (impliziter MX) – Bounces sind grenzwertig zustellbar.", bounceDomain), "Für sauberes Bounce-Handling einen MX-Record auf der Bounce-Domain setzen."), det)
		}
		return withDetails(warn("envelope_mx", "Bounce-Empfang (Envelope-MX)", -0.4, fmt.Sprintf("Bounce-Domain %s hat weder MX noch A/AAAA – Unzustellbarkeits-Benachrichtigungen (Bounces) können nicht zugestellt werden.", bounceDomain), "MX-Record für die Envelope-From/Return-Path-Domain setzen, damit Bounces ankommen."), det)
	}
	return withDetails(pass("envelope_mx", "Bounce-Empfang (Envelope-MX)", 0.1, fmt.Sprintf("Bounce-Domain %s kann Bounces empfangen (%d MX-Record(s)).", bounceDomain, len(mxs)), ""), det)
}

// ── Group B: DNS maturity signals (extra lookups in the sender's own zone) ──

func normDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// txtHasPrefix reports whether any TXT record at name starts with prefix.
func txtHasPrefix(ctx context.Context, name, prefix string) (bool, []string) {
	recs, err := net.DefaultResolver.LookupTXT(ctx, name)
	if err != nil || len(recs) == 0 {
		return false, nil
	}
	lp := strings.ToLower(prefix)
	for _, r := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), lp) {
			return true, recs
		}
	}
	return false, recs
}

func mtaStsCheck(ctx context.Context, domain string) model.CheckResult {
	domain = normDomain(domain)
	if domain == "" {
		return info("mta_sts", "MTA-STS", 0.0, "Keine Domain für den MTA-STS-Check ermittelbar.", "")
	}
	name := "_mta-sts." + domain
	ok, recs := txtHasPrefix(ctx, name, "v=STSv1")
	det := map[string]string{"dns_name": name, "txt": joinOrNone(recs)}
	if ok {
		return withDetails(pass("mta_sts", "MTA-STS", 0.15, "MTA-STS-Policy veröffentlicht – erzwingt verschlüsselten (TLS) Transport zum Mailserver.", ""), det)
	}
	return withDetails(info("mta_sts", "MTA-STS", 0.0, "Keine MTA-STS-Policy gefunden (optional, aber ein Reifesignal für sicheren Transport).", "Optional: _mta-sts-TXT-Record plus Policy unter https://mta-sts.<domain>/.well-known/mta-sts.txt veröffentlichen."), det)
}

func tlsRptCheck(ctx context.Context, domain string) model.CheckResult {
	domain = normDomain(domain)
	if domain == "" {
		return info("tls_rpt", "TLS-RPT", 0.0, "Keine Domain für den TLS-RPT-Check ermittelbar.", "")
	}
	name := "_smtp._tls." + domain
	ok, recs := txtHasPrefix(ctx, name, "v=TLSRPTv1")
	det := map[string]string{"dns_name": name, "txt": joinOrNone(recs)}
	if ok {
		return withDetails(pass("tls_rpt", "TLS-RPT", 0.1, "TLS-RPT-Reporting konfiguriert – du erhältst Berichte über fehlgeschlagene TLS-Verbindungen.", ""), det)
	}
	return withDetails(info("tls_rpt", "TLS-RPT", 0.0, "Kein TLS-RPT-Record gefunden (optional; sinnvoll zusammen mit MTA-STS).", "Optional: _smtp._tls-TXT mit v=TLSRPTv1 und rua-Reporting-Adresse setzen."), det)
}

func bimiCheck(ctx context.Context, domain string) model.CheckResult {
	domain = normDomain(domain)
	if domain == "" {
		return info("bimi", "BIMI", 0.0, "Keine Domain für den BIMI-Check ermittelbar.", "")
	}
	name := "default._bimi." + domain
	ok, recs := txtHasPrefix(ctx, name, "v=BIMI1")
	det := map[string]string{"dns_name": name, "txt": joinOrNone(recs)}
	if ok {
		return withDetails(pass("bimi", "BIMI", 0.1, "BIMI-Record veröffentlicht – Logo-Anzeige bei unterstützenden Providern (setzt durchgesetztes DMARC voraus).", ""), det)
	}
	return withDetails(info("bimi", "BIMI", 0.0, "Kein BIMI-Record gefunden (optional; erfordert DMARC p=quarantine/reject und ein SVG-Logo).", "Optional: nach DMARC-Enforcement einen default._bimi-Record mit Logo-URL veröffentlichen."), det)
}

// resolverServer returns the first system DNS server as host:port, or "" if
// none is configured. Uses only the operator's own resolver (no public
// fallback) so DNSSEC/DANE queries stay privacy-consistent with the rest.
func resolverServer() string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return ""
	}
	port := cfg.Port
	if port == "" {
		port = "53"
	}
	return net.JoinHostPort(cfg.Servers[0], port)
}

// dnsRecords queries a specific record type via the system resolver using
// miekg/dns (needed for DNSKEY/TLSA, which net.Resolver cannot request).
func dnsRecords(ctx context.Context, server, name string, qtype uint16) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	c := &dns.Client{Timeout: 4 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil || resp == nil {
		return nil
	}
	return resp.Answer
}

func dnssecCheck(ctx context.Context, domain string) model.CheckResult {
	domain = normDomain(domain)
	if domain == "" {
		return info("dnssec", "DNSSEC", 0.0, "Keine Domain für den DNSSEC-Check ermittelbar.", "")
	}
	server := resolverServer()
	if server == "" {
		return info("dnssec", "DNSSEC", 0.0, "DNSSEC nicht prüfbar (kein DNS-Resolver konfiguriert).", "")
	}
	ans := dnsRecords(ctx, server, domain, dns.TypeDNSKEY)
	has := false
	for _, rr := range ans {
		if _, ok := rr.(*dns.DNSKEY); ok {
			has = true
			break
		}
	}
	det := map[string]string{"domain": domain, "dnskey_records": strconv.Itoa(len(ans))}
	if has {
		return withDetails(pass("dnssec", "DNSSEC", 0.1, "Domain ist DNSSEC-signiert (DNSKEY vorhanden) – schützt DNS-Antworten vor Manipulation.", ""), det)
	}
	return withDetails(info("dnssec", "DNSSEC", 0.0, "Keine DNSSEC-Signierung erkannt (optional; erhöht die DNS-Integrität und ist Voraussetzung für DANE).", "Optional: DNSSEC bei deinem DNS-Provider/Registrar aktivieren."), det)
}

func daneCheck(ctx context.Context, domain string) model.CheckResult {
	domain = normDomain(domain)
	if domain == "" {
		return info("dane_tlsa", "DANE/TLSA", 0.0, "Keine Domain für den DANE-Check ermittelbar.", "")
	}
	server := resolverServer()
	if server == "" {
		return info("dane_tlsa", "DANE/TLSA", 0.0, "DANE nicht prüfbar (kein DNS-Resolver konfiguriert).", "")
	}
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return withDetails(info("dane_tlsa", "DANE/TLSA", 0.0, "Kein MX vorhanden – DANE/TLSA nicht anwendbar.", ""), map[string]string{"domain": domain})
	}
	host := strings.TrimSuffix(mxs[0].Host, ".")
	name := "_25._tcp." + host
	ans := dnsRecords(ctx, server, name, dns.TypeTLSA)
	has := false
	for _, rr := range ans {
		if _, ok := rr.(*dns.TLSA); ok {
			has = true
			break
		}
	}
	det := map[string]string{"mx_host": host, "tlsa_name": name, "tlsa_records": strconv.Itoa(len(ans))}
	if has {
		return withDetails(pass("dane_tlsa", "DANE/TLSA", 0.1, fmt.Sprintf("DANE aktiv: TLSA-Record für %s vorhanden – authentifiziertes TLS beim Transport.", host), ""), det)
	}
	return withDetails(info("dane_tlsa", "DANE/TLSA", 0.0, "Kein DANE/TLSA-Record auf dem MX gefunden (optional; erfordert DNSSEC).", "Optional: nach DNSSEC TLSA-Records für die MX-Hosts veröffentlichen."), det)
}

// ── Group C: opt-in third-party reputation checks (off by default) ──────────

// registrableDomain returns the eTLD+1 (e.g. example.co.uk) for a hostname.
func registrableDomain(domain string) string {
	d := normDomain(domain)
	if d == "" {
		return ""
	}
	if e, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return e
	}
	return d
}

// rdapRegistrationDate fetches the domain registration date via RDAP (rdap.org
// bootstrap → registry). This contacts a third-party service.
func rdapRegistrationDate(ctx context.Context, domain string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/domain/"+domain, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	cl := &http.Client{Timeout: 6 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("rdap status %d", resp.StatusCode)
	}
	body, _ := readLimited(resp.Body, 1*1024*1024)
	var data struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return time.Time{}, err
	}
	for _, e := range data.Events {
		if strings.EqualFold(e.Action, "registration") {
			if t, perr := time.Parse(time.RFC3339, e.Date); perr == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("no registration event")
}

func domainAgeCheck(ctx context.Context, domain string) model.CheckResult {
	reg := registrableDomain(domain)
	if reg == "" {
		return info("domain_age", "Domain-Alter", 0.0, "Keine Domain für die Altersprüfung ermittelbar.", "")
	}
	det := map[string]string{"domain": reg}
	created, err := rdapRegistrationDate(ctx, reg)
	if err != nil || created.IsZero() {
		if err != nil {
			det["rdap_error"] = err.Error()
		}
		return withDetails(info("domain_age", "Domain-Alter", 0.0, fmt.Sprintf("Domain-Alter für %s nicht ermittelbar (RDAP lieferte kein Registrierungsdatum).", reg), "Bei Bedarf manuell per WHOIS/RDAP prüfen."), det)
	}
	ageDays := int(time.Since(created).Hours() / 24)
	det["registered"] = created.Format("2006-01-02")
	det["age_days"] = strconv.Itoa(ageDays)

	// Continuous penalty: a brand-new domain is a strong spam/phishing signal that
	// fades smoothly to zero as the domain matures (≈ 1 year). Quadratic so very
	// young domains are hit hard while the curve flattens out for older ones.
	delta := 0.0
	if ageDays < 365 {
		f := 1 - float64(ageDays)/365.0 // 1.0 at 0 days → 0.0 at one year
		delta = -2.0 * f * f
		delta = float64(int(delta*100)) / 100 // 2 decimals, no math import
	}
	status := "pass"
	switch {
	case delta <= -1.0:
		status = "fail"
	case delta < 0:
		status = "warn"
	}
	det["age_penalty"] = fmt.Sprintf("%.2f", delta)

	var summary, sugg string
	switch status {
	case "fail":
		summary = fmt.Sprintf("Domain %s ist erst %d Tage alt (registriert %s) – sehr junge Domains sind ein starkes Spam-/Phishing-Signal; der Einfluss sinkt, je älter die Domain wird.", reg, ageDays, created.Format("2006-01-02"))
		sugg = "Junge Domains langsam 'warmlaufen' (geringe Volumina, saubere Empfängerlisten) und SPF/DKIM/DMARC vollständig konfigurieren."
	case "warn":
		summary = fmt.Sprintf("Domain %s ist %d Tage alt (registriert %s) – noch relativ jung; viele Filter sind im ersten Jahr vorsichtiger.", reg, ageDays, created.Format("2006-01-02"))
		sugg = "Reputation weiter aufbauen und konstantes, sauberes Sendeverhalten beibehalten."
	default:
		summary = fmt.Sprintf("Domain %s ist %d Tage alt (registriert %s) – etabliertes Domain-Alter.", reg, ageDays, created.Format("2006-01-02"))
	}
	return withDetails(model.CheckResult{ID: "domain_age", Name: "Domain-Alter", Status: status, ScoreDelta: delta, Summary: summary, Suggestion: sugg}, det)
}

// dnsblListed reports whether <name>.<provider> returns a 127.0.0.x listing
// (real hit), ignoring 127.255.255.x error/blocked responses.
func dnsblListed(ctx context.Context, name, provider string) bool {
	ips, err := net.DefaultResolver.LookupHost(ctx, name+"."+provider)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if strings.HasPrefix(ip, "127.0.") {
			return true
		}
	}
	return false
}

func domainBlocklistCheck(ctx context.Context, domain string, providers []string) model.CheckResult {
	reg := registrableDomain(domain)
	if reg == "" || len(providers) == 0 {
		return info("domain_blocklist", "Domain-Blocklist", 0.0, "Keine Domain/Provider für die Domain-Blocklist-Prüfung.", "")
	}
	listed := []string{}
	checked := []string{}
	for _, p := range providers {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		checked = append(checked, p)
		if dnsblListed(ctx, reg, p) {
			listed = append(listed, p)
		}
	}
	det := map[string]string{"domain": reg, "checked_providers": strings.Join(checked, "\n"), "listed_on": joinOrNone(listed)}
	if len(listed) > 0 {
		return withDetails(fail("domain_blocklist", "Domain-Blocklist", -1.5, fmt.Sprintf("Domain %s ist auf %d Domain-Blocklist(en) gelistet: %s.", reg, len(listed), strings.Join(listed, ", ")), "Delisting bei den jeweiligen Anbietern beantragen und die Ursache (kompromittierte Inhalte, Spam-Historie) beheben."), det)
	}
	return withDetails(pass("domain_blocklist", "Domain-Blocklist", 0.2, fmt.Sprintf("Domain %s steht auf keiner der geprüften Domain-Blocklists.", reg), ""), det)
}

func linkBlocklistCheck(ctx context.Context, links []string, providers []string) model.CheckResult {
	if len(providers) == 0 {
		return info("link_blocklist", "Link-Domain-Blocklist", 0.0, "Keine Provider für die Link-Blocklist-Prüfung.", "")
	}
	doms := map[string]struct{}{}
	for _, l := range links {
		if u, err := url.Parse(l); err == nil {
			if rd := registrableDomain(u.Hostname()); rd != "" {
				doms[rd] = struct{}{}
			}
		}
	}
	if len(doms) == 0 {
		return info("link_blocklist", "Link-Domain-Blocklist", 0.0, "Keine Link-Domains zum Prüfen gefunden.", "")
	}
	listed := []string{}
	n := 0
	for d := range doms {
		n++
		if n > 20 { // safety cap on third-party lookups
			break
		}
		for _, p := range providers {
			p = strings.TrimSpace(p)
			if p != "" && dnsblListed(ctx, d, p) {
				listed = append(listed, d+" ("+p+")")
			}
		}
	}
	det := map[string]string{"link_domains_checked": strconv.Itoa(len(doms)), "listed": joinOrNone(listed)}
	if len(listed) > 0 {
		return withDetails(fail("link_blocklist", "Link-Domain-Blocklist", -1.2, fmt.Sprintf("%d verlinkte Domain(s) sind auf URI-Blocklists gelistet: %s.", len(listed), strings.Join(listed, ", ")), "Verlinkte Domains bereinigen oder ersetzen; gelistete Domains beim Anbieter delisten lassen."), det)
	}
	return withDetails(pass("link_blocklist", "Link-Domain-Blocklist", 0.1, fmt.Sprintf("Alle %d geprüften Link-Domain(s) sind sauber (keine URI-Blocklist-Treffer).", len(doms)), ""), det)
}

func withDetails(c model.CheckResult, details map[string]string) model.CheckResult {
	c.TechnicalDetails = details
	return c
}

func enrichCheckResult(c model.CheckResult, ctx checkContext) model.CheckResult {
	c.Category = checkCategory(c.ID)
	c.Severity = checkSeverity(c.Status)
	c.Importance = checkImportance(c.ID)

	// Centralised, importance-weighted scoring. The score starts at 10 and only
	// goes down for problems (no inflation from "expected" passes). Most checks
	// derive their impact purely from (importance × status) so the weighting is
	// consistent and realistic; a few checks compute their own continuous or
	// reputation-based magnitude and keep it.
	switch c.ID {
	case "domain_age", "rbl", "spamassassin", "rspamd":
		// keep the self-computed ScoreDelta
	default:
		c.ScoreDelta = scoreFor(c.Importance, c.Status)
	}
	if c.TechnicalDetails == nil {
		c.TechnicalDetails = map[string]string{}
	}
	addCheckSpecificDetails(c.TechnicalDetails, c.ID, ctx)
	switch c.ID {
	case "spf":
		c.Name = "SPF für " + emptyFallback(ctx.EnvelopeDomain, "Envelope-From")
		c.TechnicalDetails["remote_ip"] = emptyFallback(ctx.Message.RemoteIP, "unknown")
		c.TechnicalDetails["helo_ehlo"] = emptyFallback(ctx.Message.HELO, "unknown")
		c.TechnicalDetails["envelope_from_domain"] = emptyFallback(ctx.EnvelopeDomain, "none")
		c.TechnicalDetails["header_from_domain"] = emptyFallback(ctx.FromDomain, "none")
		c.TechnicalDetails["spf_result"] = emptyFallback(ctx.SPFResult, "none")
		c.TechnicalDetails["spf_records"] = joinOrNone(ctx.SPFRecords)
		c.Explanation = "SPF legt fest, welche Server im Namen der Envelope-From- oder Bounce-Domain senden dürfen. Empfänger prüfen dabei die sendende IP gegen den SPF-TXT-Record dieser Domain. Gmail, Outlook, Yahoo und große Gateways gewichten SPF besonders stark, wenn DMARC aktiv ist oder die IP-Reputation noch schwach ist. Wichtigkeit: hoch – ohne SPF-Pass kann DMARC nicht greifen und viele Provider erhöhen den Spam-Score oder lehnen direkt ab."
		c.Recommendation = spfRecommendation(ctx)
		c.DocLinks = spfDocLinks()
	case "dkim":
		c.TechnicalDetails["header_from_domain"] = emptyFallback(ctx.FromDomain, "none")
		c.TechnicalDetails["dkim_result"] = emptyFallback(ctx.DKIMResult, "none")
		c.TechnicalDetails["dkim_domain"] = emptyFallback(ctx.DKIMDomain, "none")
		c.TechnicalDetails["dkim_signature"] = emptyFallback(ctx.Headers.Get("DKIM-Signature"), "none")
		c.Explanation = "DKIM signiert relevante Header und Body-Inhalte kryptografisch. Der empfangende Server prüft den Public Key per DNS unter dem Selector der DKIM-Signatur. Gmail, Outlook, Yahoo und Apple Mail nutzen DKIM stark, um Manipulationen, Weiterleitungsprobleme und Domain-Spoofing zu erkennen. Wichtigkeit: sehr hoch – DKIM ist neben SPF die zweite Säule von DMARC und trägt maßgeblich zur Domain-Reputation bei. Ohne DKIM-Signatur landen Mails häufiger im Spam-Ordner."
		c.Recommendation = dkimRecommendation(ctx)
		c.DocLinks = dkimDocLinks()
	case "dmarc":
		c.TechnicalDetails["header_from_domain"] = emptyFallback(ctx.FromDomain, "none")
		c.TechnicalDetails["spf_result"] = emptyFallback(ctx.SPFResult, "none")
		c.TechnicalDetails["dkim_result"] = emptyFallback(ctx.DKIMResult, "none")
		c.TechnicalDetails["spf_aligned"] = strconv.FormatBool(ctx.AlignedSPF)
		c.TechnicalDetails["dkim_aligned"] = strconv.FormatBool(ctx.AlignedDKIM)
		c.TechnicalDetails["dmarc_result"] = emptyFallback(ctx.DMARCResult, "none")
		c.TechnicalDetails["dmarc_records"] = joinOrNone(ctx.DMARCRecords)
		c.TechnicalDetails["policy"] = emptyFallback(ctx.DMARCPolicy, "none")
		c.Explanation = "DMARC verbindet SPF und DKIM mit der sichtbaren From-Domain. Eine Nachricht besteht DMARC, wenn SPF oder DKIM erfolgreich ist und die jeweilige Domain zur From-Domain passt. Moderne Provider erwarten für seriöse Versanddomains mindestens eine DMARC-Policy; für Bulk-Mail ist DMARC seit 2024 (Gmail/Yahoo-Anforderungen) praktisch Pflicht. Wichtigkeit: kritisch – ohne DMARC können andere Provider deine Domain für Phishing missbrauchen (Domain-Spoofing), und große Provider stufen nicht-DMARC-authentifizierte Bulk-Mails als Spam ein."
		c.Recommendation = dmarcRecommendation(ctx)
		c.DocLinks = dmarcDocLinks()
	case "ptr":
		c.TechnicalDetails["remote_ip"] = emptyFallback(ctx.Message.RemoteIP, "unknown")
		c.TechnicalDetails["helo_ehlo"] = emptyFallback(ctx.Message.HELO, "unknown")
		c.TechnicalDetails["expected"] = fmt.Sprintf("IP %s -> PTR %s -> A/AAAA %s", emptyFallback(ctx.Message.RemoteIP, "unknown"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.RemoteIP, "sender-ip"))
		c.Explanation = "Reverse DNS (PTR/rDNS) zeigt, welcher Hostname zu einer sendenden IP gehört. Empfänger prüfen typischerweise: (1) Hat die IP einen gültigen PTR-Eintrag? (2) Löst dieser PTR-Name per Forward-DNS wieder auf die gleiche IP auf (Forward-Confirmed rDNS)? (3) Stimmt der PTR-Name plausibel mit HELO/EHLO überein? Outlook/Exchange, Barracuda, Mimecast und Unternehmens-Gateways lehnen bei fehlendem PTR direkt ab. Gmail und Yahoo nutzen es als Qualitätssignal. Wichtigkeit: sehr hoch – fehlender oder inkonsistenter PTR-Record ist einer der häufigsten Gründe für direkte Ablehnung durch Unternehmens-Mailgateways. PTR-Records werden beim IP-Hosting-Provider gesetzt, nicht im eigenen DNS."
		c.Recommendation = fmt.Sprintf("PTR-Record für IP %s setzen (beim IP-/Hosting-Provider, nicht im eigenen DNS).\n\nZielzustand:\n  %s -> PTR -> %s\n  %s -> A   -> %s\n\nPostfix: myhostname = %s\nExim:    primary_hostname = %s\n\nBei Hetzner: Server > Networking > Reverse DNS\nBei DigitalOcean: Networking > Floating IP > Edit PTR\nPrüfen: dig -x %s +short", emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"), emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"))
		c.DocLinks = []model.DocLink{
			{Title: "PTR/rDNS Lookup – MXToolbox", URL: "https://mxtoolbox.com/ReverseLookup.aspx"},
			{Title: "Forward-confirmed rDNS – Wikipedia", URL: "https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS"},
			{Title: "Outlook Sender Requirements", URL: "https://sendersupport.olc.protection.outlook.com/pm/policies.aspx"},
		}
	case "helo":
		c.TechnicalDetails["helo_ehlo"] = emptyFallback(ctx.Message.HELO, "unknown")
		c.TechnicalDetails["remote_ip"] = emptyFallback(ctx.Message.RemoteIP, "unknown")
		c.Explanation = "HELO/EHLO ist der Hostname, mit dem sich der sendende MTA beim Empfänger-SMTP anmeldet. Er sollte ein stabiler, vollqualifizierter Domainname (FQDN) sein – kein 'localhost', keine rohe IP-Adresse ([203.0.113.1]) und kein zufälliger Container-Name. Empfangende Systeme prüfen: Ist der HELO-Name ein gültiger FQDN? Stimmt er mit dem PTR/rDNS der sendenden IP überein? Hat er einen A/AAAA-Record? Wichtigkeit: hoch – SpamAssassin wertet HELO_DYNAMIC, HELO_NO_DOMAIN, HELO_IP_4_5_6 mit negativen Scores; viele kommerzielle Gateways lehnen bei inkonsistentem HELO/PTR ab. Der HELO-Name wird dauerhaft im Server konfiguriert (nicht per Mail änderbar)."
		c.Recommendation = fmt.Sprintf("HELO/EHLO-Hostname auf stabilen FQDN setzen, der zu IP %s und PTR passt.\n\nPostfix (/etc/postfix/main.cf):\n  myhostname = %s\n\nExim (/etc/exim4/exim4.conf):\n  primary_hostname = %s\n\nSendmail:\n  Djmailhost.example.org (in sendmail.mc)\n\nPrüfen: telnet %s 25 -> EHLO senden -> Antwort vergleichen", emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"))
		c.DocLinks = []model.DocLink{
			{Title: "RFC 5321 – SMTP EHLO", URL: "https://www.rfc-editor.org/rfc/rfc5321#section-4.1.1.1"},
			{Title: "SpamAssassin HELO-Tests", URL: "https://spamassassin.apache.org/tests_3_4_x.html"},
		}
	case "mx_records":
		c.Explanation = "MX-Records definieren, welcher Mailserver E-Mails für eine Domain empfängt. Für reine Versanddomains ist ein MX technisch nicht zwingend, aber Domains ohne MX werden von vielen Spamfiltern misstrauischer eingestuft – weil wegwerf-artige oder kompromittierte Domains oft keinen MX haben. Außerdem setzen Bounce-Handling, DMARC-Forensik-Reports (ruf=) und Reply-To-Routing Empfangbarkeit voraus. Wichtigkeit: mittel – für transaktionale Mails nicht kritisch, aber für professionelles Domain-Setup empfohlen."
		if c.Recommendation == "" {
			c.Recommendation = fmt.Sprintf("MX-Record für %s setzen:\n\n  Name: %s\n  Typ:  MX 10\n  Wert: mail.%s\n\nDann A/AAAA für mail.%s setzen.\nRedundanz: zweiten MX mit Priorität 20 empfohlen.\nPrüfen: dig MX %s +short", emptyFallback(ctx.FromDomain, ctx.EnvelopeDomain), emptyFallback(ctx.FromDomain, ctx.EnvelopeDomain), emptyFallback(ctx.FromDomain, ctx.EnvelopeDomain), emptyFallback(ctx.FromDomain, ctx.EnvelopeDomain), emptyFallback(ctx.FromDomain, ctx.EnvelopeDomain))
		}
		c.DocLinks = []model.DocLink{
			{Title: "MX-Record prüfen – MXToolbox", URL: "https://mxtoolbox.com/MXLookup.aspx"},
			{Title: "RFC 5321 – MX-Record Semantik", URL: "https://www.rfc-editor.org/rfc/rfc5321#section-5"},
		}
	case "address_records":
		c.Explanation = "A/AAAA-Records zeigen, auf welche IPs ein Hostname zeigt. Mailserver-Hostnamen aus HELO/EHLO und MX-Einträgen müssen sauber auflösen. Ein HELO-Name ohne gültigen A/AAAA-Record erhöht Spam-Scores und signalisiert schlechte DNS-Hygiene. Tracking-Subdomains und Bounce-Domains sollten ebenfalls konsistent auflösen. Wichtigkeit: hoch – inkonsistente DNS-Auflösung ist ein verlässliches Zeichen für schlechte Infrastruktur-Qualität und erhöht den Spam-Score bei fast allen Filtersystemen."
		if c.Recommendation == "" {
			c.Recommendation = fmt.Sprintf("A-Record setzen:\n\n  Name: %s\n  Typ:  A\n  Wert: %s\n\nBei IPv6: zusätzlich AAAA und PTR für IPv6.\nPrüfen: dig A %s +short", emptyFallback(ctx.Message.HELO, "mail.example.org"), emptyFallback(ctx.Message.RemoteIP, "203.0.113.10"), emptyFallback(ctx.Message.HELO, "mail.example.org"))
		}
		c.DocLinks = []model.DocLink{
			{Title: "DNS A-Record erklärt – Cloudflare", URL: "https://www.cloudflare.com/learning/dns/dns-records/dns-a-record/"},
			{Title: "DNS-Diagnose – MXToolbox", URL: "https://mxtoolbox.com/DNSLookup.aspx"},
		}
	case "spamassassin":
		c.Explanation = "SpamAssassin bewertet Nachrichten mit einem gewichteten Regelsystem aus mehreren hundert Tests: Authentifizierung, IP-Reputation, Header-Konsistenz, Inhaltsmuster, MIME-Struktur, URLs und Bayes-Filter. Ab einem Schwellwert (typisch 5.0) gilt eine Mail als Spam. SpamAssassin ist bei ISPs, Unternehmens-Gateways, Postfix/Dovecot-Setups und cPanel-Hosting weit verbreitet. Wichtigkeit: hoch – hohe SA-Scores sind ein verlässlicher Indikator für reale Zustellprobleme. Die einzelnen Regeln zeigen genau, wo die Probleme liegen; jede Regel sollte einzeln nachgeschlagen und behoben werden."
		if c.Recommendation == "" {
			c.Recommendation = "SA-Regeln nach Gewicht priorisieren – nicht Text verschleiern:\n\n1. Authentifizierung: SPF/DKIM/DMARC ohne pass verschlechtern SA-Score signifikant\n2. IP-Reputation: RBL-Listings (RCVD_IN_*) sofort beheben\n3. Header: Date, Message-ID, From, Return-Path korrekt setzen\n4. Inhalt: Trigger-Wörter, ALL CAPS, excessive Ausrufezeichen\n5. Links: URL-Shortener, fremde Redirect-Ketten\n\nJede Regel nachschlagen: https://spamassassin.apache.org/tests_3_4_x.html"
		}
		c.DocLinks = []model.DocLink{
			{Title: "SpamAssassin Regelwerk", URL: "https://spamassassin.apache.org/tests_3_4_x.html"},
			{Title: "SA Score-Konfiguration", URL: "https://wiki.apache.org/spamassassin/WritingRules"},
		}
	case "rbl":
		c.Explanation = "RBLs/DNSBLs listen IPs, die Spam-, Abuse-, Botnet-, Proxy- oder Angriffssignale ausgelöst haben. Die bekanntesten Listen (Spamhaus SBL/XBL/PBL, Barracuda, SpamCop) werden von großen Mailbox-Providern, kommerziellen Gateways und selbst betriebenen Mailservern aktiv genutzt. Wichtigkeit: sehr hoch – ein Spamhaus-Listing führt bei Gmail, Outlook und Yahoo nahezu sicher zur Ablehnung oder Spam-Einstufung. Die richtige Reihenfolge: erst Ursache stoppen (offenes Relay, kompromittiertes Konto, Botnet), dann Infrastruktur sichern, dann Delisting beantragen. Delisting ohne Ursachenbehebung führt zur Wiederlisting."
		if c.Recommendation == "" {
			c.Recommendation = rblGenericRecommendation(ctx.Message.RemoteIP)
		}
		c.DocLinks = []model.DocLink{
			{Title: "Spamhaus Check & Delist", URL: "https://check.spamhaus.org/"},
			{Title: "MXToolbox Blacklist Check", URL: "https://mxtoolbox.com/blacklists.aspx"},
			{Title: "MultiRBL – mehrere Listen prüfen", URL: "https://multirbl.valli.org/"},
			{Title: "Barracuda Reputation Lookup", URL: "https://www.barracudacentral.org/lookups"},
		}
	default:
		c.Explanation = defaultExplanation(c.ID)
		if c.Recommendation == "" {
			c.Recommendation = defaultRecommendation(c, ctx)
		}
		if len(c.DocLinks) == 0 {
			c.DocLinks = defaultDocLinks(c.ID)
		}
	}
	if c.Recommendation == "" {
		c.Recommendation = c.Suggestion
	}
	return c
}

func addCheckSpecificDetails(details map[string]string, id string, ctx checkContext) {
	body := ctx.ParsedBody
	switch id {
	case "from_alignment":
		details["header_from"] = emptyFallback(ctx.Headers.Get("From"), "none")
		details["smtp_mail_from"] = emptyFallback(ctx.Message.SMTPFrom, "none")
		details["header_from_domain"] = emptyFallback(ctx.FromDomain, "none")
		details["envelope_from_domain"] = emptyFallback(ctx.EnvelopeDomain, "none")
	case "return_path":
		details["return_path"] = emptyFallback(ctx.ReturnPath, "none")
		details["return_path_domain"] = emptyFallback(ctx.ReturnDomain, "none")
		details["smtp_mail_from"] = emptyFallback(ctx.Message.SMTPFrom, "none")
	case "reply_to":
		details["header_from"] = emptyFallback(ctx.Headers.Get("From"), "none")
		details["reply_to"] = emptyFallback(ctx.Headers.Get("Reply-To"), "none")
	case "spf_alignment":
		details["header_from_domain"] = emptyFallback(ctx.FromDomain, "none")
		details["envelope_from_domain"] = emptyFallback(ctx.EnvelopeDomain, "none")
		details["spf_result"] = emptyFallback(ctx.SPFResult, "none")
		details["spf_aligned"] = strconv.FormatBool(ctx.AlignedSPF)
	case "dkim_alignment":
		details["header_from_domain"] = emptyFallback(ctx.FromDomain, "none")
		details["dkim_result"] = emptyFallback(ctx.DKIMResult, "none")
		details["dkim_domain"] = emptyFallback(ctx.DKIMDomain, "none")
		details["dkim_aligned"] = strconv.FormatBool(ctx.AlignedDKIM)
	case "dmarc_alignment":
		details["header_from_domain"] = emptyFallback(ctx.FromDomain, "none")
		details["spf_result"] = emptyFallback(ctx.SPFResult, "none")
		details["dkim_result"] = emptyFallback(ctx.DKIMResult, "none")
		details["spf_aligned"] = strconv.FormatBool(ctx.AlignedSPF)
		details["dkim_aligned"] = strconv.FormatBool(ctx.AlignedDKIM)
	case "received_chain", "tls_transport":
		details["remote_ip"] = emptyFallback(ctx.Message.RemoteIP, "unknown")
		details["helo_ehlo"] = emptyFallback(ctx.Message.HELO, "unknown")
		details["received_count"] = strconv.Itoa(len(ctx.ReceivedLines))
		details["received_headers"] = joinOrNone(ctx.ReceivedLines)
	case "arc":
		details["arc_seal"] = emptyFallback(ctx.Headers.Get("ARC-Seal"), "none")
		details["arc_message_signature"] = emptyFallback(ctx.Headers.Get("ARC-Message-Signature"), "none")
	case "mime_ct", "mime_boundary", "multipart_alt", "plain_text", "attachments", "image_text_ratio", "charset":
		addBodyDetails(details, ctx)
	case "links", "shortener", "tracking_links":
		details["link_count"] = strconv.Itoa(len(ctx.Links))
		details["links"] = joinOrNone(ctx.Links)
	case "html", "hidden_html", "html_validity":
		addBodyDetails(details, ctx)
		details["html_chars"] = strconv.Itoa(len([]rune(body.HTML)))
	case "subject", "subject_exclaim", "subject_caps":
		subject := ctx.Headers.Get("Subject")
		details["subject"] = emptyFallback(subject, "none")
		details["subject_chars"] = strconv.Itoa(len([]rune(subject)))
		details["exclamation_count"] = strconv.Itoa(strings.Count(subject, "!"))
	case "date", "date_skew":
		details["date_header"] = emptyFallback(ctx.Headers.Get("Date"), "none")
	case "message_id":
		details["message_id"] = firstNonEmpty(ctx.Headers.Get("Message-ID"), ctx.Headers.Get("Message-Id"), "none")
	case "list_unsub":
		details["list_unsubscribe"] = emptyFallback(ctx.Headers.Get("List-Unsubscribe"), "none")
		details["list_id"] = emptyFallback(ctx.Headers.Get("List-ID"), "none")
		details["precedence"] = emptyFallback(ctx.Headers.Get("Precedence"), "none")
	case "preheader":
		addBodyDetails(details, ctx)
	case "unicode":
		details["text_chars"] = strconv.Itoa(len([]rune(body.AllText)))
	}
}

func addBodyDetails(details map[string]string, ctx checkContext) {
	body := ctx.ParsedBody
	details["content_type"] = emptyFallback(ctx.Headers.Get("Content-Type"), "none")
	details["content_transfer_encoding"] = emptyFallback(ctx.Headers.Get("Content-Transfer-Encoding"), "none")
	details["part_count"] = strconv.Itoa(body.PartCount)
	details["has_text_part"] = strconv.FormatBool(body.HasTextPart)
	details["has_html_part"] = strconv.FormatBool(body.HasHTMLPart)
	details["text_chars"] = strconv.Itoa(len([]rune(body.Text)))
	details["html_chars"] = strconv.Itoa(len([]rune(body.HTML)))
	details["attachment_count"] = strconv.Itoa(body.Attachments)
	details["image_count"] = strconv.Itoa(body.Images)
	details["charset"] = emptyFallback(body.Charset, "none")
}

func checkCategory(id string) string {
	switch id {
	case "spf", "dkim", "dmarc", "spf_alignment", "dkim_alignment", "dmarc_alignment", "from_alignment", "return_path", "reply_to",
		"dmarc_policy", "spf_strictness", "dkim_keylength", "display_name":
		return "Authentifizierung"
	case "ptr", "helo", "mx_records", "address_records", "tls_transport", "received_chain", "rbl",
		"ptr_pattern", "envelope_mx", "mta_sts", "tls_rpt", "bimi", "dnssec", "dane_tlsa", "domain_age":
		return "DNS und Infrastruktur"
	case "spamassassin", "rspamd", "domain_blocklist", "link_blocklist":
		return "Spamfilter"
	case "mime_ct", "mime_boundary", "plain_text", "multipart_alt", "attachments", "image_text_ratio", "charset", "links", "shortener", "tracking_links", "html", "hidden_html", "html_validity", "subject", "subject_exclaim", "subject_caps", "unicode", "list_unsub", "preheader":
		return "Format und Inhalt"
	default:
		return "Header und Rohdaten"
	}
}

// checkImportance classifies how much a check matters for deliverability, mirroring
// the reference on the /about page: Kritisch | Wichtig | Empfohlen | Optional.
func checkImportance(id string) string {
	switch id {
	case "spf", "dkim", "dmarc", "ptr", "rbl", "domain_blocklist", "link_blocklist":
		// Authentication + reputation: failing these is what really blocks mail.
		return "Kritisch"
	case "spf_strictness", "dkim_keylength", "dmarc_policy",
		"spf_alignment", "dkim_alignment", "dmarc_alignment", "from_alignment",
		"helo", "mx_records", "tls_transport",
		"spamassassin", "rspamd", "display_name",
		"list_unsub", "mime_parse", "mime_ct", "mime_boundary", "message_id", "received_chain":
		return "Wichtig"
	case "mta_sts", "tls_rpt", "bimi", "dnssec", "dane_tlsa", "arc", "preheader":
		return "Optional"
	default:
		return "Empfohlen"
	}
}

// essentialPerfectCap is the highest score a message can get when one of the
// essential checks is not a clean pass.
const essentialPerfectCap = 9.5

// essentialsAllPass reports whether every essential, always-present check
// (SPF, DKIM, DMARC, PTR) actually passed. Checks that aren't present in the
// report (e.g. behind a disabled feature) are not required.
func essentialsAllPass(checks []model.CheckResult) bool {
	essential := map[string]bool{"spf": true, "dkim": true, "dmarc": true, "ptr": true}
	for _, c := range checks {
		if essential[c.ID] && c.Status != "pass" {
			return false
		}
	}
	return true
}

// scoreFor returns a check's contribution to the score from its importance tier
// and status. Deductions only — passes/infos are neutral (10 = clean baseline);
// optional/advanced signals never penalise. Tuned to mirror how real mail systems
// weight things: authentication and reputation dominate, content nits are minor.
func scoreFor(importance, status string) float64 {
	switch status {
	case "fail":
		switch importance {
		case "Kritisch":
			return -2.6
		case "Wichtig":
			return -1.3
		case "Optional":
			return 0
		default: // Empfohlen
			return -0.5
		}
	case "warn":
		switch importance {
		case "Kritisch":
			return -1.3
		case "Wichtig":
			return -0.6
		case "Optional":
			return 0
		default: // Empfohlen
			return -0.25
		}
	default: // pass / info → no reward, no penalty
		return 0
	}
}

func checkSeverity(status string) string {
	switch status {
	case "fail":
		return "high"
	case "warn":
		return "medium"
	case "pass":
		return "low"
	default:
		return "info"
	}
}

func defaultExplanation(id string) string {
	switch id {
	case "dmarc_policy":
		return "Die DMARC-Policy (p=) bestimmt, was Empfänger mit Mails tun, die DMARC nicht bestehen. p=none = nur Monitoring (kein Schutz), p=quarantine = ab in den Spam, p=reject = komplett ablehnen. Wichtigkeit: hoch – nur quarantine/reject schützen deine Domain aktiv vor Spoofing/Phishing. Gmail & Yahoo erwarten von Bulk-Sendern zunehmend mindestens eine durchgesetzte Policy. Vorgehen: mit p=none + rua-Reporting starten, Quellen sauber konfigurieren, dann schrittweise auf quarantine und reject erhöhen."
	case "spf_strictness":
		return "Der abschließende all-Mechanismus eines SPF-Records legt fest, wie streng nicht-autorisierte Server behandelt werden: -all = hardfail (empfohlen), ~all = softfail, ?all = neutral (wirkungslos), +all = erlaubt alle (gefährlich). Außerdem begrenzt RFC 7208 SPF auf 10 DNS-Lookups – wird das überschritten, schlägt SPF mit PermError fehl. Wichtigkeit: hoch – ein zu lascher oder kaputter SPF-Record untergräbt SPF und damit DMARC."
	case "dkim_keylength":
		return "Die Stärke des DKIM-Schlüssels bestimmt die Fälschungssicherheit der Signatur. 512/768-Bit-RSA gilt als gebrochen, 1024 Bit als veraltet; empfohlen sind mindestens 2048-Bit-RSA oder Ed25519. Wichtigkeit: mittel bis hoch – große Provider werten schwache Schlüssel ab oder ignorieren sie, wodurch DKIM (und damit DMARC) effektiv ausfällt. Bei Schlüsselwechsel den Selector rotieren."
	case "ptr_pattern":
		return "Selbst wenn Forward-confirmed rDNS technisch besteht, achten Spamfilter auf das Muster des PTR-Hostnamens. Namen wie '203-0-113-5.dynamic.isp.net', 'dsl-…', 'pool-…' oder 'customer-…' signalisieren Endkunden-/Dynamic-IPs, von denen seriöse Mailserver normalerweise nicht direkt senden. Wichtigkeit: hoch – SpamAssassin (RDNS_DYNAMIC) und viele Gateways werten solche Muster stark negativ. Lösung: dedizierten, sprechenden Mailserver-PTR beim Hoster setzen."
	case "display_name":
		return "Der Anzeigename im From-Header ('Friendly From') ist frei wählbar und wird von Phishing stark missbraucht: ein vertrauter Marken- oder Personenname als Anzeige, während die echte Absenderdomain eine ganz andere ist. Wichtigkeit: hoch – Provider und Security-Gateways erkennen Display-Name-Spoofing und Marken-Imitation und stufen solche Mails als Phishing ein. Anzeigename und tatsächliche Absenderdomain konsistent halten."
	case "envelope_mx":
		return "Der Return-Path/Envelope-From ist die Bounce-Adresse: dorthin gehen Unzustellbarkeits-Meldungen (DSN/NDR). Kann diese Domain keine Mail empfangen (kein MX, kein A/AAAA), gehen Bounces verloren – schlecht fürs Listen-Hygiene-Management und ein Qualitätssignal für Filter. Wichtigkeit: mittel – eine empfangsfähige Bounce-Domain gehört zu einem professionellen Versand-Setup."
	case "mta_sts":
		return "MTA-STS (RFC 8461) erlaubt einer Domain, verschlüsselten SMTP-Transport (TLS) verbindlich zu verlangen, statt ihn nur opportunistisch zu nutzen. Sendende Server prüfen die per HTTPS veröffentlichte Policy und brechen ab, wenn kein gültiges TLS möglich ist – das schützt vor Downgrade-/Man-in-the-Middle-Angriffen. Wichtigkeit: mittel – kein direkter Inbox-Platzierungsfaktor, aber ein klares Reifesignal und zunehmend Standard bei seriösen Absendern."
	case "tls_rpt":
		return "TLS-RPT (RFC 8460) lässt empfangende Server aggregierte Berichte über fehlgeschlagene oder herabgestufte TLS-Verbindungen an eine Reporting-Adresse schicken. So bemerkst du TLS-/MTA-STS-Probleme, bevor sie zu Zustellausfällen führen. Wichtigkeit: gering bis mittel – ein Monitoring-/Reifesignal, sinnvoll in Kombination mit MTA-STS."
	case "bimi":
		return "BIMI (Brand Indicators for Message Identification) zeigt bei unterstützenden Providern (Gmail, Apple Mail, Yahoo) dein Markenlogo neben der Nachricht an. Voraussetzung ist eine durchgesetzte DMARC-Policy (quarantine/reject) und ein SVG-Logo (bei manchen Providern zusätzlich ein VMC-Zertifikat). Wichtigkeit: gering für die Zustellung selbst, aber ein starkes Vertrauens-/Reifesignal und Beleg für ein vollständig konfiguriertes Authentifizierungs-Setup."
	case "dnssec":
		return "DNSSEC signiert DNS-Antworten kryptografisch und schützt vor DNS-Manipulation (Cache-Poisoning, Spoofing). Eine signierte Absenderzone ist ein Reifesignal und Voraussetzung für DANE. Wichtigkeit: gering bis mittel für die reine Inbox-Platzierung, aber relevant für die Gesamtintegrität der Mail-Infrastruktur."
	case "dane_tlsa":
		return "DANE (TLSA-Records, RFC 7672) bindet das TLS-Zertifikat des Mailservers per DNSSEC an die Domain und erzwingt so authentifiziertes TLS beim SMTP-Transport – eine Alternative/Ergänzung zu MTA-STS. Voraussetzung ist DNSSEC. Wichtigkeit: gering für Inbox-Platzierung, aber ein hohes Sicherheits-/Reifesignal, v. a. im europäischen/Behörden-Umfeld."
	case "domain_age":
		return "Das Registrierungsalter der Absenderdomain ist ein starkes Reputationssignal. Frisch registrierte Domains werden von Gmail, Outlook und Spamhaus mit großem Misstrauen behandelt – Domains unter 30 Tagen sind ein klassisches Spam-/Phishing-Muster. Wichtigkeit: hoch für neue Domains – ältere, etablierte Domains genießen Vertrauensvorschuss. Hinweis: weiches Signal (alte Domains können gekapert, neue legitim sein); wird per RDAP bei einem Dritt-Dienst abgefragt und ist daher opt-in."
	case "domain_blocklist":
		return "Domain-Blocklists (z. B. Spamhaus DBL) listen Domains, die in Spam/Phishing auftauchen – unabhängig von der sendenden IP. Eine gelistete Absenderdomain führt bei vielen Providern direkt zu Ablehnung oder Spam-Einordnung. Wichtigkeit: sehr hoch, falls gelistet. Hinweis: DNS-Abfrage beim Blocklist-Anbieter (Dritt-Dienst), daher opt-in; öffentliche Resolver werden von Spamhaus geblockt – eigenen Resolver verwenden."
	case "link_blocklist":
		return "URI-/Domain-Blocklists (URIBL, SURBL, Spamhaus DBL) prüfen die in der Mail verlinkten Domains gegen bekannte Spam-/Malware-Domains. Da Spam fast immer einen Link enthält, ist das eines der wirksamsten Filtersignale überhaupt. Wichtigkeit: sehr hoch, falls eine verlinkte Domain gelistet ist. Hinweis: DNS-Abfrage beim Blocklist-Anbieter (Dritt-Dienst), daher opt-in."
	case "from_alignment":
		return "From-Alignment prüft, ob Envelope-From (SMTP MAIL FROM) und Header-From (sichtbare Absenderadresse) zur gleichen Domain gehören. Abweichungen sind technisch möglich (z. B. ESP-Bounce-Adressen), können aber DMARC-Alignment gefährden und Spamfiltern Muster für Spoofing-Versuche liefern. Wichtigkeit: mittel – viele Nutzer prüfen die sichtbare From-Adresse; Mismatch kann Vertrauen kosten und DMARC-SPF-Alignment brechen. Tipp: Bounce-Domains als Subdomain der From-Domain konfigurieren."
	case "spf_alignment":
		return "SPF-Alignment prüft, ob die Envelope-From-Domain (MAIL FROM) und die sichtbare Header-From-Domain zusammenpassen. Für DMARC muss SPF-Alignment stimmen – andernfalls kann SPF zwar bestehen, aber DMARC trotzdem scheitern. Wichtigkeit: hoch – ESPs nutzen oft eigene Bounce-Domains; diese müssen als Subdomain der From-Domain konfiguriert sein oder DKIM muss DMARC alleine tragen. Tipp: entweder Bounce-Domain angleichen oder sicherstellen, dass DKIM-Alignment funktioniert."
	case "dkim_alignment":
		return "DKIM-Alignment prüft, ob die Domain im d=-Tag der DKIM-Signatur zur sichtbaren Header-From-Domain passt. Nur aligned bestandenes DKIM zählt für DMARC. Wichtigkeit: hoch – ohne korrekt aligntes DKIM kann DMARC scheitern, selbst wenn die Signatur technisch gültig ist. Tipp: Signing-Keys von ESPs (Mailchimp, Sendgrid etc.) müssen auf der eigenen Domain oder einer autorisierten Subdomain konfiguriert sein, nicht auf der ESP-Domain."
	case "dmarc_alignment":
		return "DMARC-Alignment ist der Gesamtcheck: Besteht SPF oder DKIM, UND ist die jeweilige Domain zur sichtbaren From-Domain aligned? Nur wenn mindestens einer dieser beiden Pfade stimmt, zählt DMARC als bestanden. Wichtigkeit: kritisch – Gmail, Yahoo, Apple Mail und Outlook setzen für Bulk-Sender DMARC-Alignment voraus; ohne aligned Pass scheitert DMARC-Enforcement und die Domain ist offen für Spoofing."
	case "return_path":
		return "Return-Path enthält die Bounce-Adresse (Envelope-From / SMTP MAIL FROM). Hierhin gehen Delivery Status Notifications (DSN/NDR) bei Zustellfehlern. Wichtigkeit: mittel – Return-Path sollte zur SPF-Domain passen und mit dem SMTP-Envelope-From konsistent sein. Viele Spamfilter prüfen Return-Path auf Domain-Alignment, fehlende MX-Records und Blacklist-Status. Tipp: Bounce-Adressen auf einer eigenen Subdomain (z. B. bounce.example.org) betreiben und SPF dafür pflegen."
	case "reply_to":
		return "Reply-To steuert, wohin Antworten gehen, wenn Nutzer auf 'Antworten' klicken. Wichtigkeit: gering bis mittel – eine Abweichung zur From-Adresse kann legitim sein (Support-Alias, Teampostfach), ist aber auch ein bekanntes Phishing-Signal. Einige Spamfilter bewerten Reply-To-Domain gegen From-Domain und melden bei starker Abweichung (z. B. andere TLD oder kostenloser Webmailer) einen Verdacht. Tipp: Reply-To nur setzen wenn nötig und dann zur eigenen Domain passend."
	case "mime_ct":
		return "Content-Type beschreibt den Medientyp der Nachricht. Wichtigkeit: hoch – ein fehlerhafter oder fehlender Content-Type verhindert korrektes Rendering in Mailclients und führt zu erhöhten Spam-Scores bei SpamAssassin und Rspamd. RFC 2045 schreibt vor, dass jede MIME-Nachricht einen gültigen Content-Type-Header enthalten muss. Tipp: Mailversand-Bibliothek oder MTA erzeugt diesen Header in der Regel automatisch – prüfen ob der MTA korrekt konfiguriert ist."
	case "mime_boundary":
		return "Multipart-Nachrichten benötigen eine eindeutige Boundary-Zeichenkette, die alle Teile trennt. Wichtigkeit: hoch – eine fehlende oder kollidierende Boundary macht die Nachricht unparsbar. SpamAssassin, Rspamd und viele Gateway-Scanner werten kaputte MIME-Strukturen stark negativ. Tipp: Boundary-String darf in keinem der MIME-Parts vorkommen; eine zufällige UUID als Boundary ist bewährt."
	case "multipart_alt":
		return "Multipart/alternative ist das empfohlene Format für HTML-Mails: ein text/plain-Part und ein text/html-Part. Wichtigkeit: mittel – der Empfänger-Client wählt den am besten geeigneten Part. Fehlt der text/plain-Part, können Mails in Text-only-Clients unlesbar werden, und Spamfilter sehen reines HTML als Spam-Signal. Tipp: Plaintext-Version immer mitschicken, auch wenn sie nur eine Kurzversion des HTML-Inhalts ist."
	case "plain_text":
		return "Ein text/plain-Part erhöht Kompatibilität mit Text-Clients, Screen-Readern und Archivierungssystemen erheblich. Wichtigkeit: mittel – reine HTML-Mails ohne Plaintext-Äquivalent erzielen bei SpamAssassin (MIME_HTML_ONLY) und Rspamd negative Scores. Gmail und Outlook rendern Plaintext-Parts separat und nutzen sie für Suche und Preheader-Erkennung. Tipp: Auch eine einfache Text-Version reicht – einfach den HTML-Inhalt ohne Tags darstellen."
	case "attachments":
		return "Anhänge erhöhen Größe, Risiko und Scanaufwand. Wichtigkeit: situationsabhängig – ausführbare Dateitypen (exe, js, vbs, bat) werden von den meisten Providern blockiert. Archive (zip, rar) werden auf Malware gescannt. Große Anhänge reduzieren Zustellwahrscheinlichkeit und erhöhen Bounce-Risiko durch Quotas. Tipp: Dateien besser extern verlinken (Cloud-Speicher, eigene Download-URL); Office-Dateien mit Makros sind besonders problematisch."
	case "image_text_ratio":
		return "Mails mit vielen Bildern und wenig Text sind ein klassisches Spam-Signal, weil Spammer früh lernten, Text in Bilder zu verlagern, um Textfilter zu umgehen. Wichtigkeit: mittel – SpamAssassin (HTML_IMAGE_RATIO_*) und Rspamd bewerten ein ungünstiges Bild/Text-Verhältnis negativ. Tipp: zentrale Aussage immer auch als Text ausdrücken, Bilder mit Alt-Text versehen, kein Bild-only-Layout verwenden."
	case "links":
		return "Links werden von Mailprovidern und Gateways intensiv geprüft: Domain-Reputation, Blacklist-Status, Redirect-Ketten, Homoglyph-Domains und Phishing-Muster. Wichtigkeit: hoch – viele Domains in einer Mail, Mismatch zwischen angezeigtem und tatsächlichem Linkziel oder Links auf verdächtige TLDs erhöhen Spam-Scores erheblich. Tipp: Nur notwendige Links verwenden, eigene saubere Tracking-Domain einsetzen, HTTPS überall sicherstellen."
	case "shortener":
		return "URL-Shortener (bit.ly, t.co, tinyurl etc.) verbergen das tatsächliche Ziel und können nicht geprüft werden. Wichtigkeit: hoch – Spamfilter, Security-Gateways und Virenscanner lehnen Shortener-Links oft pauschal ab oder erhöhen den Spam-Score stark. Tipp: Eigene Tracking-Domains (z. B. go.example.org) mit eigenem Redirect-Service sind die professionelle Alternative zu öffentlichen Shortenern."
	case "tracking_links":
		return "Tracking-Links mit fremden Redirect-Domains (ESP-Domains wie click.mailchimp.com, r.sendgrid.net) oder aggressiven UTM-Parametern werden von Spamfiltern und Security-Gateways geprüft. Wichtigkeit: mittel – die Tracking-Domain sollte sauber (nicht gelistet) und HTTPS-fähig sein. Tipp: Eigene Tracking-Subdomains (z. B. click.example.org) signalisieren professionellen Betrieb und sind unabhängig von der ESP-Reputation."
	case "html":
		return "HTML-Inhalt wird von Mailclients restriktiv gerendert (kein JavaScript, eingeschränktes CSS) und von Spamfiltern auf Phishing-Muster, versteckte Texte, kaputte Struktur und verdächtige Tags geprüft. Wichtigkeit: mittel – komplexes HTML, inline Styles in übermäßigen Mengen und defekte Tags erhöhen Spam-Scores. Tipp: Einfaches, tabellen-basiertes Layout verwenden, CSS nur inline und sparsam, keine externen Ressourcen einbinden."
	case "hidden_html":
		return "Versteckte HTML-Elemente (display:none, font-size:0, color:white auf weißem Hintergrund, overflow:hidden mit height:0) sind eine bekannte Spam-Taktik. Wichtigkeit: hoch – SpamAssassin, Rspamd und Gmail erkennen diese Muster explizit und erhöhen den Spam-Score erheblich. Tipp: Preheader-Text darf versteckt sein, aber sparsam und ohne aggressives Hiding; alle anderen Inhalte sichtbar halten."
	case "html_validity":
		return "Valides HTML verbessert Rendering-Konsistenz über alle Mailclients und wird von Spamfiltern als Qualitätssignal gewertet. Wichtigkeit: mittel – kaputte Tags, unkorrekt geschachtelte Elemente und fehlende Pflicht-Attribute können zu inkonsistenter Darstellung und erhöhten Spam-Scores führen. Tipp: HTML mit dem W3C Validator oder einem Mail-spezifischen Tester prüfen; Litmus und Email on Acid zeigen Rendering in echten Clients."
	case "subject":
		return "Der Betreff ist eines der stärksten Nutzer- und Filterbewertungs-Signale. Wichtigkeit: hoch – ein leerer oder generischer Betreff, fehlender Bezug zum Absender oder betrügerische Muster (Re:, Fwd: ohne Kontext) werden von Spamfiltern und Nutzern negativ bewertet. Tipp: Betreff klar, konkret und zum Inhalt passend formulieren; keine Großschreibung, keine Ausrufezeichen-Häufungen, keine spamverdächtigen Wörter wie 'kostenlos', 'gratis', 'Gewinn'."
	case "subject_exclaim":
		return "Mehrfache Ausrufezeichen und andere Sonderzeichen-Häufungen im Betreff sind klassische Spam-Signale. Wichtigkeit: mittel – SpamAssassin prüft SUBJECT_ENDS_IN_EXCLAIM, SUBJ_MULT_EXCLAIM und ähnliche Muster explizit. Tipp: Professionelle Transaktionsmails nutzen maximal ein Ausrufezeichen, wenn überhaupt. Dringlichkeit besser durch klare Formulierung als durch Sonderzeichen ausdrücken."
	case "subject_caps":
		return "Durchgehende Großschreibung (ALL CAPS) im Betreff ist ein sehr starkes Spam-Signal. Wichtigkeit: hoch – wird von SpamAssassin (SUBJ_ALL_CAPS), Rspamd und manuellen Nutzern sofort als aufdringlich wahrgenommen. Tipp: Nur dort Großbuchstaben nutzen, wo grammatikalisch korrekt – Produktnamen, Abkürzungen. Niemals komplette Wörter oder Sätze in Großbuchstaben schreiben."
	case "message_id":
		return "Message-ID ist ein RFC-Pflichtfeld (RFC 5322) und identifiziert jede Nachricht eindeutig. Wichtigkeit: hoch – sie wird für E-Mail-Threading (In-Reply-To, References), Duplikaterkennung und Reputationsverfolgung genutzt. Fehlende oder generische Message-IDs (z. B. mit lokalem Hostnamen wie localhost) erhöhen Spam-Scores und stören Client-Threading. Tipp: Format wie <unique-uuid@mail.example.org> verwenden; niemals localhost oder interne IP-Adressen in der Message-ID."
	case "date":
		return "Der Date-Header muss ein gültiges RFC 2822-Datum enthalten, das plausibel zur tatsächlichen Versandzeit passt. Wichtigkeit: mittel – falsches Datum signalisiert falsch gestellte Serverzeit, manipulierte Nachrichten oder Software-Fehler. Manche Spamfilter lehnen Mails ab, die weit in der Zukunft oder Vergangenheit datiert sind. Tipp: NTP auf dem Mailserver aktivieren und sicherstellen, dass der MTA keinen manuell manipulierten Date-Header erzeugt."
	case "date_skew":
		return "Starke Zeitabweichung zwischen Date-Header und tatsächlichem Empfangszeitpunkt ist ein Spam-Signal. Wichtigkeit: mittel – erlaubt sind typischerweise ±24 h für Zeitzonendifferenzen und Netzwerkverzögerungen. Tipp: Serverzeit per NTP synchronisieren (ntpd oder systemd-timesyncd), Zeitzone korrekt konfigurieren und sicherstellen, dass der MTA keine manipulierten Date-Header erzeugt."
	case "tls_transport":
		return "TLS (STARTTLS oder SMTPS) schützt den SMTP-Transport vor Abhören und Manipulation. Wichtigkeit: hoch – viele Provider (Gmail, Outlook, Yahoo) bevorzugen oder erzwingen TLS-verschlüsselten Empfang. Opportunistisches STARTTLS ist heute Minimalstandard. Tipp: DANE (DNSSEC + TLSA-Records) ist der nächste Härtungsschritt für kritische Infrastruktur; MTA-STS bietet eine einfachere Alternative für erzwungenes TLS."
	case "received_chain":
		return "Received-Header dokumentieren den kompletten Transportweg der Nachricht. Jeder MTA trägt seinen Received-Header ein. Wichtigkeit: mittel – empfangende Systeme nutzen die Kette für IP-Reputation, Routing-Analyse und Forensik. Tipp: Fehlende Header können durch falsch konfigurierte Proxies entstehen; zu viele Hops können auf Fehlkonfiguration oder Mailloops hinweisen. Mindestens ein Received-Header sollte vorhanden sein."
	case "arc":
		return "ARC (Authenticated Received Chain) erhält Authentifizierungs-Ergebnisse (SPF, DKIM, DMARC) über Weiterleitungs-Hops hinweg. Wichtigkeit: mittel bis hoch für weitergeleitete Mails – wenn eine Mail weitergeleitet wird, können SPF/DKIM-Signaturen brechen. ARC-Header dokumentieren den Originalzustand. Tipp: Besonders relevant bei Mailing-Listen, Alumni-Weiterleitungen und Catchall-Setups; der weiterleitende Mailserver muss ARC unterstützen."
	case "list_unsub":
		return "List-Unsubscribe ist seit 2024 von Gmail und Yahoo für Bulk-Sender (>5.000 Mails/Tag) verpflichtend. Wichtigkeit: kritisch für Bulk-Sender – der Header ermöglicht Providern, einen 'Abmelden'-Button direkt in der UI anzubieten. List-Unsubscribe-Post (One-Click) muss RFC 8058 entsprechen: POST-Anfrage an eine HTTPS-URL, die sofortige Abmeldung ausführt. Tipp: Fehlender Header führt bei Gmail zu Spam-Einstufung für Bulk-Sender; auch für kleinere Versandmengen ist er Best Practice."
	case "preheader":
		return "Der Preheader-Text ist der erste sichtbare Text im Mail-Body und wird von Mailclients (Gmail, Outlook, Apple Mail, iOS Mail) als Vorschau-Snippet neben dem Betreff angezeigt. Wichtigkeit: mittel – ohne expliziten Preheader ziehen Clients oft unpassenden Text (Links, Abmeldehinweise, HTML-Code). Tipp: Einen kurzen, ansprechenden Satz (40–90 Zeichen) als versteckten Preheader-Text einfügen, der den Betreff ergänzt und zum Öffnen animiert."
	case "unicode":
		return "Zero-Width-Zeichen (U+200B, U+FEFF etc.), Bidi-Override-Zeichen und Unicode-Homoglyphen-Substitutionen sind bekannte Techniken, um Spamfilter zu umgehen und Nutzer zu täuschen. Wichtigkeit: hoch wenn vorhanden – SpamAssassin, Rspamd und Gmail erkennen gängige Unicode-Obfuskationsmuster explizit. Tipp: Normale Sonderzeichen für Sprache (Umlaute, Akzente) sind unproblematisch; nur Zero-Width- und Steuerzeichen vermeiden."
	default:
		return "Dieser Check bewertet ein technisches Signal, das Mailprovider für Zustellbarkeit, Missbrauchserkennung oder Nutzervertrauen heranziehen."
	}
}

func defaultRecommendation(c model.CheckResult, ctx checkContext) string {
	if c.Suggestion != "" {
		return c.Suggestion
	}
	switch c.ID {
	case "from_alignment":
		return fmt.Sprintf("Envelope-From/Bounce-Domain und sichtbare From-Domain angleichen. Aktuell: Header-From `%s`, Envelope-From-Domain `%s`. Empfehlenswert ist z. B. Bounce-Adresse `bounce@%s` oder eine Subdomain wie `bounce.%s`, die per SPF autorisiert ist.", emptyFallback(ctx.Headers.Get("From"), "none"), emptyFallback(ctx.EnvelopeDomain, "none"), emptyFallback(ctx.FromDomain, "example.org"), emptyFallback(ctx.FromDomain, "example.org"))
	case "return_path":
		return fmt.Sprintf("Im Versand-MTA oder ESP eine gültige Envelope-From/Bounce-Adresse setzen. Beispiel für die DNS-/MTA-Konfiguration: `bounce@%s` mit SPF-Record für die sendende IP %s.", emptyFallback(ctx.FromDomain, "example.org"), emptyFallback(ctx.Message.RemoteIP, "203.0.113.10"))
	case "reply_to":
		return "Wenn Antworten an eine andere Adresse gehen sollen, Reply-To bewusst setzen, z. B. `Reply-To: support@example.org`. Wenn nicht, Reply-To weglassen oder zur sichtbaren From-Domain passend halten."
	case "spf_alignment":
		return fmt.Sprintf("SPF für die Envelope-From-Domain `%s` so konfigurieren, dass die sendende IP %s erlaubt ist, und die Bounce-Domain als gleiche Domain oder Subdomain von `%s` verwenden.", emptyFallback(ctx.EnvelopeDomain, "none"), emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"), emptyFallback(ctx.FromDomain, "example.org"))
	case "dkim_alignment":
		return fmt.Sprintf("DKIM mit einer Domain signieren, die zur sichtbaren From-Domain passt. Beispiel: `d=%s` oder eine erlaubte Subdomain; DNS-Record unter `selector._domainkey.%s` setzen.", emptyFallback(ctx.FromDomain, "example.org"), emptyFallback(ctx.FromDomain, "example.org"))
	case "dmarc_alignment":
		return fmt.Sprintf("Mindestens SPF oder DKIM muss aligned bestehen. Praktisch: DKIM-Signatur mit `d=%s` aktivieren und SPF für `%s` korrigieren; DMARC-Record unter `_dmarc.%s` pflegen.", emptyFallback(ctx.FromDomain, "example.org"), emptyFallback(ctx.EnvelopeDomain, "example.org"), emptyFallback(ctx.FromDomain, "example.org"))
	case "received_chain":
		return "Der empfangende SMTP-Server sollte mindestens einen Received-Header schreiben. Wenn vorgeschaltete Relays Header entfernen, deren Konfiguration prüfen und RFC-konforme Received-Zeilen erhalten."
	case "message_id":
		return "Mailserver oder Versandsoftware so konfigurieren, dass jede Nachricht eine eindeutige Message-ID erzeugt, z. B. `<unique-id@" + emptyFallback(ctx.FromDomain, "example.org") + ">`."
	case "mime_ct", "mime_boundary", "multipart_alt":
		return "Das Template als RFC-konforme MIME-Mail erzeugen. Für HTML-Mails empfohlen: `multipart/alternative` mit `text/plain` und `text/html`, sauberer Boundary und `Content-Type: multipart/alternative; boundary=...`."
	case "plain_text":
		return "Im Versandtemplate einen text/plain-Part zusätzlich zum HTML-Part ausliefern."
	case "attachments":
		return "Anhänge nur verwenden, wenn noetig. Große Dateien extern verlinken, Dateinamen klar halten und riskante Dateitypen wie ausführbare Dateien vermeiden."
	case "image_text_ratio":
		return "Mehr echten Text in die Mail aufnehmen und Bild-only-Layouts vermeiden. Richtwert: zentrale Aussage als Text ausgeben, Bilder mit Alt-Text versehen und nicht mehr als wenige Hero-/Produktbilder verwenden."
	case "charset":
		return "UTF-8 als Charset verwenden und Content-Type korrekt setzen, z. B. `Content-Type: text/html; charset=UTF-8`."
	case "links":
		return "Nur notwendige Links verwenden und sichtbare Link-Domain, Ziel-Domain und Absenderdomain plausibel zusammenhalten. Kritische Links mit der eigenen Domain oder einer sauber eingerichteten Tracking-Domain ausliefern."
	case "shortener":
		return "URL-Shortener entfernen. Stattdessen direkte HTTPS-URLs oder eine eigene Tracking-Domain mit passendem CNAME/A-Record und TLS verwenden."
	case "tracking_links":
		return "Tracking-Parameter reduzieren. Wenn Tracking notwendig ist, eine eigene Subdomain wie `click." + emptyFallback(ctx.FromDomain, "example.org") + "` verwenden und diese sauber per DNS/TLS konfigurieren."
	case "html", "hidden_html", "html_validity":
		return "HTML-Template validieren, versteckte Elemente minimieren und kritische Inhalte nicht per `display:none`, `font-size:0` oder komplexem CSS verstecken. Lange CSS-Blöcke und kaputte Tags bereinigen."
	case "subject":
		return "Einen konkreten, normalen Betreff setzen, der Inhalt und Absender widerspiegelt. Beispiel: `Ihre Buchungsbestätigung für Veranstaltung XY` statt leerer oder generischer Betreffzeile."
	case "subject_exclaim", "subject_caps":
		return "Betreff normalisieren: wenige Satzzeichen, keine durchgehende Großschreibung, keine aggressiven Triggerwörter. Beispiel: `Aktualisierung zu Ihrer Bestellung`."
	case "date", "date_skew":
		return "Serverzeit per NTP synchronisieren und Date-Header vom MTA korrekt erzeugen lassen. Bei Postfix/Exim keine manuell manipulierten Date-Header aus der Anwendung erzwingen."
	case "tls_transport":
		return "STARTTLS am ausgehenden MTA aktivieren und Zertifikat/Hostname prüfen."
	case "list_unsub":
		return "Für Newsletter einen RFC-konformen Header setzen, z. B. `List-Unsubscribe: <mailto:unsubscribe@" + emptyFallback(ctx.FromDomain, "example.org") + ">, <https://" + emptyFallback(ctx.FromDomain, "example.org") + "/unsubscribe/...>` und optional `List-Unsubscribe-Post: List-Unsubscribe=One-Click`."
	case "preheader":
		return "Im HTML-Template einen kurzen Preheader direkt am Anfang des Body platzieren. Beispiel: ein 80–120 Zeichen langer Vorschautext, visuell dezent versteckt, aber nicht missbräuchlich obfuskiert."
	case "unicode":
		return "Zero-Width-Zeichen und unnötige Unicode-Obfuskation aus Betreff und Body entfernen. Normale Sonderzeichen für Sprache sind ok; versteckte Steuerzeichen sollten vermieden werden."
	default:
		return "Den genannten Wert im Mailserver, DNS oder Versandtemplate korrigieren und danach erneut testen."
	}
}

func defaultDocLinks(id string) []model.DocLink {
	switch id {
	case "from_alignment", "spf_alignment", "dkim_alignment", "dmarc_alignment":
		return []model.DocLink{
			{Title: "DMARC Alignment erklärt – dmarcian", URL: "https://dmarcian.com/alignment/"},
			{Title: "RFC 7489 – DMARC Alignment", URL: "https://www.rfc-editor.org/rfc/rfc7489#section-3.1"},
		}
	case "return_path":
		return []model.DocLink{
			{Title: "Return-Path vs. From – Postmark", URL: "https://postmarkapp.com/blog/what-is-the-return-path"},
			{Title: "RFC 5321 – SMTP Reverse-Path", URL: "https://www.rfc-editor.org/rfc/rfc5321#section-4.1.1.2"},
		}
	case "reply_to":
		return []model.DocLink{
			{Title: "RFC 5322 – Reply-To Header", URL: "https://www.rfc-editor.org/rfc/rfc5322#section-3.6.2"},
		}
	case "tls_transport":
		return []model.DocLink{
			{Title: "STARTTLS erklärt – Fastmail", URL: "https://www.fastmail.help/hc/en-us/articles/1500000278321"},
			{Title: "DANE für SMTP – IETF RFC 7672", URL: "https://www.rfc-editor.org/rfc/rfc7672"},
			{Title: "TLS-Check – internet.nl", URL: "https://internet.nl/mail/"},
		}
	case "received_chain":
		return []model.DocLink{
			{Title: "RFC 5321 – Received Header", URL: "https://www.rfc-editor.org/rfc/rfc5321#section-4.4"},
			{Title: "E-Mail-Header analysieren – MXToolbox", URL: "https://mxtoolbox.com/EmailHeaders.aspx"},
		}
	case "arc":
		return []model.DocLink{
			{Title: "ARC erklärt – arc-spec.org", URL: "https://arc-spec.org/"},
			{Title: "RFC 8617 – ARC", URL: "https://www.rfc-editor.org/rfc/rfc8617"},
		}
	case "mime_ct", "mime_boundary", "multipart_alt":
		return []model.DocLink{
			{Title: "RFC 2045 – MIME Part One", URL: "https://www.rfc-editor.org/rfc/rfc2045"},
			{Title: "MIME-Typen – MDN", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types"},
		}
	case "plain_text":
		return []model.DocLink{
			{Title: "Multipart/Alternative Best Practices", URL: "https://www.litmus.com/blog/best-practices-multipart-alternative-emails/"},
		}
	case "html", "hidden_html", "html_validity":
		return []model.DocLink{
			{Title: "HTML E-Mail Guide – Campaign Monitor", URL: "https://www.campaignmonitor.com/dev-resources/guides/html-email-best-practices/"},
			{Title: "E-Mail-Kompatibilitätstests – Can I Email", URL: "https://www.caniemail.com/"},
		}
	case "links", "shortener", "tracking_links":
		return []model.DocLink{
			{Title: "Link-Tracking Best Practices – Postmark", URL: "https://postmarkapp.com/blog/link-tracking-in-email"},
			{Title: "URL-Reputation prüfen – Google", URL: "https://transparencyreport.google.com/safe-browsing/search"},
			{Title: "URL-Reputation – VirusTotal", URL: "https://www.virustotal.com/gui/home/url"},
		}
	case "subject", "subject_exclaim", "subject_caps":
		return []model.DocLink{
			{Title: "Betreff Best Practices – Mailchimp", URL: "https://mailchimp.com/resources/email-subject-line-best-practices/"},
			{Title: "SpamAssassin Subject-Regeln", URL: "https://spamassassin.apache.org/tests_3_4_x.html"},
		}
	case "message_id":
		return []model.DocLink{
			{Title: "RFC 5322 – Message-ID", URL: "https://www.rfc-editor.org/rfc/rfc5322#section-3.6.4"},
		}
	case "date", "date_skew":
		return []model.DocLink{
			{Title: "RFC 5322 – Date Header", URL: "https://www.rfc-editor.org/rfc/rfc5322#section-3.6.1"},
			{Title: "NTP-Synchronisierung – pool.ntp.org", URL: "https://www.ntppool.org/en/"},
		}
	case "attachments", "image_text_ratio":
		return []model.DocLink{
			{Title: "Attachment Best Practices – Postmark", URL: "https://postmarkapp.com/developer/user-guide/send-email-with-attachments"},
			{Title: "Bild/Text-Verhältnis – Validity", URL: "https://www.validity.com/resource-center/image-to-text-ratio/"},
		}
	case "list_unsub":
		return []model.DocLink{
			{Title: "Gmail Bulk-Sender Anforderungen", URL: "https://support.google.com/mail/answer/81126"},
			{Title: "Yahoo Sender Best Practices", URL: "https://senders.yahooinc.com/best-practices/"},
			{Title: "RFC 8058 – One-Click Unsubscribe", URL: "https://www.rfc-editor.org/rfc/rfc8058"},
			{Title: "RFC 2369 – List-Unsubscribe Header", URL: "https://www.rfc-editor.org/rfc/rfc2369"},
		}
	case "preheader":
		return []model.DocLink{
			{Title: "Preheader Best Practices – Litmus", URL: "https://www.litmus.com/blog/the-ultimate-guide-to-preview-text-support/"},
		}
	case "unicode":
		return []model.DocLink{
			{Title: "Unicode-Zeichen prüfen – Unicode Inspector", URL: "https://apps.timwhitlock.info/unicode/inspect"},
			{Title: "IDN Homograph Attack erklärt", URL: "https://www.xudongz.com/blog/2017/idn-phishing/"},
		}
	default:
		return nil
	}
}

func spfRecommendation(ctx checkContext) string {
	domain := emptyFallback(ctx.EnvelopeDomain, "example.org")
	ip := emptyFallback(ctx.Message.RemoteIP, "203.0.113.10")
	if len(ctx.SPFRecords) == 0 {
		return fmt.Sprintf(`Keinen SPF-Record auf der Envelope-From-Domain gefunden. DNS-TXT-Record anlegen:

  Name:  %s   (oder @ im DNS-Manager)
  Typ:   TXT
  Wert:  "v=spf1 ip4:%s -all"

Wenn ein Versanddienst genutzt wird (Google Workspace, Mailchimp, SendGrid…):
  "v=spf1 include:_spf.google.com -all"
  "v=spf1 include:sendgrid.net -all"

Qualifier:
  -all  → Hard Fail  (empfohlen für Produktion)
  ~all  → Soft Fail  (toleranter; für den Einstieg geeignet)

Prüfen: dig TXT %s +short`, domain, ip, domain)
	}
	return fmt.Sprintf(`SPF-Record für %s vorhanden, aber die sendende IP %s ist nicht berechtigt.

Aktueller Record: %s

Häufige Ursachen:
  • IP nicht in ip4:/ip6:-Mechanismus gelistet
  • Kein passendes include: für den Versanddienst
  • SPF-Lookup-Limit überschritten (max. 10 DNS-Lookups pro Prüfung)

Fix: IP oder include: ergänzen, bei zu vielen Lookups ein SPF-Flattening-Tool nutzen.
Prüfen: dig TXT %s +short`, domain, ip, strings.Join(ctx.SPFRecords, " | "), domain)
}

func spfDocLinks() []model.DocLink {
	return []model.DocLink{
		{Title: "RFC 7208 – Sender Policy Framework", URL: "https://www.rfc-editor.org/rfc/rfc7208"},
		{Title: "SPF-Record prüfen – MXToolbox", URL: "https://mxtoolbox.com/spf.aspx"},
		{Title: "SPF-Wizard – dmarcian", URL: "https://dmarcian.com/spf-wizard/"},
		{Title: "SPF-Lookup-Limit erklären – Google", URL: "https://support.google.com/a/answer/10684623"},
	}
}

func dkimRecommendation(ctx checkContext) string {
	domain := emptyFallback(ctx.FromDomain, "example.org")
	return fmt.Sprintf(`DKIM-Schlüsselpaar erzeugen und DNS-TXT-Record anlegen.

1. Schlüssel erzeugen (2048 Bit empfohlen):
   openssl genrsa -out dkim_private.pem 2048
   openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem

2. DNS-Eintrag:
   Name:  mail._domainkey.%s
   Typ:   TXT
   Wert:  "v=DKIM1; k=rsa; p=<Base64-Inhalt von dkim_public.pem ohne Header>"

3. MTA konfigurieren – Beispiel Postfix + OpenDKIM (/etc/opendkim.conf):
   Domain         %s
   Selector       mail
   KeyFile        /etc/dkim/dkim_private.pem

4. Prüfen: dig TXT mail._domainkey.%s +short`, domain, domain, domain)
}

func dkimDocLinks() []model.DocLink {
	return []model.DocLink{
		{Title: "RFC 6376 – DomainKeys Identified Mail", URL: "https://www.rfc-editor.org/rfc/rfc6376"},
		{Title: "DKIM-Record prüfen – MXToolbox", URL: "https://mxtoolbox.com/dkim.aspx"},
		{Title: "DKIM-Schlüssel generieren – EasyDMARC", URL: "https://easydmarc.com/tools/dkim-record-generator"},
		{Title: "OpenDKIM Installationsanleitung", URL: "https://www.opendkim.org/"},
	}
}

func dmarcRecommendation(ctx checkContext) string {
	domain := emptyFallback(ctx.FromDomain, "example.org")
	if len(ctx.DMARCRecords) == 0 {
		return fmt.Sprintf(`Keinen DMARC-Record für %s gefunden. DNS-TXT-Record anlegen:

  Name:  _dmarc.%s
  Typ:   TXT

Einstieg (p=none – nur Monitoring, kein Einfluss auf Zustellung):
  "v=DMARC1; p=none; rua=mailto:dmarc@%s"

Empfohlen für Produktion (Quarantäne):
  "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@%s"

Streng (Ablehnung – nur wenn SPF + DKIM stabil laufen):
  "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@%s"

Voraussetzungen: SPF und DKIM müssen aligned bestehen.
Vorgehen: p=none → Berichte analysieren → p=quarantine → p=reject`, domain, domain, domain, domain, domain)
	}
	return fmt.Sprintf(`DMARC für %s ist gesetzt (Policy: %s), aber SPF oder DKIM besteht nicht aligned.

Checkliste:
  ✓ SPF muss für die Envelope-From-Domain bestehen und aligned zur From-Domain sein
  ✓ DKIM muss mit d=%s signieren
  ✓ Beide Mechanismen separat mit dig und Mail-Tests prüfen

Aktuelle Records: %s`, domain, emptyFallback(ctx.DMARCPolicy, "none"), domain, strings.Join(ctx.DMARCRecords, " | "))
}

func dmarcDocLinks() []model.DocLink {
	return []model.DocLink{
		{Title: "RFC 7489 – DMARC", URL: "https://www.rfc-editor.org/rfc/rfc7489"},
		{Title: "DMARC-Einstiegsguide – dmarc.org", URL: "https://dmarc.org/overview/"},
		{Title: "DMARC-Record prüfen – MXToolbox", URL: "https://mxtoolbox.com/dmarc.aspx"},
		{Title: "DMARC-Analyzer – dmarcian", URL: "https://dmarcian.com/dmarc-inspector/"},
	}
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, "\n")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func clampScore(s float64) float64 {
	if s < 0 {
		return 0
	}
	if s > 10 {
		return 10
	}
	return float64(int(s*10+0.5)) / 10
}

func assignLabel(r *model.AnalysisReport) {
	switch {
	case r.Score >= 9:
		r.ScoreLabel = "Excellent"
	case r.Score >= 7.5:
		r.ScoreLabel = "Good"
	case r.Score >= 5.5:
		r.ScoreLabel = "Needs Work"
	default:
		r.ScoreLabel = "High Risk"
	}
}

func parseAuthResult(s, key string) string {
	re := regexp.MustCompile(`(?:^|[;\s])` + regexp.QuoteMeta(key) + `=([a-zA-Z]+)`)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.ToLower(m[1])
}

func headerValues(h mail.Header, key string) []string {
	k := textproto.CanonicalMIMEHeaderKey(key)
	v, ok := h[k]
	if !ok {
		return nil
	}
	out := make([]string, len(v))
	copy(out, v)
	return out
}

func headerFromDomain(raw string) (domain, addr string) {
	if raw == "" {
		return "", ""
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil {
		return domainPart(raw), ""
	}
	return domainPart(parsed.Address), parsed.Address
}

func domainPart(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "<>"))
	if v == "" {
		return ""
	}
	at := strings.LastIndex(v, "@")
	if at < 0 || at+1 >= len(v) {
		return ""
	}
	return strings.ToLower(v[at+1:])
}

func ptrPlausibility(ctx context.Context, ip, helo string) model.CheckResult {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return warn("ptr", "PTR/rDNS", -0.4, "Remote-IP ist ungültig, PTR nicht prüfbar.", "SMTP-Quelle prüfen.")
	}
	ptr, err := net.DefaultResolver.LookupAddr(ctx, parsed.String())
	if err != nil || len(ptr) == 0 {
		return fail("ptr", "PTR/rDNS", -1.0, "Kein PTR/rDNS für die sendende IP gefunden.", "PTR-Record für ausgehende Mail-IP setzen.")
	}
	host := strings.TrimSuffix(strings.ToLower(ptr[0]), ".")
	fwd, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(fwd) == 0 {
		return warn("ptr", "PTR/rDNS", -0.5, "PTR vorhanden, aber Forward-Lookup liefert keine Adresse.", "Forward-confirmed reverse DNS einrichten.")
	}
	for _, candidate := range fwd {
		if candidate == parsed.String() {
			hostMatchesHELO := strings.EqualFold(host, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(helo)), "."))
			if helo != "" && !hostMatchesHELO {
				return warn("ptr", "PTR/rDNS", -0.4, "PTR und Forward DNS sind konsistent, passen aber nicht zum HELO/EHLO.", "PTR/rDNS und HELO/EHLO auf denselben Mailserver-Hostnamen setzen.")
			}
			return pass("ptr", "PTR/rDNS", 0.2, "PTR und Forward DNS sind konsistent.", "")
		}
	}
	return warn("ptr", "PTR/rDNS", -0.4, "PTR vorhanden, aber nicht forward-consistent zur sendenden IP.", "PTR/FQDN und A/AAAA sauber angleichen.")
}

type parsedBody struct {
	Text        string
	HTML        string
	AllText     string
	PartCount   int
	HasTextPart bool
	HasHTMLPart bool
	Attachments int
	Images      int
	Charset     string
}

func inspectBody(headers mail.Header, body []byte) ([]model.CheckResult, parsedBody) {
	out := make([]model.CheckResult, 0)
	pb := parsedBody{AllText: string(body)}

	ct := headers.Get("Content-Type")
	mediatype, params, err := mime.ParseMediaType(ct)
	if err != nil {
		out = append(out, warn("mime_ct", "MIME Content-Type", -0.4, "Content-Type wirkt fehlerhaft.", "Content-Type Header korrigieren."))
		return out, pb
	}
	pb.Charset = strings.ToLower(params["charset"])

	if strings.HasPrefix(mediatype, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			out = append(out, fail("mime_boundary", "Multipart-Aufbau", -1.0, "Multipart ohne Boundary.", "MIME-Boundary korrekt setzen."))
			return out, pb
		}
		mr := multipart.NewReader(strings.NewReader(string(body)), boundary)
		for {
			part, perr := mr.NextPart()
			if perr != nil {
				break
			}
			pb.PartCount++
			pbytes, _ := readLimited(part, 2*1024*1024)
			ptype, pparams, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if ptype == "text/plain" {
				pb.HasTextPart = true
				pb.Text += decodeBody(part.Header, pbytes)
			}
			if ptype == "text/html" {
				pb.HasHTMLPart = true
				h := decodeBody(part.Header, pbytes)
				pb.HTML += h
				pb.Images += strings.Count(strings.ToLower(h), "<img")
			}
			if filename := pparams["name"]; filename != "" || part.FileName() != "" {
				pb.Attachments++
			}
			_ = part.Close()
		}
	} else {
		if mediatype == "text/plain" {
			pb.HasTextPart = true
			pb.Text = decodeBody(textproto.MIMEHeader(headers), body)
		}
		if mediatype == "text/html" {
			pb.HasHTMLPart = true
			pb.HTML = decodeBody(textproto.MIMEHeader(headers), body)
			pb.Images = strings.Count(strings.ToLower(pb.HTML), "<img")
		}
		pb.PartCount = 1
	}

	if pb.Text == "" && pb.HTML != "" {
		out = append(out, warn("plain_text", "Plaintext-Part", -0.8, "Kein text/plain Part gefunden.", "Einen sauberen Plaintext-Part ergänzen."))
	} else if pb.Text != "" {
		out = append(out, pass("plain_text", "Plaintext-Part", 0.1, "Plaintext-Part vorhanden.", ""))
	}

	if pb.HasTextPart && pb.HasHTMLPart {
		out = append(out, pass("multipart_alt", "Multipart Struktur", 0.2, "Text und HTML sind vorhanden.", ""))
	} else if pb.HasHTMLPart || pb.HasTextPart {
		out = append(out, info("multipart_alt", "Multipart Struktur", 0.0, "Nur ein Body-Format vorhanden.", "Multipart/alternative verbessert Kompatibilität."))
	}

	if pb.Attachments > 0 {
		out = append(out, info("attachments", "Anhänge", 0.0, fmt.Sprintf("%d Anhang/Anhänge erkannt.", pb.Attachments), "Anhänge klein und vertrauenswürdig halten."))
	}

	if pb.Images >= 4 && len(stripHTML(pb.HTML)) < 240 {
		out = append(out, warn("image_text_ratio", "Bild/Text-Verhältnis", -0.7, "Viele Bilder bei wenig Text erkannt.", "Mehr echten Text ergänzen."))
	} else {
		out = append(out, info("image_text_ratio", "Bild/Text-Verhältnis", 0.0, "Bild/Text-Verhältnis ohne grobe Auffälligkeit.", ""))
	}

	all := strings.TrimSpace(pb.Text + "\n" + stripHTML(pb.HTML))
	if all != "" {
		pb.AllText = all
	}

	if pb.Charset != "" && pb.Charset != "utf-8" && pb.Charset != "us-ascii" {
		out = append(out, warn("charset", "Charset", -0.3, fmt.Sprintf("Ungewöhnlicher Charset erkannt: %s.", pb.Charset), "Nach Möglichkeit UTF-8 verwenden."))
	} else {
		out = append(out, pass("charset", "Charset", 0.1, "Charset wirkt unauffällig.", ""))
	}

	return out, pb
}

func decodeBody(headers textproto.MIMEHeader, body []byte) string {
	enc := strings.ToLower(strings.TrimSpace(headers.Get("Content-Transfer-Encoding")))
	switch enc {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(removeCRLF(string(body)))
		if err == nil {
			return string(decoded)
		}
	}
	return string(body)
}

func removeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", "")
}

func stripHTML(in string) string {
	if strings.TrimSpace(in) == "" {
		return ""
	}
	node, err := html.Parse(strings.NewReader(in))
	if err != nil {
		return in
	}
	var b strings.Builder
	var walker func(*html.Node)
	walker = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteString(" ")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walker(c)
		}
	}
	walker(node)
	return strings.TrimSpace(b.String())
}

func extractLinks(in string) []string {
	re := regexp.MustCompile(`https?://[^\s"'>)]+`)
	return re.FindAllString(in, -1)
}

func evaluateURLs(links []string) ([]model.CheckResult, []string) {
	if len(links) == 0 {
		return []model.CheckResult{info("links", "Link-Analyse", 0.0, "Keine Links erkannt.", "")}, nil
	}
	checks := []model.CheckResult{info("links", "Link-Analyse", 0.0, fmt.Sprintf("%d Links erkannt.", len(links)), "")}
	spamSignals := make([]string, 0)
	shorteners := map[string]bool{"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true, "is.gd": true, "ow.ly": true}
	tracking := 0
	shortCount := 0
	for _, raw := range links {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
		if shorteners[host] {
			shortCount++
		}
		for q := range u.Query() {
			lq := strings.ToLower(q)
			if strings.HasPrefix(lq, "utm_") || strings.Contains(lq, "track") || strings.Contains(lq, "mc_eid") {
				tracking++
				break
			}
		}
	}
	if shortCount > 0 {
		checks = append(checks, warn("shortener", "URL-Shortener", -0.6, fmt.Sprintf("%d verkürzte URL(s) erkannt.", shortCount), "Direkte, vertrauenswürdige Domains verwenden."))
		spamSignals = append(spamSignals, "URL-Shortener erkannt")
	}
	if tracking > 0 {
		checks = append(checks, info("tracking_links", "Tracking-Links", 0.0, fmt.Sprintf("%d Link(s) mit Tracking-Merkmalen.", tracking), "Tracking-Parameter minimieren erhöht Vertrauen."))
	}
	return checks, spamSignals
}

func htmlHeuristics(htmlBody string) []model.CheckResult {
	if strings.TrimSpace(htmlBody) == "" {
		return []model.CheckResult{info("html", "HTML-Analyse", 0.0, "Kein HTML-Body vorhanden.", "")}
	}
	checks := make([]model.CheckResult, 0, 3)
	lower := strings.ToLower(htmlBody)
	hiddenCount := strings.Count(lower, "display:none") + strings.Count(lower, "font-size:0") + strings.Count(lower, "visibility:hidden")
	if hiddenCount > 3 {
		checks = append(checks, warn("hidden_html", "Versteckte HTML-Elemente", -0.6, "Mehrere versteckte HTML-Elemente erkannt.", "Versteckte Inhalte reduzieren."))
	} else {
		checks = append(checks, pass("hidden_html", "Versteckte HTML-Elemente", 0.1, "Keine auffällige Menge versteckter Elemente.", ""))
	}
	if _, err := html.Parse(strings.NewReader(htmlBody)); err != nil {
		checks = append(checks, warn("html_validity", "HTML-Grundvalidierung", -0.4, "HTML wirkt strukturell fehlerhaft.", "HTML-Template validieren."))
	} else {
		checks = append(checks, pass("html_validity", "HTML-Grundvalidierung", 0.1, "HTML ist parsebar.", ""))
	}
	return checks
}

func subjectHeuristics(subject string) ([]model.CheckResult, []string) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return []model.CheckResult{warn("subject", "Betreff", -0.7, "Betreff fehlt.", "Klaren, präzisen Betreff setzen.")}, nil
	}
	checks := []model.CheckResult{pass("subject", "Betreff", 0.1, "Betreff vorhanden.", "")}
	signals := make([]string, 0)
	ex := strings.Count(subject, "!")
	if ex >= 3 {
		checks = append(checks, warn("subject_exclaim", "Betreff-Zeichenstil", -0.4, "Viele Ausrufezeichen im Betreff.", "Weniger reißerische Zeichensetzung verwenden."))
		signals = append(signals, "Betreff mit vielen Ausrufezeichen")
	}
	letters := 0
	upper := 0
	for _, r := range subject {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				upper++
			}
		}
	}
	if letters > 8 && float64(upper)/float64(letters) > 0.7 {
		checks = append(checks, warn("subject_caps", "Betreff-Großschreibung", -0.5, "Betreff ist überwiegend in Großbuchstaben.", "Gemischte Schreibweise nutzen."))
		signals = append(signals, "All-caps Betreff")
	}
	return checks, signals
}

func headerHeuristics(headers mail.Header) ([]model.CheckResult, []string) {
	checks := make([]model.CheckResult, 0)
	warnings := make([]string, 0)
	dateRaw := headers.Get("Date")
	if dateRaw == "" {
		checks = append(checks, warn("date", "Date-Header", -0.6, "Date-Header fehlt.", "Date-Header korrekt setzen."))
	} else if t, err := mail.ParseDate(dateRaw); err != nil {
		checks = append(checks, warn("date", "Date-Header", -0.5, "Date-Header ist nicht parsebar.", "RFC-kompatibles Datumsformat nutzen."))
	} else {
		delta := time.Since(t)
		if delta < -2*time.Hour || delta > 14*24*time.Hour {
			checks = append(checks, warn("date_skew", "Datumsplausibilität", -0.4, "Date-Header wirkt zeitlich inkonsistent.", "Serverzeit/NTP prüfen."))
			warnings = append(warnings, "Date-Header zeitlich auffällig")
		} else {
			checks = append(checks, pass("date", "Date-Header", 0.1, "Date-Header plausibel.", ""))
		}
	}
	if headers.Get("Message-Id") == "" && headers.Get("Message-ID") == "" {
		checks = append(checks, fail("message_id", "Message-ID", -0.8, "Message-ID fehlt.", "Jede Mail mit stabiler Message-ID versenden."))
	} else {
		checks = append(checks, pass("message_id", "Message-ID", 0.1, "Message-ID vorhanden.", ""))
	}
	return checks, warnings
}

func unicodeObfuscationCheck(text string) (model.CheckResult, string) {
	if text == "" {
		return info("unicode", "Unicode/Obfuscation", 0.0, "Kein Text für Unicode-Heuristik.", ""), ""
	}
	zwCount := strings.Count(text, "\u200b") + strings.Count(text, "\u200c") + strings.Count(text, "\u2060")
	nonASCII := 0
	for _, r := range text {
		if r > unicode.MaxASCII {
			nonASCII++
		}
	}
	if zwCount > 2 {
		return warn("unicode", "Unicode/Obfuscation", -0.6, "Mehrere Zero-Width Zeichen erkannt.", "Versteckte Unicode-Zeichen entfernen."), "Zero-width obfuscation erkannt"
	}
	if nonASCII > 0 && float64(nonASCII)/float64(len([]rune(text))) > 0.6 {
		return info("unicode", "Unicode/Obfuscation", 0.0, "Hoher Unicode-Anteil erkannt (evtl. sprachbedingt).", ""), ""
	}
	return pass("unicode", "Unicode/Obfuscation", 0.1, "Keine offensichtliche Unicode-Obfuscation erkannt.", ""), ""
}

func newsletterHeuristics(headers mail.Header, body parsedBody) []model.CheckResult {
	checks := make([]model.CheckResult, 0)
	all := strings.ToLower(body.AllText)
	newsletterHint := strings.Contains(all, "unsubscribe") || strings.Contains(strings.ToLower(headers.Get("Precedence")), "bulk") || strings.TrimSpace(headers.Get("List-Id")) != ""
	if newsletterHint {
		if headers.Get("List-Unsubscribe") == "" {
			checks = append(checks, warn("list_unsub", "List-Unsubscribe", -0.7, "Newsletter-Hinweise vorhanden, aber List-Unsubscribe fehlt.", "List-Unsubscribe Header ergänzen."))
		} else {
			checks = append(checks, pass("list_unsub", "List-Unsubscribe", 0.2, "List-Unsubscribe Header vorhanden.", ""))
		}
	}

	htmlLower := strings.ToLower(body.HTML)
	if strings.Contains(htmlLower, "preheader") || strings.Contains(htmlLower, "display:none") {
		checks = append(checks, info("preheader", "Preheader-Heuristik", 0.0, "Möglicher Preheader erkannt.", ""))
	} else if body.HasHTMLPart {
		checks = append(checks, warn("preheader", "Preheader-Heuristik", -0.2, "Kein klarer Preheader erkennbar.", "Optional kurzen Preheader ergänzen."))
	}
	return checks
}

func rblHeuristics(ctx context.Context, remoteIP string, providers []string) []model.CheckResult {
	if len(providers) == 0 {
		return []model.CheckResult{info("rbl", "DNSBL/RBL", 0.0, "RBL-Pruefung aktiv, aber keine Provider konfiguriert.", "")}
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil || ip.To4() == nil {
		return []model.CheckResult{info("rbl", "DNSBL/RBL", 0.0, "RBL nur für IPv4 geprüft.", "")}
	}
	octets := strings.Split(ip.String(), ".")
	queryIP := fmt.Sprintf("%s.%s.%s.%s", octets[3], octets[2], octets[1], octets[0])
	listed := 0
	listedProviders := make([]string, 0)
	cleanProviders := make([]string, 0, len(providers))
	queryNames := make([]string, 0, len(providers))
	listingResponses := make([]string, 0)
	txtEvidence := make([]string, 0)
	lookupErrors := make([]string, 0)
	delistingSteps := make([]string, 0)
	delistingURLs := make([]string, 0)
	for _, p := range providers {
		provider := strings.TrimSpace(p)
		if provider == "" {
			continue
		}
		meta := rblProviderMeta(provider, remoteIP)
		cleanProviders = append(cleanProviders, fmt.Sprintf("%s (%s)|%s", provider, meta.Name, meta.Description))
		name := queryIP + "." + provider
		queryNames = append(queryNames, name)
		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := net.DefaultResolver.LookupHost(lookupCtx, name)
		cancel()
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				continue
			}
			lookupErrors = append(lookupErrors, fmt.Sprintf("%s: %v", provider, err))
			continue
		}
		if len(ips) > 0 {
			// Query-Verweigerungen (z. B. Spamhaus 127.255.255.254 = Open Resolver)
			// sind kein echtes Listing — als Fehler behandeln, nicht als Treffer.
			if rblQueryRefusal(ips) {
				lookupErrors = append(lookupErrors, fmt.Sprintf("%s: Query verweigert (%s) — Open Resolver oder Rate Limit; kein echtes Listing", provider, strings.Join(ips, ", ")))
				continue
			}
			listed++
			listedProviders = append(listedProviders, fmt.Sprintf("%s (%s)", provider, meta.Name))
			meaning := rblResponseMeaning(provider, ips)
			listingResponses = append(listingResponses, fmt.Sprintf("%s → %s", provider, meaning))
			txtCtx, txtCancel := context.WithTimeout(ctx, 2*time.Second)
			txts, txtErr := net.DefaultResolver.LookupTXT(txtCtx, name)
			txtCancel()
			if txtErr == nil && len(txts) > 0 {
				txtEvidence = append(txtEvidence, provider+" TXT: "+strings.Join(txts, " | "))
			}
			delistingSteps = append(delistingSteps, fmt.Sprintf("%s: %s", provider, meta.Delisting))
			delistingURLs = append(delistingURLs, fmt.Sprintf("%s: %s", provider, meta.DelistURL))
		}
	}
	details := map[string]string{
		"remote_ip":             remoteIP,
		"rbl_query_prefix":      queryIP,
		"checked_providers":     strings.Join(cleanProviders, "\n"),
		"query_names":           strings.Join(queryNames, "\n"),
		"listed_providers":      emptyFallback(strings.Join(listedProviders, "\n"), "none"),
		"listing_responses":     emptyFallback(strings.Join(listingResponses, "\n"), "none"),
		"txt_evidence":          emptyFallback(strings.Join(txtEvidence, "\n"), "none"),
		"lookup_errors":         emptyFallback(strings.Join(lookupErrors, "\n"), "none"),
		"pre_delisting_checks":  rblPreDelistingChecklist(remoteIP),
		"provider_delisting":    emptyFallback(strings.Join(delistingSteps, "\n\n"), "none"),
		"provider_delist_urls":  emptyFallback(strings.Join(delistingURLs, "\n"), "none"),
		"deliverability_impact": rblImpactText(listed),
	}
	if listed > 0 {
		// Being on a blacklist is one of the strongest real-world deliverability
		// killers; scale with the number of lists hit.
		scoreDelta := -1.3
		status := "warn"
		if listed >= 2 {
			scoreDelta = -2.2
			status = "fail"
		}
		if listed >= 3 {
			scoreDelta = -3.0
		}
		summary := fmt.Sprintf("Die Absender-IP %s ist auf %d der geprüften RBL(s) gelistet: %s.", remoteIP, listed, strings.Join(listedProviders, ", "))
		rec := rblListedRecommendation(remoteIP, listedProviders)
		if status == "fail" {
			return []model.CheckResult{withDetails(fail("rbl", "DNSBL/RBL", scoreDelta, summary, rec), details)}
		}
		return []model.CheckResult{withDetails(warn("rbl", "DNSBL/RBL", scoreDelta, summary, rec), details)}
	}
	return []model.CheckResult{withDetails(pass("rbl", "DNSBL/RBL", 0.1, fmt.Sprintf("Die Absender-IP %s ist in den konfigurierten RBLs nicht gelistet.", remoteIP), ""), details)}
}

type rblProvider struct {
	Name        string
	Description string // Was die Liste listet und wie sie genutzt wird
	DelistURL   string
	Delisting   string
}

// rblQueryRefusal gibt true zurück wenn die Antwort eine Spamhaus-spezifische
// Fehlermeldung ist (kein echtes Listing, sondern Query-Verweigerung).
func rblQueryRefusal(ips []string) bool {
	for _, ip := range ips {
		if ip == "127.255.255.254" || ip == "127.255.255.255" {
			return true
		}
	}
	return false
}

// rblResponseMeaning übersetzt bekannte DNS-Antwort-IPs in verständlichen Text.
func rblResponseMeaning(provider string, ips []string) string {
	p := strings.ToLower(provider)
	meanings := make([]string, 0, len(ips))
	for _, ip := range ips {
		switch {
		case ip == "127.255.255.254":
			meanings = append(meanings, ip+" (Query verweigert — Open Resolver; kein echtes Listing)")
		case ip == "127.255.255.255":
			meanings = append(meanings, ip+" (Query-Timeout; kein echtes Listing)")
		case strings.Contains(p, "spamhaus") || strings.HasSuffix(p, ".spamhaus.org"):
			switch ip {
			case "127.0.0.2":
				meanings = append(meanings, ip+" → SBL: bekannte Spam-Quelle")
			case "127.0.0.3":
				meanings = append(meanings, ip+" → SBL CSS: Snowshoe-Spam")
			case "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7":
				meanings = append(meanings, ip+" → XBL: Exploit/Botnet/kompromittierter Host")
			case "127.0.0.9":
				meanings = append(meanings, ip+" → DROP/EDROP: vollständig blockierter Adressbereich")
			case "127.0.0.10":
				meanings = append(meanings, ip+" → PBL: dynamische/Consumer-IP (ISP-Policy)")
			case "127.0.0.11":
				meanings = append(meanings, ip+" → PBL: dynamische IP (Nutzer-gemeldet)")
			default:
				meanings = append(meanings, ip+" → Spamhaus-Listing (unbekannter Subtyp)")
			}
		case strings.Contains(p, "barracuda"):
			meanings = append(meanings, ip+" → Barracuda BRBL: Spam-Reputationstreffer")
		case strings.Contains(p, "spamcop"):
			meanings = append(meanings, ip+" → SpamCop: von Nutzern gemeldete Spam-IP")
		case strings.Contains(p, "dronebl"):
			switch ip {
			case "127.0.0.3":
				meanings = append(meanings, ip+" → IRC-Drone")
			case "127.0.0.5":
				meanings = append(meanings, ip+" → Bottrap")
			case "127.0.0.6":
				meanings = append(meanings, ip+" → IRC-Spam-Bot")
			case "127.0.0.7":
				meanings = append(meanings, ip+" → HTTP-Proxy (Open Proxy)")
			case "127.0.0.8":
				meanings = append(meanings, ip+" → SOCKS-Proxy (Open Proxy)")
			case "127.0.0.9":
				meanings = append(meanings, ip+" → Proxy-Chain")
			case "127.0.0.13":
				meanings = append(meanings, ip+" → Brute-Force-Angreifer")
			case "127.0.0.14":
				meanings = append(meanings, ip+" → Open Resolver (missbraucht für DDoS)")
			case "127.0.0.17":
				meanings = append(meanings, ip+" → Automatischer E-Mail-Angriff")
			case "127.0.0.255":
				meanings = append(meanings, ip+" → Manuell gelistet")
			default:
				meanings = append(meanings, ip+" → DroneBL-Listing")
			}
		default:
			meanings = append(meanings, ip)
		}
	}
	return strings.Join(meanings, ", ")
}

func rblProviderMeta(provider, remoteIP string) rblProvider {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case "zen.spamhaus.org", "sbl.spamhaus.org", "xbl.spamhaus.org", "pbl.spamhaus.org", "sbl-xbl.spamhaus.org", "dbl.spamhaus.org":
		return rblProvider{
			Name:        "Spamhaus",
			Description: "Spamhaus betreibt die weltweit meistgenutzten DNSBLs. ZEN kombiniert SBL (bekannte Spam-Quellen), XBL (Exploits/Botnets) und PBL (Policy-Liste für dynamische IPs). Ein Spamhaus-Listing führt bei Gmail, Outlook, Yahoo und den meisten Enterprise-Gateways direkt zur Ablehnung. Antwort-Codes: 127.0.0.2=SBL, 127.0.0.3=SBL-CSS, 127.0.0.4=XBL, 127.0.0.10/11=PBL. Code 127.255.255.254 bedeutet Query-Verweigerung (kein echtes Listing).",
			DelistURL:   "https://check.spamhaus.org/",
			Delisting:   "Spamhaus Reputation Checker öffnen, IP/Domain prüfen und die angezeigte Liste beachten. Bei SBL muss in der Regel der ISP/Provider das Abuse-Problem bestätigt beheben und die Entfernung anstoßen; bei XBL/CSS erst Malware, Proxy oder kompromittierte Accounts entfernen; bei PBL nur delisten, wenn die IP wirklich ein legitimer Mailserver ist.",
		}
	case "bl.spamcop.net":
		return rblProvider{
			Name:        "SpamCop Blocking List",
			Description: "SpamCop listet IPs, von denen Nutzer aktiv Spam gemeldet haben. Das Listing ist zeitbasiert und läuft automatisch aus, wenn keine neuen Meldungen eingehen. Wird von vielen ISPs und selbst betriebenen Mailservern genutzt. Eher ein Warnsignal als ein hartes Blockierungswerkzeug.",
			DelistURL:   "https://www.spamcop.net/bl.shtml",
			Delisting:   "SpamCop ist zeitbasiert. Es gibt normalerweise kein manuelles Express-Delisting; nach Ende neuer Spam-Reports läuft das Listing automatisch aus. Prüfe SpamCop-Reports, kompromittierte Accounts, offene Relays, infizierte Hosts und fehlgeleitete Bounces.",
		}
	case "b.barracudacentral.org", "bb.barracudacentral.org":
		return rblProvider{
			Name:        "Barracuda Reputation Block List",
			Description: "Barracuda BRBL listet IPs mit schlechter Versandreputation basierend auf Spam-Beschwerden und Spam-Trap-Treffern. Wird von Barracuda-Gateways in Unternehmen weit verbreitet eingesetzt. Ein Listing kann direkte Ablehnungen bei Unternehmensempfängern verursachen. Delisting ist kostenlos über das Webformular möglich.",
			DelistURL:   "https://www.barracudacentral.org/rbl/removal-request",
			Delisting:   "Barracuda Removal Request mit IP, Kontaktadresse, Telefonnummer und nachvollziehbarer Ursache einreichen. Vorher Spamquelle stoppen, Queue prüfen und erklären, was konkret behoben wurde; Mehrfachanfragen ohne neue Informationen vermeiden.",
		}
	case "psbl.surriel.com":
		return rblProvider{
			Name:        "Passive Spam Block List",
			Description: "PSBL ist eine passive Liste — sie listet IPs, die Spam-Traps getroffen haben, ohne aktive Nutzer-Reports. Wird von kleineren Mailservern und einigen ISPs genutzt. Delisting ist self-service. Ein Listing deutet oft auf alte oder gekaufte Empfängerlisten hin.",
			DelistURL:   "https://www.psbl.org/remove",
			Delisting:   "PSBL-Remove-Seite mit der IP nutzen. PSBL listet typischerweise Spamtrap-Treffer; vor Delisting Listenherkunft, Empfängerlisten, kompromittierte Accounts und ungewollte Direktzustellung prüfen. Removal ist self-service, DNS-Propagation kann dauern.",
		}
	case "dnsbl.dronebl.org":
		return rblProvider{
			Name:        "DroneBL",
			Description: "DroneBL listet IPs die als offene Proxies, Botnets, IRC-Dronen oder Angreifer bekannt sind. Wird vor allem in IRC-Netzwerken und von selbst betriebenen Mailservern genutzt. Ein Listing deutet auf kompromittierte Infrastruktur oder Malware-Aktivität hin. Antwort-Codes zeigen den genauen Typ (Proxy, Bot, Brute-Force etc.).",
			DelistURL:   "https://www.dronebl.org/lookup",
			Delisting:   "DroneBL-Lookup ausführen und den dort angezeigten Instruktionen folgen. Häufige Ursachen sind offene Proxies, Botnet-/Malware-Verkehr oder kompromittierte Hosts; diese Ursache muss vor dem Delisting beseitigt sein.",
		}
	case "bl.blocklist.de":
		return rblProvider{
			Name:        "blocklist.de",
			Description: "blocklist.de ist eine deutschsprachige DNSBL die IPs listet, die durch Brute-Force-Angriffe (SSH, FTP, SMTP, HTTP) oder Spam auffällig geworden sind. Daten kommen aus Fail2Ban-Reports von teilnehmenden Servern. Listings laufen automatisch aus, können aber vorzeitig über das Delist-Formular entfernt werden.",
			DelistURL:   "https://www.blocklist.de/en/delist.html?ip=" + url.QueryEscape(remoteIP),
			Delisting:   "blocklist.de delistet Angreifer-IP-Adressen nach Behebung vorzeitig über die Delist-Seite; sonst läuft das Listing typischerweise automatisch aus. Vorher Logins, SSH/FTP/Web-/Mail-Bruteforce, kompromittierte Dienste und Fail2Ban-Meldungen prüfen.",
		}
	case "cbl.abuseat.org":
		return rblProvider{
			Name:        "Composite Blocking List",
			Description: "CBL listet IPs die durch Spam, offene Proxies oder Botnet-Aktivität auffällig geworden sind. Wird von Spamhaus XBL als Datenquelle genutzt — ein CBL-Listing führt daher oft auch zu einem XBL-Listing. Automatisches Delisting nach Behebung der Ursache.",
			DelistURL:   "https://www.abuseat.org/lookup.cgi?ip=" + url.QueryEscape(remoteIP),
			Delisting:   "CBL-Lookup mit der IP öffnen, Ursache lesen und erst nach Beseitigung von Malware, Proxy, Botnet-Verkehr oder kompromittierten SMTP-Zugangsdaten delisten.",
		}
	default:
		return rblProvider{
			Name:        "DNSBL",
			Description: "Diese DNSBL-Liste listet IPs basierend auf eigenem Regelwerk. Prüfe die Dokumentation des Providers für Details zu Listungskriterien und Delisting-Prozess.",
			DelistURL:   "https://" + provider,
			Delisting:   "Provider-Dokumentation der DNSBL öffnen, Listinggrund prüfen, Ursache technisch beheben und erst danach eine Entfernung beantragen. Falls keine Delisting-Seite existiert, Abuse-Kontakt des Providers oder automatische Expiry-Regeln beachten.",
		}
	}
}

func rblPreDelistingChecklist(remoteIP string) string {
	return strings.Join([]string{
		"1. Versand für die IP " + emptyFallback(remoteIP, "<sender-ip>") + " kurz stoppen oder stark drosseln.",
		"2. Mailqueue, Auth-Logs, Bounce-Logs und Webform-/Newsletter-Logs auf Spamwellen prüfen.",
		"3. Kompromittierte Accounts, offene Relays, offene Proxies, Malware und fehlgeleitete Bounces beheben.",
		"4. SPF, DKIM, DMARC, PTR/rDNS und HELO konsistent machen.",
		"5. Erst danach Delisting beim jeweiligen Provider beantragen und die konkrete Behebung dokumentieren.",
	}, "\n")
}

func rblImpactText(listed int) string {
	if listed == 0 {
		return "Keine Listing-Treffer in den konfigurierten RBLs. Das garantiert keine gute Inbox-Platzierung, reduziert aber ein wichtiges Infrastruktur-Risiko."
	}
	if listed == 1 {
		return "Ein einzelnes Listing ist ein Warnsignal. Je nach Liste kann es bei kleineren Providern direkt zu Ablehnungen führen und bei großen Providern die IP-Reputation indirekt belasten."
	}
	return "Mehrere Listings sind ein starkes Reputationsproblem. Vor weiterem Versand sollte die Ursache behoben werden, sonst drohen Ablehnungen, Spamfolder-Platzierung und schnelle Wiederlistings."
}

func rblListedRecommendation(remoteIP string, listedProviders []string) string {
	return fmt.Sprintf("Die IP %s ist gelistet. Stoppe zunächst die Ursache, bevor du Delisting beantragst; sonst wird die IP meist erneut gelistet. Prüfe insbesondere kompromittierte SMTP-Accounts, offene Relay-/Proxy-Konfiguration, infizierte Webanwendungen, Spamtrap-Treffer durch alte Empfängerlisten und fehlgeleitete Bounces. Danach pro gelisteter RBL den Delisting-Link aus den technischen Details nutzen und in der Begründung konkret nennen, was behoben wurde. Betroffene Listen: %s.", emptyFallback(remoteIP, "<sender-ip>"), strings.Join(listedProviders, ", "))
}

func rblGenericRecommendation(remoteIP string) string {
	return fmt.Sprintf("Wenn ein RBL-Listing auftritt: Ursache für IP %s zuerst abstellen, Versand temporär stoppen, Logs und Queue prüfen, dann über die jeweilige Provider-Seite delisten. Ohne behobene Ursache führt Delisting fast immer zu erneutem Listing.", emptyFallback(remoteIP, "<sender-ip>"))
}

func spamAssassinHeuristic(ctx context.Context, hostport, raw string) model.CheckResult {
	details := map[string]string{"spamd_hostport": hostport}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		details["error"] = err.Error()
		return withDetails(info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin nicht erreichbar.", "Optionalen spamd-Dienst prüfen oder Option deaktivieren."), details)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := fmt.Sprintf("SYMBOLS SPAMC/1.5\r\nContent-length: %d\r\n\r\n%s", len(raw), raw)
	if _, err := conn.Write([]byte(req)); err != nil {
		details["error"] = err.Error()
		return withDetails(info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Anfrage fehlgeschlagen.", "spamd-Verbindung prüfen."), details)
	}

	resp, err := readLimited(conn, 64*1024)
	if err != nil {
		details["error"] = err.Error()
		return withDetails(info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Antwort nicht lesbar.", "spamd Antwortformat prüfen."), details)
	}
	lower := strings.ToLower(string(resp))
	spamLine := ""
	for _, line := range strings.Split(string(resp), "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "spam:") {
			spamLine = strings.TrimSpace(line)
			break
		}
	}
	details["spam_line"] = emptyFallback(spamLine, "none")
	if strings.Contains(lower, "spam: true") {
		return withDetails(fail("spamassassin", "SpamAssassin", -1.6, emptyFallback(spamLine, "SpamAssassin stuft Nachricht als Spam ein."), "SpamAssassin-Regeln/Symbole prüfen und Mailinhalt überarbeiten."), details)
	}
	if spamLine != "" {
		return withDetails(pass("spamassassin", "SpamAssassin", 0.0, spamLine, ""), details)
	}
	return withDetails(info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Antwort ohne klassisches Spam-Headerformat erhalten.", ""), details)
}

type rspamdCheckResult struct {
	Score         float64                    `json:"score"`
	RequiredScore float64                    `json:"required_score"`
	Action        string                     `json:"action"`
	Symbols       map[string]json.RawMessage `json:"symbols"`
}

func rspamdHeuristic(ctx context.Context, endpointURL, password, raw string) model.CheckResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewBufferString(raw))
	if err != nil {
		return info("rspamd", "Rspamd", 0.0, "Rspamd request build failed.", "Check RSPAMD_URL configuration.")
	}
	req.Header.Set("Content-Type", "message/rfc822")
	if strings.TrimSpace(password) != "" {
		req.Header.Set("Password", password)
	}

	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return info("rspamd", "Rspamd", 0.0, "Rspamd not reachable.", "Check Rspamd service availability or disable ENABLE_RSPAMD.")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return info("rspamd", "Rspamd", 0.0, "Rspamd denied access (auth).", "Set correct RSPAMD_PASSWORD or adjust controller auth.")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return info("rspamd", "Rspamd", 0.0, fmt.Sprintf("Rspamd HTTP status %d.", resp.StatusCode), "Check Rspamd controller endpoint.")
	}

	var parsed rspamdCheckResult
	if err := json.Unmarshal(body, &parsed); err != nil {
		return info("rspamd", "Rspamd", 0.0, "Rspamd response parse failed.", "Verify Rspamd endpoint returns JSON (checkv2).")
	}

	action := strings.ToLower(strings.TrimSpace(parsed.Action))
	topSymbols := topRspamdSymbols(parsed.Symbols, 4) // kept for suggestion generation
	allSyms := allRspamdSymbols(parsed.Symbols)

	actionDisplay := emptyFallback(action, "unknown")
	summary := fmt.Sprintf("Score %.2f / %.2f · Aktion: %s · %d Symbole analysiert",
		parsed.Score, parsed.RequiredScore, actionDisplay, len(parsed.Symbols))
	suggestion := rspamdSuggestionFor(topSymbols, action)

	details := map[string]string{
		"action":         actionDisplay,
		"score":          fmt.Sprintf("%.2f", parsed.Score),
		"required_score": fmt.Sprintf("%.2f", parsed.RequiredScore),
		"symbol_count":   strconv.Itoa(len(parsed.Symbols)),
	}
	// Add top symbols (by absolute weight) for structured display in the UI.
	// Value format: "<score>|<description>|<explanation>" — both the Go template
	// and the client-side decrypted renderer split on "|" and use these parts.
	maxSyms := 15
	if len(allSyms) < maxSyms {
		maxSyms = len(allSyms)
	}
	for _, s := range allSyms[:maxSyms] {
		details["sym:"+s.Name] = fmt.Sprintf("%+.2f|%s|%s", s.Score, s.Description, rspamdSymbolExplain(s.Name))
	}

	switch action {
	case "reject":
		return withDetails(fail("rspamd", "Rspamd", -2.2, summary, suggestion), details)
	case "soft reject":
		return withDetails(fail("rspamd", "Rspamd", -1.5, summary, suggestion), details)
	case "add header", "rewrite subject", "greylist":
		return withDetails(warn("rspamd", "Rspamd", -0.8, summary, suggestion), details)
	case "no action":
		return withDetails(pass("rspamd", "Rspamd", 0.0, summary, ""), details)
	default:
		if parsed.RequiredScore > 0 && parsed.Score >= parsed.RequiredScore {
			return withDetails(warn("rspamd", "Rspamd", -0.8, summary, suggestion), details)
		}
		return withDetails(info("rspamd", "Rspamd", 0.0, summary, ""), details)
	}
}

type rspamdSymbol struct {
	Name        string
	Score       float64
	Description string
}

func topRspamdSymbols(raw map[string]json.RawMessage, n int) []rspamdSymbol {
	symbols := make([]rspamdSymbol, 0, len(raw))
	for name, payload := range raw {
		score, desc := parseRspamdSymbolPayload(payload)
		if score <= 0 {
			continue
		}
		symbols = append(symbols, rspamdSymbol{Name: name, Score: score, Description: desc})
	}
	sort.SliceStable(symbols, func(i, j int) bool {
		if symbols[i].Score == symbols[j].Score {
			return symbols[i].Name < symbols[j].Name
		}
		return symbols[i].Score > symbols[j].Score
	})
	if n > 0 && len(symbols) > n {
		return symbols[:n]
	}
	return symbols
}

// allRspamdSymbols returns every symbol sorted by absolute score descending,
// so the most impactful entries (positive spam signals and negative ham signals)
// appear first regardless of direction.
func allRspamdSymbols(raw map[string]json.RawMessage) []rspamdSymbol {
	symbols := make([]rspamdSymbol, 0, len(raw))
	for name, payload := range raw {
		score, desc := parseRspamdSymbolPayload(payload)
		symbols = append(symbols, rspamdSymbol{Name: name, Score: score, Description: desc})
	}
	sort.SliceStable(symbols, func(i, j int) bool {
		ai, aj := symbols[i].Score, symbols[j].Score
		if ai < 0 {
			ai = -ai
		}
		if aj < 0 {
			aj = -aj
		}
		if ai != aj {
			return ai > aj
		}
		return symbols[i].Name < symbols[j].Name
	})
	return symbols
}

func parseRspamdSymbolPayload(payload json.RawMessage) (float64, string) {
	var typed struct {
		Score       float64 `json:"score"`
		Description string  `json:"description"`
	}
	if err := json.Unmarshal(payload, &typed); err == nil {
		return typed.Score, strings.TrimSpace(typed.Description)
	}

	var generic map[string]any
	if err := json.Unmarshal(payload, &generic); err != nil {
		return 0, ""
	}
	score := anyNumberToFloat(generic["score"])
	desc := ""
	if d, ok := generic["description"]; ok {
		desc = strings.TrimSpace(fmt.Sprintf("%v", d))
	}
	return score, desc
}

func anyNumberToFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func rspamdSuggestionFor(symbols []rspamdSymbol, action string) string {
	parts := make([]string, 0, 4)
	if action == "reject" || action == "soft reject" {
		parts = append(parts, "Message was rejected by Rspamd; fix the highest positive symbols first.")
	}
	for _, s := range symbols {
		name := strings.ToUpper(s.Name)
		switch {
		case strings.Contains(name, "SPF"):
			parts = append(parts, "Fix SPF for the envelope sender and align with visible From.")
		case strings.Contains(name, "DKIM"):
			parts = append(parts, "Ensure DKIM signatures validate for this sending stream.")
		case strings.Contains(name, "DMARC"):
			parts = append(parts, "Align DMARC with SPF or DKIM pass for the From domain.")
		case strings.Contains(name, "URL"), strings.Contains(name, "PHISH"):
			parts = append(parts, "Review links; remove suspicious redirects/shorteners and limit tracking parameters.")
		case strings.Contains(name, "MIME"), strings.Contains(name, "HTML"):
			parts = append(parts, "Simplify MIME/HTML structure and avoid hidden/deceptive markup.")
		case strings.Contains(name, "RBL"), strings.Contains(name, "DNSBL"):
			parts = append(parts, "Check sender IP reputation and remove DNSBL/RBL listings.")
		}
		if len(parts) >= 4 {
			break
		}
	}
	if len(parts) == 0 {
		return "Inspect Rspamd symbol details and adjust auth, content, and link hygiene."
	}
	return strings.Join(dedupeSorted(parts), " ")
}

func domainFromDKIM(sig string) string {
	sig = strings.ToLower(sig)
	return extractTagValue(sig, "d")
}

func extractTagValue(v, key string) string {
	for _, token := range strings.Split(v, ";") {
		token = strings.TrimSpace(token)
		if strings.HasPrefix(token, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(token, key+"="))
		}
	}
	return ""
}

func emptyFallback(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func readLimited(r interface{ Read([]byte) (int, error) }, limit int64) ([]byte, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 1024), int(limit))
	var b strings.Builder
	for s.Scan() {
		line := s.Text()
		if int64(b.Len()+len(line)+1) > limit {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// rspamdSymbolExplain returns a German admin-facing explanation for a Rspamd
// symbol. Prefix matching handles symbol families (e.g. DMARC_POLICY_*).
func rspamdSymbolExplain(name string) string {
	// Exact matches first.
	switch name {
	// ── Authentication ───────────────────────────────────────────────────────
	case "DMARC_POLICY_ALLOW", "DMARC_POLICY_ALLOW_WITH_FAILURES":
		return "DMARC-Prüfung bestanden. SPF oder DKIM ist aligned mit der sichtbaren From-Domain. → Positiv: Kein Handlungsbedarf."
	case "DMARC_POLICY_REJECT":
		return "DMARC-Policy ist 'reject' und die Mail scheitert am DMARC-Check. → Kritisch: Empfänger-Server wird die Mail ablehnen. SPF und DKIM prüfen, sicherstellen dass mindestens einer aligned besteht."
	case "DMARC_POLICY_QUARANTINE":
		return "DMARC-Policy ist 'quarantine' und die Mail schlägt den Check fehl. → Hoch: Mail landet wahrscheinlich im Spam-Ordner. SPF/DKIM-Alignment korrigieren, DMARC-Policy erst auf 'none' mit Reporting testen."
	case "DMARC_POLICY_SOFTFAIL":
		return "DMARC ergibt Soft Fail: Authentifizierung ist nicht vollständig aligned. → Mittel: Bei strengen Providern negative Auswirkung. Alignment von SPF (Envelope-From) oder DKIM (d=-Tag) zur sichtbaren From-Domain prüfen."
	case "DMARC_NA":
		return "Kein DMARC-Record für die From-Domain. DMARC ist nicht konfiguriert. → Hoch: Die Domain kann von Dritten für Phishing/Spoofing missbraucht werden. Mindestens _dmarc.<domain> TXT mit p=none einrichten und Reporting aktivieren."
	case "R_DKIM_ALLOW", "DKIM_ALLOW":
		return "DKIM-Signatur vorhanden und gültig. Privater Schlüssel stimmt mit dem DNS-Record überein. → Positiv: Kein Handlungsbedarf; prüfen ob d=-Domain auch zur From-Domain passt (Alignment)."
	case "R_DKIM_REJECT", "DKIM_REJECT":
		return "DKIM-Signatur ungültig oder manipuliert. Verifizierung fehlgeschlagen. → Kritisch: Mail verliert Vertrauensbonus, DMARC kann scheitern. Mögliche Ursachen: Mail nach dem Signieren verändert, falscher Selector, abgelaufener DNS-Key. Selector und DNS-Record prüfen."
	case "R_DKIM_TEMPFAIL", "DKIM_TEMPFAIL":
		return "DKIM-Prüfung temporär fehlgeschlagen (DNS-Timeout bei der Schlüsselabfrage). → Gering: Kein dauerhaftes Problem, aber kein Vertrauensbonus für diese Zustellung. DNS-Erreichbarkeit des Signing-Selectors prüfen."
	case "R_DKIM_NA", "DKIM_NA":
		return "Keine DKIM-Signatur in der Mail. DKIM ist am Absender-MTA nicht konfiguriert. → Hoch: Ohne DKIM kann DMARC nur über SPF bestehen; viele Provider werten fehlende DKIM-Signatur negativ. DKIM-Signing im ausgehenden MTA (Postfix: OpenDKIM/Rspamd, Exim: built-in) aktivieren."
	case "R_SPF_ALLOW", "SPF_ALLOW":
		return "SPF-Prüfung bestanden. Die sendende IP ist im SPF-Record der Envelope-From-Domain autorisiert. → Positiv: Kein Handlungsbedarf; sicherstellen dass SPF-Domain auch zur From-Domain passt (Alignment für DMARC)."
	case "R_SPF_FAIL", "SPF_FAIL":
		return "SPF Hard Fail. Die sendende IP ist explizit nicht autorisiert (-all im SPF-Record). → Kritisch: Empfänger sollten diese Mail ablehnen. Entweder die IP zum SPF-Record hinzufügen oder den MTA so konfigurieren, dass er über eine autorisierte IP sendet."
	case "R_SPF_SOFTFAIL", "SPF_SOFTFAIL":
		return "SPF Soft Fail (~all). Die sendende IP ist nicht autorisiert, aber keine harte Ablehnung. → Mittel: Wird oft als Warnung behandelt, erhöht Spam-Score. Sendende IP in den SPF-Record aufnehmen (include:, ip4:, ip6:)."
	case "R_SPF_NEUTRAL", "SPF_NEUTRAL":
		return "SPF Neutral (? Qualifier). Der Record trifft keine Aussage über diese IP. → Gering: Kein positiver oder negativer Einfluss auf DMARC. SPF-Record so anpassen, dass autorisierte IPs explizit erlaubt sind."
	case "R_SPF_NA", "SPF_NA":
		return "Kein SPF-Record für die Envelope-From-Domain. SPF ist nicht konfiguriert. → Hoch: Ohne SPF verliert die Domain Vertrauenspunkte und DMARC kann SPF nicht nutzen. TXT-Record v=spf1 auf der Envelope-From-Domain setzen."
	case "R_SPF_DNSFAIL", "SPF_DNSFAIL":
		return "SPF-Prüfung wegen DNS-Fehler nicht abgeschlossen. → Gering bis mittel: Temporäres Problem; bei Wiederholung DNS-Erreichbarkeit und SPF-Record-Syntax prüfen (zu viele DNS-Lookups, >10, können SPF brechen)."
	case "ARC_ALLOW":
		return "ARC-Chain (Authenticated Received Chain) ist gültig. → Positiv: Weitergeleitete Mail mit intaktem Auth-Nachweis; hilft Empfängern korrekte Bewertung trotz Weiterleitung. Kein Handlungsbedarf."
	case "ARC_INVALID":
		return "ARC-Chain vorhanden, aber ungültig. → Mittel: Mögliche Manipulation nach Weiterleitung oder fehlerhafter ARC-Seal. Weiterleitenden Mailserver prüfen."
	case "ARC_NA":
		return "Keine ARC-Header. Mail wurde nicht weitergeleitet oder ARC nicht genutzt. → Neutral für direkt versendete Mails. Bei Weiterleitungs-Problemen: ARC im weiterleitenden Mailserver aktivieren."

	// ── DNSBL / IP-Reputation ────────────────────────────────────────────────
	case "RCVD_IN_DNSWL_NONE":
		return "IP steht auf keiner DNSWL-Whitelist. Kein Vertrauensbonus. → Neutral: Normal für neue oder kleine Sender. Mit der Zeit durch konsistentes sauberes Versenden Reputation aufbauen."
	case "RCVD_IN_DNSWL_LOW":
		return "IP auf DNSWL als Low-Trust gelistet. Geringe positive Reputation. → Leicht positiv: Zeigt, dass die IP als legitimer Sender bekannt ist."
	case "RCVD_IN_DNSWL_MED":
		return "IP auf DNSWL als Medium-Trust gelistet (z. B. bekannte Mailinglisten-Server). → Positiv: Gute Reputation; kein Handlungsbedarf."
	case "RCVD_IN_DNSWL_HI":
		return "IP auf DNSWL als High-Trust gelistet (große Provider wie Gmail, Outlook, Fastmail). → Sehr positiv: Beste erreichbare Whitelist-Kategorie; kein Handlungsbedarf."
	case "RCVD_IN_MSPIKE_H2":
		return "IP hat gute Reputation in der Mimecast/MSPIKE-Datenbank (Level H2). → Positiv: Kein Handlungsbedarf."
	case "RCVD_IN_MSPIKE_H3", "RCVD_IN_MSPIKE_H4", "RCVD_IN_MSPIKE_H5":
		return "IP hat sehr gute Reputation in der Mimecast/MSPIKE-Datenbank. → Sehr positiv: Kein Handlungsbedarf."
	case "RCVD_IN_MSPIKE_L4", "RCVD_IN_MSPIKE_L5":
		return "IP hat schlechte Reputation in der Mimecast/MSPIKE-Datenbank. → Hoch: Spam-Risiko erhöht. Ursache für schlechte Reputation finden (Spam-Beschwerden, abrupte Volumenänderungen) und beheben; Delisting unter https://www.barracudacentral.org/ beantragen."
	case "RCVD_IN_SBL", "RCVD_IN_SBL_CSS":
		return "IP auf Spamhaus SBL (Spam Block List) gelistet – direkt mit Spam-Quellen assoziiert. → Kritisch: Führt bei den meisten großen Providern zur direkten Ablehnung. Ursache stoppen (offenes Relay, Malware, Spam-Kampagne), dann Delisting unter https://check.spamhaus.org/ beantragen."
	case "RCVD_IN_XBL":
		return "IP auf Spamhaus XBL (Exploits Block List) gelistet – Botnet, Proxy oder kompromittierter Host. → Kritisch: System auf Malware/Botnet prüfen, Ports scannen, Passwörter ändern. Erst nach Bereinigung Delisting unter https://check.spamhaus.org/ beantragen."
	case "RCVD_IN_PBL":
		return "IP auf Spamhaus PBL (Policy Block List) gelistet – typischerweise dynamische/Consumer-IP ohne Mailserver-Berechtigung. → Hoch: E-Mail sollte über einen dedizierten Mailserver mit statischer IP gesendet werden; Consumer-IPs sind für direkten Mailversand nicht geeignet."
	case "RCVD_IN_ZEN":
		return "IP auf Spamhaus ZEN gelistet (kombinierte SBL/XBL/PBL-Datenbank). → Kritisch: Schwerwiegendes Spam-Signal; führt bei fast allen Providern zur Ablehnung. Zuerst prüfen welche Subliste zutrifft (SBL/XBL/PBL), dann gezielt beheben und Delisting beantragen."
	case "RCVD_IN_RP_CERTIFIED":
		return "IP ist Return Path Certified – seriöse ESPs mit strengen Versandstandards. → Positiv: Kein Handlungsbedarf; Vorteil durch bessere Posteingang-Platzierung bei Unterstützern."

	// ── Header-Vollständigkeit ───────────────────────────────────────────────
	case "MISSING_DATE":
		return "Kein Date-Header. RFC 5322 schreibt ihn vor. → Hoch: Deutet auf fehlkonfigurierten MTA hin; erhöht Spam-Score deutlich. MTA so konfigurieren, dass er Date-Header automatisch setzt."
	case "MISSING_FROM":
		return "Kein From-Header. RFC-Pflichtfeld. → Kritisch: Ohne From-Header wird die Mail von praktisch allen Filtern abgelehnt. Versandsoftware prüfen."
	case "MISSING_MID", "MISSING_MESSAGE_ID":
		return "Keine Message-ID. RFC-Pflichtfeld. → Hoch: Beeinträchtigt Threading in Mailclients und erhöht Spam-Score. MTA so konfigurieren, dass er eine eindeutige Message-ID erzeugt (Format: <uuid@domain>)."
	case "MISSING_MIME_VERSION":
		return "Kein MIME-Version-Header. Bei HTML-Mails Pflicht. → Mittel: Deutet auf schlechte MIME-Konstruktion hin; Header 'MIME-Version: 1.0' zur Mail hinzufügen."
	case "MISSING_SUBJECT":
		return "Kein Subject-Header. → Hoch: Erhöht Spam-Score deutlich; kein legitimer MTA lässt den Betreff weg. Betreff im Mailtemplate oder MTA-Konfiguration setzt den Subject-Header."
	case "MISSING_TO":
		return "Kein To-Header. RFC-Pflicht. → Hoch: Das Fehlen weist auf Massenversand ohne korrekten Envelope hin; To-Header in der Mail setzen."
	case "INVALID_DATE":
		return "Date-Header-Datum ist ungültig oder liegt stark in Vergangenheit/Zukunft. → Mittel: Serverzeit prüfen (NTP), MTA-Konfiguration für Date-Header kontrollieren."
	case "DATE_IN_FUTURE":
		return "Datum liegt in der Zukunft. → Mittel: Falsch gestellte Serverzeit oder manipulierter Header. NTP-Synchronisation prüfen."
	case "DATE_IN_PAST":
		return "Datum liegt weit in der Vergangenheit. → Mittel: Falsch gestellte Serverzeit oder lange Queue-Verzögerung. NTP und Mail-Queue-Status prüfen."

	// ── MIME / Struktur ──────────────────────────────────────────────────────
	case "MIME_HTML_ONLY":
		return "Mail enthält nur HTML ohne text/plain-Alternative. → Mittel: Erhöht Spam-Score; Plaintext-Part empfohlen. Mailtemplate so anpassen, dass multipart/alternative mit text/plain und text/html gesendet wird."
	case "MIME_GOOD":
		return "MIME-Struktur korrekt (multipart/alternative mit text/plain und text/html). → Positiv: Kein Handlungsbedarf."
	case "MIME_HTML_NO_TEXT":
		return "HTML-Part vorhanden, aber kein lesbarer Textinhalt extrahierbar. → Mittel: Möglicherweise bild-lastiger Aufbau; mehr sichtbaren Text in den HTML-Part aufnehmen."
	case "MIME_BAD_UNICODE":
		return "Ungültige Unicode-Zeichen im Inhalt. → Mittel: Kann auf Encoding-Fehler oder Obfuskation hinweisen. Charset-Deklaration und Encoding-Konvertierung im Mailtemplate prüfen."
	case "MIME_BASE64_TEXT":
		return "Textteil ist base64-kodiert. Ungewöhnlich. → Gering bis mittel: Einige Filter bewerten base64-kodierten Plaintext negativ. Textteil als quoted-printable oder plain-text senden."
	case "MIME_CHARSET_UNICODE":
		return "Unicode-Charset (UTF-8/UTF-16) verwendet. → Neutral: UTF-8 ist empfohlen; Charset korrekt im Content-Type angeben."

	// ── URLs / Links ─────────────────────────────────────────────────────────
	case "HAS_ONLY_HTML_PART":
		return "Nur HTML-Part, kein Plaintext. → Mittel: Häufiges Muster bei Marketing-Mails; Filter bewerten es negativ. Immer einen text/plain-Part mitschicken."
	case "HTTP_REDIRECTOR":
		return "Link führt über einen HTTP-Redirector. → Mittel bis hoch: Verschleiert das eigentliche Ziel; Spam-Signal. Direkte HTTPS-URLs oder eigene Tracking-Domain verwenden."
	case "R_SUSPICIOUS_URL":
		return "Verdächtige URL erkannt – Muster ähnelt bekannten Phishing- oder Spam-Domains. → Hoch: Alle Links im Mailtemplate auf verdächtige Domains oder Muster prüfen."
	case "URIBL_BLOCKED":
		return "URL-Abfrage durch URIBL geblockt (Abfrage-Limit erreicht). → Neutral: Kein aussagekräftiger Befund; auf eigenen Rspamd-Servern eigene URIBL-API-Keys konfigurieren."
	case "URIBL_SBL":
		return "URL-Domain auf Spamhaus SBL gelistet. → Kritisch: Direkte Spam-Assoziation der verlinkten Domain. Die betroffene Domain aus dem Mailtemplate entfernen oder eine saubere Domain verwenden."
	case "URIBL_ZEN_URIBL":
		return "URL-Domain auf Spamhaus ZEN URIBL gelistet. → Kritisch: Stark mit Spam assoziierte Domain. Verlinkte Domain prüfen und ersetzen."
	case "SURBL_ABUSE":
		return "URL-Domain auf SURBL Abuse-Liste. → Kritisch: Domain ist für Phishing oder Spam bekannt. Verlinkte Domain ersetzen; ggf. eigene Domain auf SURBL prüfen und Delisting beantragen."
	case "SURBL_MULTI":
		return "URL-Domain auf SURBL gelistet. → Hoch: Kombinations-Check mehrerer SURBL-Listen; verlinkte Domain prüfen und ggf. ersetzen."

	// ── Absender / Envelope ──────────────────────────────────────────────────
	case "FROM_HAS_DN":
		return "From enthält einen Anzeigenamen (Display Name). → Neutral bis positiv: Normal für legitime Mails. Mismatch zwischen Anzeigename und Adresse ist aber ein Phishing-Signal; beides konsistent halten."
	case "FROM_NEQ_ENVFROM":
		return "Header-From und Envelope-From (MAIL FROM) stimmen nicht überein. → Mittel: Kann legitim sein (ESP-Bounce-Domain), erhöht aber Spam-Score. Bounce-Domain als Subdomain der From-Domain konfigurieren um SPF-Alignment zu erhalten."
	case "TO_MATCH_ENVRCPT_ALL":
		return "Alle To-Adressen stimmen mit dem Envelope-Rcpt überein. → Positiv: Saubere Konfiguration; kein Handlungsbedarf."
	case "TO_MATCH_ENVRCPT_SOME":
		return "Nur ein Teil der To-Adressen stimmt mit dem Envelope überein. → Gering: Möglicherweise BCC-Versand oder fehlkonfiguriert. Nur wenn Score negativ: Envelope-Empfänger mit To-Header abstimmen."
	case "TO_DN_EQ_ADDR_FROM":
		return "Anzeigename im To-Header stimmt mit der From-Adresse überein. → Gering: Ungewöhnlich, aber selten problematisch."
	case "REPLYTO_DN_EQ_FROM_DN":
		return "Reply-To hat denselben Anzeigenamen wie From. → Neutral: Harmlos wenn intentional."
	case "FORGED_SENDER":
		return "Absender-Domain ist wahrscheinlich gefälscht. → Kritisch: Starkes Phishing-Signal; führt oft zur direkten Ablehnung. SPF, DKIM und DMARC korrekt konfigurieren; die eigene Domain nicht in From-Adressen verwenden ohne korrekte Authentifizierung."
	case "FROM_EXCESS_BASE64":
		return "From-Header ist unnötig base64-kodiert. → Mittel: Verschleierungs-Taktik oder Encoder-Fehler. From-Header als plain ASCII oder RFC 2047 encoded-word bei Sonderzeichen senden."

	// ── Reputation / Scoring ─────────────────────────────────────────────────
	case "BAYES_HAM":
		return "Bayes-Klassifikator stuft die Mail als legitim (Ham) ein. Inhalt ähnelt bekannten Non-Spam-Mails. → Positiv: Kein Handlungsbedarf; gut trainierter Bayes-Filter ist ein starkes positives Signal."
	case "BAYES_SPAM":
		return "Bayes-Klassifikator stuft die Mail als Spam ein. Inhalt ähnelt bekannten Spam-Mustern. → Hoch: Inhalt, Formulierungen und Struktur der Mail überprüfen. Spam-typische Phrasen ('Jetzt klicken!', 'Angebot nur heute', etc.) vermeiden."
	case "NEURAL_HAM":
		return "KI-Modell (neuronales Netz) klassifiziert die Mail als legitim. → Positiv: Starkes positives Signal von Rspamd's ML-Klassifikator; kein Handlungsbedarf."
	case "NEURAL_SPAM":
		return "KI-Modell (neuronales Netz) klassifiziert die Mail als Spam. → Hoch: Der ML-Klassifikator hat strukturelle oder inhaltliche Ähnlichkeit mit Spam erkannt. Inhalt, HTML-Struktur und Formulierungen überarbeiten."

	// ── Sonstiges ────────────────────────────────────────────────────────────
	case "ONCE_RECEIVED":
		return "Nur ein Received-Header. Mail direkt zugestellt ohne Zwischenhop. → Neutral bis positiv für einfache Infrastruktur; unüblich für komplexe Unternehmensinfrastruktur."
	case "TWO_RECEIVED":
		return "Genau zwei Received-Header. Typisch bei direktem Versand über einen Relayhost. → Neutral: Kein Handlungsbedarf."
	case "MULTIPLE_RECEIVED":
		return "Viele Received-Header. Lange Routing-Kette. → Neutral bei komplexer Infrastruktur; bei unerwartet vielen Hops Mail-Queue und Relay-Konfiguration prüfen, um Loops auszuschließen."
	case "HELO_LOCALHOST":
		return "HELO/EHLO ist 'localhost' oder ähnlich. → Kritisch: Fehlkonfigurierter MTA; fast alle Filter werten das stark negativ. myhostname in Postfix oder primary_hostname in Exim auf den echten FQDN des Servers setzen."
	case "HELO_NUMERIC":
		return "HELO/EHLO ist eine IP-Adresse statt eines Hostnamens. → Hoch: RFC-widrig; FQDN des Mailservers als HELO-Name konfigurieren."
	case "HELO_NORES_IP_1", "HELO_NORES_IP_2":
		return "HELO-Name löst nicht zur sendenden IP auf (kein Forward-confirmed rDNS). → Hoch: PTR-Record für die sendende IP beim Hosting-Provider setzen und sicherstellen, dass der A-Record des HELO-Namens auf dieselbe IP zeigt."
	case "RCPT_COUNT_ONE":
		return "Genau ein Empfänger. → Positiv für transaktionale Mails: Kein Handlungsbedarf."
	case "MX_INVALID":
		return "MX-Record der Absender-Domain ist ungültig oder nicht auflösbar. → Mittel: Bounces können nicht zugestellt werden; MX-Record und DNS-Auflösung prüfen."
	case "MX_MISSING":
		return "Kein MX-Record für die Absender-Domain. Bounce-Delivery nicht möglich. → Mittel: MX-Record setzen damit Bounces und DMARC-Reports zugestellt werden können."
	case "MAILLIST":
		return "Mail zeigt Merkmale einer Mailinglisten-Nachricht (List-* Header). → Neutral: ARC bei Weiterleitungen wichtig damit Auth-Ergebnisse erhalten bleiben."
	case "DMARC_DNSFAIL":
		return "DMARC-Abfrage wegen DNS-Fehler nicht abgeschlossen. → Gering: Temporäres Problem; bei Wiederholung _dmarc-DNS-Record und Nameserver prüfen."
	}

	// Prefix matching für Familien ohne exakten Match.
	switch {
	case strings.HasPrefix(name, "DMARC_"):
		return "DMARC-bezogenes Signal. Prüft das Alignment von SPF/DKIM mit der sichtbaren From-Domain. → DMARC-Record unter _dmarc.<domain> prüfen und sicherstellen, dass SPF oder DKIM aligned besteht."
	case strings.HasPrefix(name, "R_DKIM_") || strings.HasPrefix(name, "DKIM_"):
		return "DKIM-Signal. Betrifft die kryptografische Signatur der Mail. → DKIM-Selector, DNS-Key-Record und Signaturkonfiguration im MTA prüfen."
	case strings.HasPrefix(name, "R_SPF_") || strings.HasPrefix(name, "SPF_"):
		return "SPF-Signal. Prüft ob die sendende IP im DNS-Record der Absender-Domain autorisiert ist. → SPF-Record (v=spf1 ...) auf der Envelope-From-Domain prüfen und die sendende IP aufnehmen."
	case strings.HasPrefix(name, "RCVD_IN_"):
		return "IP-Reputationscheck (DNSBL/Whitelist). Die sendende IP wird gegen eine externe Liste geprüft. → IP unter https://multirbl.valli.org/ prüfen; bei negativen Listings Ursache beheben und Delisting beantragen."
	case strings.HasPrefix(name, "URIBL_") || strings.HasPrefix(name, "SURBL_"):
		return "URL-Blacklist-Treffer. Eine verlinkte Domain ist auf einer Spam- oder Phishing-Liste gelistet. → Alle Links im Mailtemplate prüfen; betroffene Domain unter https://mxtoolbox.com/blacklists.aspx prüfen."
	case strings.HasPrefix(name, "BAYES_"):
		return "Bayes-Klassifikator. Bewertet den Inhalt statistisch anhand erlernter Spam-/Ham-Muster. → Bei BAYES_SPAM: Formulierungen, Struktur und Inhalt der Mail überprüfen; Spam-typische Phrasen vermeiden."
	case strings.HasPrefix(name, "NEURAL_"):
		return "Neuronales Netz. KI-basierte Klassifikation des Mail-Inhalts. → Bei NEURAL_SPAM: Inhalt und HTML-Struktur überarbeiten; signifikante Änderungen sind oft nötig."
	case strings.HasPrefix(name, "FUZZY_"):
		return "Fuzzy-Hash-Treffer. Inhalt ähnelt einer bekannten Spam-Mail in der Datenbank. → Mail-Inhalt und Template deutlich überarbeiten; Wiederverwendung von Spam-Mustern vermeiden."
	case strings.HasPrefix(name, "MISSING_"):
		return "Pflicht-Header fehlt. RFC 5322 schreibt diesen Header vor. → MTA oder Versandsoftware so konfigurieren, dass alle RFC-Pflicht-Header (Date, From, Message-ID, MIME-Version) gesetzt werden."
	case strings.HasPrefix(name, "HELO_"):
		return "HELO/EHLO-Signal. Betrifft den Hostnamen, mit dem sich der sendende MTA vorstellt. → myhostname (Postfix) / primary_hostname (Exim) auf den echten FQDN des Servers setzen; PTR-Record muss übereinstimmen."
	case strings.HasPrefix(name, "MX_"):
		return "MX-Record-Check. Prüft ob die Absender-Domain korrekte Empfangsserver konfiguriert hat. → MX-Record für die Domain setzen und sicherstellen, dass er korrekt auflöst."
	case strings.HasPrefix(name, "ARC_"):
		return "ARC (Authenticated Received Chain). Bewahrt Auth-Ergebnisse über Weiterleitungen hinweg. → Relevant bei Mail-Weiterleitungen; weiterleitenden Mailserver mit ARC-Unterstützung konfigurieren."
	case strings.HasPrefix(name, "MIME_"):
		return "MIME-Struktur-Signal. Betrifft den technischen Aufbau der Nachricht (Multipart, Encoding, Charset). → multipart/alternative mit text/plain und text/html verwenden; Charset-Angabe und Boundaries prüfen."
	case strings.HasPrefix(name, "FROM_") || strings.HasPrefix(name, "TO_") || strings.HasPrefix(name, "REPLYTO_"):
		return "Absender/Empfänger-Signal. Prüft Konsistenz und Vertrauenswürdigkeit der Adress-Header. → From, Reply-To und Envelope-From konsistent und zur eigenen Domain passend konfigurieren."
	}
	return ""
}
