package main

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"sort"
	"strconv"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"

	"github.com/brightcolor/sender-report/internal/analyzer"
	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/smtp"
)

type authResults struct {
	SPFResult   string
	SPFDomain   string
	SPFDetail   string
	DKIMResult  string
	DKIMDomain  string
	DKIMDetail  string
	DMARCResult string
	FromDomain  string
	DMARCDetail string
}

func enrichWithReceiverAuthHeaders(ctx context.Context, cfg config.Config, rm smtp.ReceivedMail, raw string) string {
	res := evaluateAuthResults(ctx, rm, raw)
	authHeader := buildAuthenticationResultsHeader(cfg.SMTPDomain, res)
	receivedSPF := buildReceivedSPFHeader(cfg.SMTPDomain, rm, res.SPFResult)
	detailHeaders := []string{
		authHeader,
		receivedSPF,
		"X-Sender-Report-SPF-Detail: " + safeAuthValue(emptyFallback(res.SPFDetail, "none")),
		"X-Sender-Report-DKIM-Detail: " + safeAuthValue(emptyFallback(res.DKIMDetail, "none")),
		"X-Sender-Report-DMARC-Detail: " + safeAuthValue(emptyFallback(res.DMARCDetail, "none")),
	}
	return prependHeaders(raw, detailHeaders)
}

func evaluateAuthResults(ctx context.Context, rm smtp.ReceivedMail, raw string) authResults {
	out := authResults{
		SPFResult:   "none",
		DKIMResult:  "none",
		DMARCResult: "none",
	}

	ip := net.ParseIP(strings.TrimSpace(rm.RemoteIP))
	spfRes, spfDomain, spfDetail := evaluateSPF(ctx, ip, rm.HELO, rm.MailFrom)
	out.SPFResult = spfRes
	out.SPFDomain = spfDomain
	out.SPFDetail = spfDetail

	dkimRes, dkimDomain, dkimDetail := evaluateDKIM(raw)
	out.DKIMResult = dkimRes
	out.DKIMDomain = dkimDomain
	out.DKIMDetail = dkimDetail

	out.FromDomain = fromDomain(raw)
	out.DMARCResult, out.DMARCDetail = evaluateDMARC(ctx, out.FromDomain, out.SPFResult, out.SPFDomain, out.DKIMResult, out.DKIMDomain)

	return out
}

func buildAuthenticationResultsHeader(authServID string, res authResults) string {
	if strings.TrimSpace(authServID) == "" {
		authServID = "sender-report.local"
	}
	spfDomain := safeAuthValue(emptyFallback(res.SPFDomain, "unknown"))
	dkimDomain := safeAuthValue(emptyFallback(res.DKIMDomain, "unknown"))
	fromDomain := safeAuthValue(emptyFallback(res.FromDomain, "unknown"))

	line := fmt.Sprintf(
		"Authentication-Results: %s; spf=%s smtp.mailfrom=%s; dkim=%s header.d=%s; dmarc=%s header.from=%s",
		authServID,
		safeAuthValue(res.SPFResult),
		spfDomain,
		safeAuthValue(res.DKIMResult),
		dkimDomain,
		safeAuthValue(res.DMARCResult),
		fromDomain,
	)
	return line
}

func buildReceivedSPFHeader(receiver string, rm smtp.ReceivedMail, spfResult string) string {
	return fmt.Sprintf(
		"Received-SPF: %s client-ip=%s; envelope-from=%s; helo=%s; receiver=%s",
		safeAuthValue(spfResult),
		safeAuthValue(rm.RemoteIP),
		safeAuthValue(emptyFallback(rm.MailFrom, "<>")),
		safeAuthValue(emptyFallback(rm.HELO, "unknown")),
		safeAuthValue(emptyFallback(receiver, "sender-report.local")),
	)
}

func prependHeaders(raw string, extra []string) string {
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.SplitN(norm, "\n\n", 2)
	headerPart := ""
	bodyPart := ""
	if len(parts) > 0 {
		headerPart = parts[0]
	}
	if len(parts) == 2 {
		bodyPart = parts[1]
	}

	all := make([]string, 0, len(extra)+1)
	for _, h := range extra {
		h = strings.TrimSpace(h)
		if h != "" {
			all = append(all, h)
		}
	}
	if strings.TrimSpace(headerPart) != "" {
		all = append(all, headerPart)
	}

	joined := strings.Join(all, "\n")
	if bodyPart != "" {
		joined += "\n\n" + bodyPart
	} else {
		joined += "\n\n"
	}
	return strings.ReplaceAll(joined, "\n", "\r\n")
}

func safeAuthValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	v = strings.ReplaceAll(v, ";", "")
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return v
}

func fromDomain(raw string) string {
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return ""
	}
	from := strings.TrimSpace(msg.Header.Get("From"))
	if from == "" {
		return ""
	}
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return extractDomain(from)
	}
	return extractDomain(addr.Address)
}

func evaluateDKIM(raw string) (result, domain string, detail string) {
	verifs, err := dkim.Verify(strings.NewReader(raw))
	if len(verifs) == 0 {
		if err != nil {
			switch {
			case dkim.IsTempFail(err):
				return "temperror", "", err.Error()
			case dkim.IsPermFail(err):
				return "permerror", "", err.Error()
			default:
				return "fail", "", err.Error()
			}
		}
		return "none", "", "no signature"
	}

	chunks := make([]string, 0, len(verifs))
	for _, v := range verifs {
		if v == nil {
			continue
		}
		if v.Err == nil {
			chunks = append(chunks, fmt.Sprintf("%s=pass", emptyFallback(v.Domain, "unknown")))
		} else {
			chunks = append(chunks, fmt.Sprintf("%s=%s", emptyFallback(v.Domain, "unknown"), v.Err.Error()))
		}
		if v.Err == nil {
			return "pass", strings.ToLower(strings.TrimSpace(v.Domain)), strings.Join(chunks, ", ")
		}
	}
	for _, v := range verifs {
		if v == nil || v.Err == nil {
			continue
		}
		if dkim.IsTempFail(v.Err) {
			return "temperror", strings.ToLower(strings.TrimSpace(v.Domain)), strings.Join(chunks, ", ")
		}
	}
	for _, v := range verifs {
		if v == nil || v.Err == nil {
			continue
		}
		if dkim.IsPermFail(v.Err) {
			return "permerror", strings.ToLower(strings.TrimSpace(v.Domain)), strings.Join(chunks, ", ")
		}
	}
	for _, v := range verifs {
		if v != nil {
			return "fail", strings.ToLower(strings.TrimSpace(v.Domain)), strings.Join(chunks, ", ")
		}
	}
	return "fail", "", strings.Join(chunks, ", ")
}

func evaluateDMARC(ctx context.Context, fromDomain, spfResult, spfDomain, dkimResult, dkimDomain string) (string, string) {
	if strings.TrimSpace(fromDomain) == "" {
		return "none", "missing from domain"
	}
	rec, err := dmarc.LookupWithOptions(fromDomain, &dmarc.LookupOptions{
		LookupTXT: func(domain string) ([]string, error) {
			return net.DefaultResolver.LookupTXT(ctx, domain)
		},
	})
	if err != nil {
		switch {
		case err == dmarc.ErrNoPolicy:
			return "none", "no policy"
		case dmarc.IsTempFail(err):
			return "temperror", err.Error()
		default:
			return "permerror", err.Error()
		}
	}

	spfAligned := false
	if spfResult == "pass" {
		spfAligned = domainAligned(spfDomain, fromDomain, rec.SPFAlignment == dmarc.AlignmentStrict)
	}
	dkimAligned := false
	if dkimResult == "pass" {
		dkimAligned = domainAligned(dkimDomain, fromDomain, rec.DKIMAlignment == dmarc.AlignmentStrict)
	}
	detail := fmt.Sprintf("policy=%s spf_aligned=%t dkim_aligned=%t adkim=%s aspf=%s", rec.Policy, spfAligned, dkimAligned, rec.DKIMAlignment, rec.SPFAlignment)
	if spfAligned || dkimAligned {
		return "pass", detail
	}
	return "fail", detail
}

func domainAligned(authDomain, fromDomain string, strict bool) bool {
	authDomain = strings.ToLower(strings.TrimSpace(authDomain))
	fromDomain = strings.ToLower(strings.TrimSpace(fromDomain))
	if authDomain == "" || fromDomain == "" {
		return false
	}
	if strict {
		return authDomain == fromDomain
	}
	return authDomain == fromDomain || strings.HasSuffix(authDomain, "."+fromDomain) || strings.HasSuffix(fromDomain, "."+authDomain)
}

func evaluateSPF(ctx context.Context, remoteIP net.IP, helo, envelopeFrom string) (result, domain string, detail string) {
	domain = extractDomain(envelopeFrom)
	if domain == "" {
		domain = strings.ToLower(strings.TrimSpace(helo))
	}
	if domain == "" || remoteIP == nil {
		return "none", domain, "missing sender domain or remote ip"
	}
	seen := make(map[string]struct{})
	lookups := 0
	res, matchedBy := checkSPFDomain(ctx, remoteIP, domain, 0, seen, &lookups)
	detail = fmt.Sprintf("domain=%s mechanism=%s", domain, emptyFallback(matchedBy, "none"))
	return res, domain, detail
}

// spfLookupBudget is the RFC 7208 §4.6.4 limit on DNS-querying mechanisms per
// SPF evaluation. It is a property of the whole evaluation, not of one nesting
// level, which is why it lives in a counter passed down rather than in depth.
const spfLookupBudget = 10

func checkSPFDomain(ctx context.Context, remoteIP net.IP, domain string, depth int, seen map[string]struct{}, lookups *int) (string, string) {
	if depth > 10 {
		return "permerror", "depth-limit"
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "none", "empty-domain"
	}
	if _, ok := seen[domain]; ok {
		return "permerror", "loop-detected"
	}
	seen[domain] = struct{}{}
	defer delete(seen, domain)

	record, recErr := lookupSPFRecord(ctx, domain)
	if recErr == "none" {
		return "none", "no-record"
	}
	if recErr == "temperror" {
		return "temperror", "dns-temporary-error"
	}
	if recErr == "permerror" {
		return "permerror", "multiple-records"
	}

	tokens := strings.Fields(record)
	if len(tokens) == 0 {
		return "none", "empty-record"
	}

	redirect := ""
	for _, tok := range tokens[1:] {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(tok), "redirect=") {
			redirect = strings.TrimSpace(strings.SplitN(tok, "=", 2)[1])
			continue
		}
		if strings.HasPrefix(strings.ToLower(tok), "exp=") {
			continue
		}
		if strings.Contains(tok, "=") {
			continue
		}

		qualifier := byte('+')
		if strings.ContainsRune("+-~?", rune(tok[0])) {
			qualifier = tok[0]
			tok = tok[1:]
		}
		matched, errRes := matchSPFMechanism(ctx, remoteIP, domain, tok, depth, seen, lookups)
		if errRes != "" {
			return errRes, nameOrToken(tok)
		}
		if matched {
			return qualifierToResult(qualifier), nameOrToken(tok)
		}
	}

	if redirect != "" {
		// redirect= counts against the same budget (RFC 7208 §4.6.4).
		*lookups++
		if *lookups > spfLookupBudget {
			return "permerror", "lookup-limit"
		}
		res, mech := checkSPFDomain(ctx, remoteIP, redirect, depth+1, seen, lookups)
		if mech == "" {
			mech = "redirect"
		}
		return res, "redirect->" + mech
	}
	return "neutral", "default-neutral"
}

func lookupSPFRecord(ctx context.Context, domain string) (record string, status string) {
	txts, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return "", "none"
		}
		return "", "temperror"
	}
	matchCount := 0
	for _, rec := range txts {
		rec = strings.TrimSpace(rec)
		if strings.HasPrefix(strings.ToLower(rec), "v=spf1") {
			matchCount++
			record = rec
		}
	}
	if matchCount > 1 {
		return "", "permerror"
	}
	if record != "" {
		return record, ""
	}
	return "", "none"
}

func matchSPFMechanism(ctx context.Context, remoteIP net.IP, currentDomain, mechanism string, depth int, seen map[string]struct{}, lookups *int) (bool, string) {
	name, value, cidr := parseSPFMechanism(mechanism)

	// RFC 7208 §4.6.4: include, a, mx, ptr and exists each cost one DNS lookup,
	// and at most ten are allowed across the whole evaluation. Receivers enforce
	// this, so a record that exceeds it fails in the real world — while this
	// evaluator, which bounded only nesting depth, happily followed a long flat
	// chain of includes and reported a pass.
	switch name {
	case "include", "a", "mx", "ptr", "exists":
		*lookups++
		if *lookups > spfLookupBudget {
			return false, "permerror"
		}
	}

	switch name {
	case "all":
		return true, ""
	case "include":
		if value == "" {
			return false, "permerror"
		}
		res, _ := checkSPFDomain(ctx, remoteIP, value, depth+1, seen, lookups)
		if res == "pass" {
			return true, ""
		}
		if res == "temperror" || res == "permerror" {
			return false, res
		}
		return false, ""
	case "ip4":
		return ipMatchesWithOptionalCIDR(remoteIP, net.ParseIP(value), normalizeCIDR(cidr, 32)), ""
	case "ip6":
		return ipMatchesWithOptionalCIDR(remoteIP, net.ParseIP(value), normalizeCIDR(cidr, 128)), ""
	case "a":
		target := value
		if target == "" {
			target = currentDomain
		}
		return hostResolvesToIP(ctx, target, remoteIP, cidr)
	case "mx":
		target := value
		if target == "" {
			target = currentDomain
		}
		return mxResolvesToIP(ctx, target, remoteIP, cidr)
	case "exists":
		target := value
		if target == "" {
			target = currentDomain
		}
		ips, err := net.DefaultResolver.LookupHost(ctx, target)
		if err != nil {
			// IsTemporary alone misses timeouts and non-DNSError failures, both of
			// which are lookup failures rather than an absent record.
			if analyzer.DNSLookupFailed(err) {
				return false, "temperror"
			}
			return false, ""
		}
		return len(ips) > 0, ""
	case "ptr":
		// RFC 7208 §5.5: without a value the mechanism uses the current domain.
		// Leaving it empty made the suffix comparison below trivially true for
		// every PTR name, so `v=spf1 mx ptr -all` authorised every IP on the
		// internet — the exact opposite of what such a record is meant to say.
		target := strings.ToLower(strings.TrimSpace(value))
		if target == "" {
			target = strings.ToLower(strings.TrimSpace(currentDomain))
		}
		if target == "" {
			return false, ""
		}
		ptrs, err := net.DefaultResolver.LookupAddr(ctx, remoteIP.String())
		if err != nil {
			if analyzer.DNSLookupFailed(err) {
				return false, "temperror"
			}
			return false, ""
		}
		for _, host := range ptrs {
			host = strings.TrimSuffix(strings.ToLower(host), ".")
			if !ptrNameUnderDomain(host, target) {
				continue
			}
			// RFC 7208 §5.5 requires the PTR name to resolve back to the
			// connecting IP; without that check anyone who controls the reverse
			// zone of their own address could claim any domain.
			if matched, errRes := hostResolvesToIP(ctx, host, remoteIP, -1); matched {
				return true, ""
			} else if errRes != "" {
				return false, errRes
			}
		}
		return false, ""
	default:
		return false, ""
	}
}

// ptrNameUnderDomain reports whether a reverse-DNS name belongs to a domain:
// it must be the domain itself or a subdomain of it, on a label boundary.
//
// Two bugs lived in the plain suffix comparison this replaces. With an empty
// domain it was trivially true for every name, so `v=spf1 mx ptr -all`
// authorised the entire internet. And without the boundary, "notexample.org"
// counted as belonging to "example.org" — anyone could register a name ending
// in someone else's domain and pass their ptr mechanism.
func ptrNameUnderDomain(host, domain string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if host == "" || domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func parseSPFMechanism(mech string) (name, value string, cidr int) {
	cidr = -1
	raw := strings.TrimSpace(mech)
	if i := strings.Index(raw, ":"); i >= 0 {
		name = strings.ToLower(strings.TrimSpace(raw[:i]))
		value = strings.TrimSpace(raw[i+1:])
	} else {
		name = strings.ToLower(raw)
	}
	if j := strings.Index(name, "/"); j >= 0 {
		cidr = parseCIDRBits(name[j+1:])
		name = strings.TrimSpace(name[:j])
	}
	if slash := strings.Index(value, "/"); slash >= 0 {
		rawCIDR := strings.TrimSpace(value[slash+1:])
		value = value[:slash]
		cidr = parseCIDRBits(rawCIDR)
	}
	return name, value, cidr
}

// hostResolvesToIP reports whether host resolves to an address matching
// remoteIP. The second return value is "temperror" when the lookup could not be
// answered at all: RFC 7208 §4.4 requires SPF evaluation to stop there instead
// of treating the mechanism as "no match". Without it a resolver outage lets a
// trailing `-all` turn a perfectly correct record into a hard fail.
func hostResolvesToIP(ctx context.Context, host string, remoteIP net.IP, cidr int) (bool, string) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		if analyzer.DNSLookupFailed(err) {
			return false, "temperror"
		}
		return false, ""
	}
	for _, a := range addrs {
		if ipMatchesWithOptionalCIDR(remoteIP, a.IP, cidr) {
			return true, ""
		}
	}
	return false, ""
}

// mxResolvesToIP reports whether any MX host of domain resolves to remoteIP.
// Like hostResolvesToIP it surfaces "temperror" for a lookup that failed —
// both for the MX query itself and for the address lookup of each MX host.
func mxResolvesToIP(ctx context.Context, domain string, remoteIP net.IP, cidr int) (bool, string) {
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		if analyzer.DNSLookupFailed(err) {
			return false, "temperror"
		}
		return false, ""
	}
	sort.SliceStable(mxs, func(i, j int) bool {
		return mxs[i].Pref < mxs[j].Pref
	})
	// A failed lookup for one MX host is remembered but does not stop the loop:
	// another host may still match. Only if none matches does the failure decide
	// the outcome — otherwise a single unreachable MX would mask a valid match.
	deferred := ""
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		matched, errRes := hostResolvesToIP(ctx, host, remoteIP, cidr)
		if matched {
			return true, ""
		}
		if errRes != "" {
			deferred = errRes
		}
	}
	return false, deferred
}

func ipMatchesWithOptionalCIDR(remoteIP, candidate net.IP, cidr int) bool {
	if remoteIP == nil || candidate == nil {
		return false
	}
	if cidr < 0 {
		return remoteIP.Equal(candidate)
	}
	bits := 128
	base := candidate
	check := remoteIP
	if candidate.To4() != nil && remoteIP.To4() != nil {
		bits = 32
		base = candidate.To4()
		check = remoteIP.To4()
	}
	if cidr > bits {
		return false
	}
	mask := net.CIDRMask(cidr, bits)
	if mask == nil {
		return false
	}
	return base.Mask(mask).Equal(check.Mask(mask))
}

func qualifierToResult(q byte) string {
	switch q {
	case '+':
		return "pass"
	case '-':
		return "fail"
	case '~':
		return "softfail"
	case '?':
		return "neutral"
	default:
		return "neutral"
	}
}

func extractDomain(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "<>"))
	if v == "" {
		return ""
	}
	at := strings.LastIndex(v, "@")
	if at < 0 || at+1 >= len(v) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(v[at+1:]))
}

func parseCIDRBits(v string) int {
	i, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return -1
	}
	return i
}

func nameOrToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if strings.ContainsRune("+-~?", rune(token[0])) {
		token = token[1:]
	}
	if i := strings.Index(token, ":"); i >= 0 {
		return strings.ToLower(strings.TrimSpace(token[:i]))
	}
	return strings.ToLower(token)
}

func normalizeCIDR(cidr int, bits int) int {
	if cidr < 0 {
		return bits
	}
	return cidr
}

func emptyFallback(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
