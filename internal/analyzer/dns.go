package analyzer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/net/idna"

	"github.com/brightcolor/sender-report/internal/model"
)

// dnsStatus tells an authoritative "this record does not exist" apart from
// "we could not ask at all".
//
// net.Resolver reports both cases the same way — an empty result plus a
// non-nil error — so a discarded error turns a resolver outage into the claim
// that a record is missing. That is the worst failure this tool can produce:
// it tells senders with a correct setup that their DNS is broken, costs them
// score, and sends them off to change a zone that was fine. Every lookup in
// this package therefore goes through the helpers below instead of calling
// net.DefaultResolver directly.
type dnsStatus int

const (
	// dnsOK means the lookup answered and returned at least one record.
	dnsOK dnsStatus = iota
	// dnsAbsent means the answer was authoritative and negative: the name does
	// not exist (NXDOMAIN) or carries no record of this type (NODATA). Only
	// this state justifies telling the user that something is missing.
	dnsAbsent
	// dnsUnavailable means the question could not be answered: SERVFAIL,
	// timeout, connection refused, no reachable resolver. Nothing may be
	// concluded about the domain — neither present nor missing.
	dnsUnavailable
)

// unresolvable marks a name that cannot be asked about at all.
var errUnresolvableName = errors.New("domain name cannot be represented in DNS")

// dnsFailures counts lookups that could not be answered since process start.
//
// Without it a resolver outage left no trace anywhere: the reports said "not
// checkable" to whoever happened to read them, but the operator saw a green
// healthcheck and no log line. Exposed through DNSFailureCount for /readyz and
// the metrics page, so a broken resolver is visible from outside.
var dnsFailures atomic.Uint64

// DNSFailureCount returns how many DNS lookups could not be answered since the
// process started. A number climbing with every report means this server's
// resolver is not working, not that senders' domains are misconfigured.
func DNSFailureCount() uint64 { return dnsFailures.Load() }

// classifyDNSError maps a resolver error onto the three states above.
//
// net.DNSError.IsNotFound is the only flag that signals an authoritative
// negative answer. Everything else — IsTemporary, IsTimeout, or an error that
// is not a DNSError at all — means the lookup failed, not that the record is
// absent. Defaulting to dnsUnavailable is deliberate: an unknown error must
// never be read as "no such record".
func classifyDNSError(err error) dnsStatus {
	if err == nil {
		return dnsOK
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return dnsAbsent
	}
	dnsFailures.Add(1)
	return dnsUnavailable
}

// DNSLookupFailed reports whether err means the question could not be answered,
// as opposed to an authoritative "no such record".
//
// Exported for the SMTP-side SPF evaluation in cmd/sender-report: RFC 7208 §4.4
// requires evaluation to stop with temperror when a mechanism's lookup fails.
// Treating it as "mechanism does not match" lets a trailing `-all` produce a
// hard fail for a record that is entirely correct.
func DNSLookupFailed(err error) bool {
	return classifyDNSError(err) == dnsUnavailable
}

// isASCII reports whether s consists solely of ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// asciiDomain converts a domain to the Punycode (A-label) form the resolver
// expects.
//
// Go rejects non-ASCII names in isDomainName before any query goes out and
// reports IsNotFound — so an umlaut domain would look exactly like a domain
// that does not exist, and the three states above would not help. Conversion
// runs per label and only where it is needed: underscore labels such as
// `_dmarc` or `selector._domainkey` are valid in DNS but not under the IDNA
// lookup profile, so ASCII labels are passed through untouched.
func asciiDomain(name string) (string, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if trimmed == "" {
		return "", errUnresolvableName
	}
	if isASCII(trimmed) {
		return trimmed, nil
	}
	labels := strings.Split(trimmed, ".")
	for i, label := range labels {
		if isASCII(label) {
			continue
		}
		converted, err := idna.ToASCII(label)
		if err != nil {
			return "", fmt.Errorf("%w: %q: %v", errUnresolvableName, label, err)
		}
		labels[i] = converted
	}
	return strings.Join(labels, "."), nil
}

// lookupTXT resolves TXT records and reports which of the three states applies.
func lookupTXT(ctx context.Context, name string) ([]string, dnsStatus) {
	ascii, err := asciiDomain(name)
	if err != nil {
		return nil, dnsAbsent
	}
	recs, err := net.DefaultResolver.LookupTXT(ctx, ascii)
	if err != nil {
		return nil, classifyDNSError(err)
	}
	if len(recs) == 0 {
		return nil, dnsAbsent
	}
	return recs, dnsOK
}

// lookupMX resolves MX records and reports which of the three states applies.
func lookupMX(ctx context.Context, name string) ([]*net.MX, dnsStatus) {
	ascii, err := asciiDomain(name)
	if err != nil {
		return nil, dnsAbsent
	}
	mxs, err := net.DefaultResolver.LookupMX(ctx, ascii)
	if err != nil {
		return nil, classifyDNSError(err)
	}
	if len(mxs) == 0 {
		return nil, dnsAbsent
	}
	return mxs, dnsOK
}

// lookupIPAddr resolves A/AAAA records and reports which state applies.
func lookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, dnsStatus) {
	ascii, err := asciiDomain(name)
	if err != nil {
		return nil, dnsAbsent
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, ascii)
	if err != nil {
		return nil, classifyDNSError(err)
	}
	if len(ips) == 0 {
		return nil, dnsAbsent
	}
	return ips, dnsOK
}

// lookupHost resolves a hostname to its addresses and reports which state
// applies. Used for the forward half of a forward-confirmed reverse DNS check.
func lookupHost(ctx context.Context, name string) ([]string, dnsStatus) {
	ascii, err := asciiDomain(name)
	if err != nil {
		return nil, dnsAbsent
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, ascii)
	if err != nil {
		return nil, classifyDNSError(err)
	}
	if len(addrs) == 0 {
		return nil, dnsAbsent
	}
	return addrs, dnsOK
}

// lookupAddr resolves the PTR records of an IP and reports which state applies.
func lookupAddr(ctx context.Context, ip string) ([]string, dnsStatus) {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil, classifyDNSError(err)
	}
	if len(names) == 0 {
		return nil, dnsAbsent
	}
	return names, dnsOK
}

// dmarcLookup is the result of resolving a From domain's DMARC policy.
type dmarcLookupResult struct {
	Records []string // the raw v=DMARC1 records found
	Policy  string   // the policy that applies to this From domain
	Domain  string   // where the record was actually found
	ViaOrg  bool     // true when it came from the organisational domain
	Status  dnsStatus
}

// lookupDMARCRecord finds the DMARC policy for a From domain.
//
// RFC 7489 §6.6.3 defines a two-step lookup: the From domain first, and if it
// publishes no record, its organisational domain. Only the first step was
// implemented, so the ordinary setup "From on a subdomain, DMARC published once
// on the main domain" was reported as "no DMARC record" — the single largest
// deduction in the report, for a configuration that is not only valid but
// recommended. When the policy comes from the organisational domain, a
// subdomain is governed by sp= where that tag is present.
func lookupDMARCRecord(ctx context.Context, fromDomain string) dmarcLookupResult {
	fromDomain = normDomain(fromDomain)
	if fromDomain == "" {
		return dmarcLookupResult{Status: dnsAbsent}
	}

	if res, ok := dmarcRecordsAt(ctx, fromDomain); ok {
		res.Policy = extractTagValue(strings.ToLower(res.Records[0]), "p")
		return res
	} else if res.Status == dnsUnavailable {
		return res
	}

	org := registrableDomain(fromDomain)
	if org == "" || org == fromDomain {
		return dmarcLookupResult{Domain: fromDomain, Status: dnsAbsent}
	}
	res, ok := dmarcRecordsAt(ctx, org)
	if !ok {
		return res
	}
	res.ViaOrg = true
	lower := strings.ToLower(res.Records[0])
	// For a subdomain the sp= tag wins where it is set; otherwise p= applies.
	if sp := extractTagValue(lower, "sp"); sp != "" {
		res.Policy = sp
	} else {
		res.Policy = extractTagValue(lower, "p")
	}
	return res
}

// dmarcRecordsAt fetches the v=DMARC1 records published at one domain.
func dmarcRecordsAt(ctx context.Context, domain string) (dmarcLookupResult, bool) {
	recs, st := lookupTXT(ctx, "_dmarc."+domain)
	out := dmarcLookupResult{Domain: domain, Status: st}
	if st != dnsOK {
		return out, false
	}
	for _, r := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=dmarc1") {
			out.Records = append(out.Records, strings.TrimSpace(r))
		}
	}
	if len(out.Records) == 0 {
		out.Status = dnsAbsent
		return out, false
	}
	return out, true
}

// unresolvedNote is the sentence appended to every check that ended in
// dnsUnavailable, kept in one place so the wording stays identical everywhere.
const unresolvedNote = "Das sagt nichts über Ihre Einstellungen aus — der Eintrag kann durchaus vorhanden sein. Wir konnten ihn in diesem Moment nur nicht abfragen."

// unresolved builds the third state a check can end in: the lookup itself did
// not work, so neither "present" nor "missing" may be claimed.
//
// It never moves the score. A resolver that does not answer is not the
// sender's mistake, and charging points for it would make an outage on this
// server look like a fault in someone else's domain.
//
// subject names what was being looked up, in words the reader recognises from
// the check title (e.g. "Der DMARC-Eintrag").
func unresolved(id, name, subject string) model.CheckResult {
	c := info(id, name, 0,
		fmt.Sprintf("%s konnte nicht abgefragt werden: Die Namensauflösung (DNS) hat nicht geantwortet. %s", subject, unresolvedNote),
		"Warten Sie einen Moment und starten Sie die Prüfung erneut. Erscheint der Hinweis dauerhaft, liegt es entweder an den Nameservern Ihrer Domain oder an der Internetverbindung dieses Prüfservers — nicht an Ihrem E-Mail-Versand.")
	return withDetails(c, map[string]string{
		unresolvedDetailKey: "nicht beantwortet (kein NXDOMAIN, sondern Fehler oder Zeitüberschreitung)",
	})
}

// English variants of the unresolved wording. Reports are stored bilingually,
// so this state needs its own English text — falling back to the ordinary
// "info" phrasing would assert on one language what the other refuses to claim.
const (
	unresolvedSummaryEN = "This could not be checked: the DNS lookup did not answer. That says nothing about your settings — the record may well be in place. We simply could not read it at this moment."

	unresolvedRecommendationEN = "Wait a moment and run the check again. If this notice persists, the cause is either your domain's name servers or this test server's own connection to DNS — not your mail setup."
)

// unresolvedDetailKey marks a check that ended in dnsUnavailable. It is set by
// unresolved() and read back by countUnresolved() so the report header can say
// how much of the result is missing.
const unresolvedDetailKey = "dns_lookup"

// countUnresolved counts the checks that could not be completed because a DNS
// lookup did not answer.
func countUnresolved(checks []model.CheckResult) int {
	n := 0
	for _, c := range checks {
		if _, ok := c.TechnicalDetails[unresolvedDetailKey]; ok {
			n++
		}
	}
	return n
}

// unresolvedWarning is the line added to the report header when at least one
// check ended in dnsUnavailable, so the score is not read as a complete result.
func unresolvedWarning(count int) string {
	if count == 1 {
		return "Eine Prüfung konnte nicht durchgeführt werden, weil die DNS-Abfrage nicht beantwortet wurde. Das Ergebnis ist deshalb unvollständig — bitte später erneut prüfen."
	}
	return fmt.Sprintf("%d Prüfungen konnten nicht durchgeführt werden, weil DNS-Abfragen nicht beantwortet wurden. Das Ergebnis ist deshalb unvollständig — bitte später erneut prüfen.", count)
}

// dedupeKeepOrder removes duplicates while preserving first-seen order.
//
// The counterpart dedupeSorted also sorts, which is right for warnings but wrong
// for advice: it put the alphabetically first recommendation at the top of the
// sidebar regardless of how much the underlying problem costs.
func dedupeKeepOrder(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// spamAssassinScorePattern matches the score and limit in a SpamAssassin
// "Spam: False ; 4.9 / 5.0" status line.
var spamAssassinScorePattern = regexp.MustCompile(`(-?\d+(?:\.\d+)?)\s*/\s*(-?\d+(?:\.\d+)?)`)

// parseSpamAssassinScore pulls the score and the configured limit out of the
// status line, so a near miss can be reported instead of only a hard verdict.
func parseSpamAssassinScore(line string) (score, limit float64, ok bool) {
	m := spamAssassinScorePattern.FindStringSubmatch(line)
	if len(m) != 3 {
		return 0, 0, false
	}
	s, err1 := strconv.ParseFloat(m[1], 64)
	l, err2 := strconv.ParseFloat(m[2], 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return s, l, true
}
