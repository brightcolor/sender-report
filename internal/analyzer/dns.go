package analyzer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

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
