package analyzer

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/brightcolor/sender-report/internal/dnsfallback"
)

// Zustände des DKIM-Schlüssels, wie sie die Abfrage des Selector-Records ergibt.
const (
	dkimKeyAbsent      = "absent"      // der DNS-Server kennt den Namen nicht
	dkimKeyUnavailable = "unavailable" // keine Antwort (Zeitüberschreitung, Serverfehler)
	dkimKeyUsable      = "usable"      // Record vorhanden und als Schlüssel lesbar
	dkimKeyUnusable    = "unusable"    // Record vorhanden, aber fehlerhaft
)

// dkimKeyDiag beschreibt, was beim Abruf des Schlüssels zur DKIM-Signatur
// herauskam. Ohne diese Angaben meldet die Prüfung nur „Schlüssel nicht
// gefunden“, und der Absender weiß weder, welcher Selector gesucht wurde noch
// ob der Record fehlt oder fehlerhaft ist.
type dkimKeyDiag struct {
	Selector, Domain, DNSName string
	State                     string
	KeyInfo                   string   // z. B. „RSA, 2048 Bit“, wenn der Schlüssel brauchbar ist
	ProblemDE, ProblemEN      string   // gesetzt, wenn der Record vorhanden, aber fehlerhaft ist
	ExternalResolvers         []string // externe Resolver, die zusätzlich gefragt wurden (DNS_FALLBACK_RESOLVERS)
}

func (d dkimKeyDiag) known() bool { return d.State != "" && d.DNSName != "" }

// diagnoseDKIMKey liest Selector und Domain aus der DKIM-Signatur, ruft den
// Record ab und stellt fest, in welchem Zustand er ist.
func diagnoseDKIMKey(ctx context.Context, dkimSig string) dkimKeyDiag {
	selector := strings.TrimSpace(extractTagValue(dkimSig, "s"))
	domain := strings.ToLower(strings.TrimSpace(extractTagValue(dkimSig, "d")))
	if selector == "" || domain == "" {
		return dkimKeyDiag{}
	}
	d := dkimKeyDiag{Selector: selector, Domain: domain, DNSName: selector + "._domainkey." + domain, ExternalResolvers: dnsfallback.Hosts()}
	records, st := lookupTXT(ctx, d.DNSName)
	switch st {
	case dnsUnavailable:
		d.State = dkimKeyUnavailable
	case dnsAbsent:
		d.State = dkimKeyAbsent
	default:
		d.KeyInfo, d.ProblemDE, d.ProblemEN = inspectDKIMKeyRecords(records)
		if d.ProblemDE != "" {
			d.State = dkimKeyUnusable
		} else {
			d.State = dkimKeyUsable
		}
	}
	return d
}

// inspectDKIMKeyRecords prüft die TXT-Records eines Selectors nach RFC 6376
// §3.6.1 und RFC 8301. Bei einem brauchbaren Schlüssel kommt dessen Kurzbeschreibung
// zurück, sonst die Beschreibung des Problems in beiden Sprachen.
func inspectDKIMKeyRecords(records []string) (info, problemDE, problemEN string) {
	if len(records) > 1 {
		return "",
			fmt.Sprintf("unter dem Namen liegen %d TXT-Records, zulässig ist genau einer", len(records)),
			fmt.Sprintf("%d TXT records exist under that name, exactly one is allowed", len(records))
	}
	rec := strings.TrimSpace(strings.Join(records, ""))
	if v := extractTagValue(rec, "v"); v != "" && !strings.EqualFold(v, "DKIM1") {
		return "",
			fmt.Sprintf("das Tag v= hat den Wert %q, erwartet ist v=DKIM1", v),
			fmt.Sprintf("the v= tag is %q, v=DKIM1 is expected", v)
	}
	if !strings.Contains(";"+strings.ReplaceAll(rec, " ", ""), ";p=") {
		return "",
			"im Record fehlt das Tag p= mit dem öffentlichen Schlüssel (der Record gehört vermutlich zu etwas anderem, etwa einem Verifizierungstext)",
			"the record has no p= tag with the public key (it probably belongs to something else, such as a verification text)"
	}
	pub := strings.ReplaceAll(strings.TrimSpace(extractTagValue(rec, "p")), " ", "")
	if pub == "" {
		return "",
			"p= ist leer, der Schlüssel gilt damit als widerrufen",
			"p= is empty, which marks the key as revoked"
	}
	if s := strings.TrimSpace(extractTagValue(rec, "s")); s != "" && !dkimServiceAllowsEmail(s) {
		return "",
			fmt.Sprintf("das Tag s=%s erlaubt den Schlüssel nicht für E-Mail (zulässig sind * und email)", s),
			fmt.Sprintf("the s=%s tag does not allow the key for email (* and email are valid)", s)
	}
	keyType := strings.ToLower(emptyFallback(strings.TrimSpace(extractTagValue(rec, "k")), "rsa"))
	der, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(der) == 0 {
		return "",
			"der Wert von p= ist kein gültiges Base64, oft durch Zeilenumbrüche oder Anführungszeichen, die beim Eintragen im DNS-Panel mitkopiert wurden",
			"the p= value is not valid base64, often because line breaks or quotes were copied into the DNS panel"
	}
	if keyType == "ed25519" {
		return "Ed25519", "", ""
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "",
			"p= enthält keinen lesbaren öffentlichen Schlüssel",
			"p= does not contain a readable public key"
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Sprintf("k=%s passt nicht zum Schlüssel in p=", keyType), fmt.Sprintf("k=%s does not match the key in p=", keyType)
	}
	bits := rsaPub.N.BitLen()
	if bits < 1024 {
		return "",
			fmt.Sprintf("der RSA-Schlüssel hat nur %d Bit, mindestens 1024 sind nach RFC 8301 erforderlich", bits),
			fmt.Sprintf("the RSA key has only %d bits, RFC 8301 requires at least 1024", bits)
	}
	return fmt.Sprintf("RSA, %d Bit", bits), "", ""
}

func dkimServiceAllowsEmail(s string) bool {
	for _, part := range strings.Split(s, ":") {
		part = strings.TrimSpace(part)
		if part == "*" || strings.EqualFold(part, "email") {
			return true
		}
	}
	return false
}

// dkimMissingKeyFinding formuliert den Befund „Schlüssel nicht gefunden“. Mit den
// Angaben aus der Diagnose nennt er Selector, Domain und den abgefragten
// DNS-Namen, sagt, ob der Record fehlt oder fehlerhaft ist, und was zu tun ist.
func dkimMissingKeyFinding(detail string, diag dkimKeyDiag) dkimFinding {
	f := dkimFinding{
		status: "fail", delta: -1.2, specific: true,
		summaryDE: "Der öffentliche DKIM-Schlüssel konnte nicht gefunden oder gelesen werden (Selector-DNS-Record fehlt, ist leer oder fehlerhaft).",
		summaryEN: "The DKIM public key could not be found or read (selector DNS record missing, empty or malformed).",
		suggestDE: "TXT-Record <selector>._domainkey.<domain> prüfen: v=DKIM1; k=rsa; p=<base64-Key>.",
		suggestEN: "Check the TXT record <selector>._domainkey.<domain>: v=DKIM1; k=rsa; p=<base64-key>.",
	}
	if !diag.known() {
		return f
	}
	n := diag.DNSName
	head := fmt.Sprintf("Die Mail ist mit Selector „%s“ für die Domain %s signiert. Der Prüfer suchte den Schlüssel im TXT-Record %s und fand ihn nicht.", diag.Selector, diag.Domain, n)
	headEN := fmt.Sprintf("The mail is signed with selector “%s” for the domain %s. The verifier looked for the key in the TXT record %s and did not find it.", diag.Selector, diag.Domain, n)
	check := fmt.Sprintf("Kontrolle: dig +short TXT %s", n)
	checkEN := fmt.Sprintf("Check: dig +short TXT %s", n)

	switch diag.State {
	case dkimKeyAbsent:
		f.summaryDE = head + " Unter diesem Namen gibt es im DNS keinen TXT-Record."
		f.summaryEN = headEN + " The DNS has no TXT record under that name."
		if len(diag.ExternalResolvers) > 0 {
			list := strings.Join(diag.ExternalResolvers, ", ")
			f.summaryDE += " Auch die externen Resolver " + list + " kennen den Namen nicht."
			f.summaryEN += " The external resolvers " + list + " do not know the name either."
		}
		f.suggestDE = fmt.Sprintf("TXT-Record %s anlegen mit dem Wert v=DKIM1; k=rsa; p=<öffentlicher Schlüssel>. Den Schlüssel erzeugt die Software, die signiert (etwa OpenDKIM, Rspamd oder der Mailanbieter). Der Selector im Namen muss genau dem s= der Signatur entsprechen: %s. Existiert der Record schon unter einem anderen Selector, den Signer auf diesen umstellen. %s", n, diag.Selector, check)
		f.suggestEN = fmt.Sprintf("Create the TXT record %s with the value v=DKIM1; k=rsa; p=<public key>. The software that signs (for example OpenDKIM, Rspamd or the mail provider) generates the key. The selector in the name has to match the s= of the signature exactly: %s. If the record already exists under another selector, switch the signer to that one. %s", n, diag.Selector, checkEN)
	case dkimKeyUnavailable:
		f.status, f.delta = "warn", -0.6
		f.summaryDE = head + " Die DNS-Abfrage wurde nicht beantwortet (Zeitüberschreitung oder Serverfehler). Ob der Record fehlt, ist damit offen."
		f.summaryEN = headEN + " The DNS query got no answer (timeout or server error), so it is unknown whether the record is missing."
		f.suggestDE = fmt.Sprintf("Testmail erneut senden. Antwortet das DNS wieder nicht, die Nameserver der Domain %s prüfen (dig NS %s). %s", diag.Domain, diag.Domain, check)
		f.suggestEN = fmt.Sprintf("Send the test mail again. If the DNS stays silent, check the name servers of %s (dig NS %s). %s", diag.Domain, diag.Domain, checkEN)
	case dkimKeyUnusable:
		f.summaryDE = head + " Der Record ist vorhanden, aber unbrauchbar: " + diag.ProblemDE + "."
		f.summaryEN = headEN + " The record exists but is unusable: " + diag.ProblemEN + "."
		f.suggestDE = fmt.Sprintf("Den TXT-Record %s korrigieren: %s. Gültige Form: v=DKIM1; k=rsa; p=<Base64 ohne Zeilenumbrüche>. %s", n, diag.ProblemDE, check)
		f.suggestEN = fmt.Sprintf("Fix the TXT record %s: %s. Valid form: v=DKIM1; k=rsa; p=<base64 without line breaks>. %s", n, diag.ProblemEN, checkEN)
	case dkimKeyUsable:
		f.status, f.delta = "warn", -0.6
		f.summaryDE = head + fmt.Sprintf(" Beim Prüfen der Mail meldete der DNS-Resolver des Servers, der Name existiere nicht. Inzwischen ist der Record abrufbar und enthält einen gültigen Schlüssel (%s). Das passiert bei einem frisch angelegten Record, dessen Negativ-Antwort noch im Cache stand, oder bei einem unzuverlässigen Resolver.", diag.KeyInfo)
		f.summaryEN = headEN + fmt.Sprintf(" When the mail was verified, the server's DNS resolver reported that the name does not exist. The record can be fetched now and holds a valid key (%s). This happens with a freshly created record whose negative answer was still cached, or with an unreliable resolver.", diag.KeyInfo)
		f.suggestDE = fmt.Sprintf("Testmail erneut senden. Besteht DKIM danach, lag es am Zwischenspeicher. Bleibt es beim Fehler, den Resolver des Servers prüfen: dig +short TXT %s @<Resolver des Servers>.", n)
		f.suggestEN = fmt.Sprintf("Send the test mail again. If DKIM passes, a cache was the cause. If it keeps failing, check the server's resolver: dig +short TXT %s @<server resolver>.", n)
	}
	if d := strings.TrimSpace(detail); d != "" && d != "none" {
		f.summaryDE += fmt.Sprintf(" Meldung des Prüfers: %s", d)
		f.summaryEN += fmt.Sprintf(" Verifier message: %s", d)
	}
	return f
}

// dkimDetailIsKeyProblem erkennt Meldungen des Prüfers, die den Schlüssel im
// DNS betreffen (der Text stammt kleingeschrieben aus classifyDKIMFailure).
func dkimDetailIsKeyProblem(d string) bool {
	d = strings.ToLower(d)
	for _, marker := range []string{"no key for signature", "no valid key", "key syntax", "key revoked"} {
		if strings.Contains(d, marker) {
			return true
		}
	}
	return false
}
