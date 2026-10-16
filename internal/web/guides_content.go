package web

// Inhalt der Ratgeber unter /de/guides und /en/guides. Jeder Ratgeber erklärt ein
// Thema, das Menschen vor der Frage „Warum landet meine Mail im Spam?“ suchen,
// und führt zum Test. Die Texte stehen hier, damit sie ohne Eingriff in den
// Code der Seiten gepflegt werden können. Updated ist das Datum der letzten
// inhaltlichen Änderung (JJJJ-MM-TT) und erscheint in Seite und Sitemap.

var guideList = []guide{
	{
		Slug: "deliverability", Updated: "2026-10-16", Icon: "bi-send-check",
		Related: []string{"spf", "dkim", "dmarc", "reverse-dns", "blacklist", "spam-score"},
		DE: guideText{
			Title:       "E-Mail-Zustellbarkeit verbessern: Checkliste für SPF, DKIM, DMARC & Spam-Score",
			Description: "Warum Mails im Spam landen und wie du es behebst: Checkliste zu SPF, DKIM, DMARC, Reverse-DNS, Blacklists, Spam-Score und Inhalt. Mit kostenlosem Test.",
			H1:          "E-Mail-Zustellbarkeit verbessern",
			Lead:        "Ob eine Mail im Posteingang oder im Spam-Ordner landet, entscheiden Empfänger-Server anhand von drei Gruppen: Authentifizierung, Infrastruktur und Inhalt. Diese Checkliste geht sie der Reihe nach durch.",
			Sections: []guideSection{
				{Heading: "1. Authentifizierung: SPF, DKIM und DMARC", Paragraphs: []string{
					"Die drei Verfahren beweisen, dass eine Mail von deiner Domain stammt und unterwegs unverändert blieb. Gmail, Yahoo und Outlook erwarten sie von jedem, der größere Mengen versendet.",
				}, Items: []string{
					"SPF legt fest, welche Server für deine Domain senden dürfen.",
					"DKIM versieht jede Mail mit einer kryptografischen Signatur.",
					"DMARC sagt dem Empfänger, was bei fehlgeschlagener Prüfung geschehen soll, und liefert dir Berichte.",
				}},
				{Heading: "2. Infrastruktur: Reverse-DNS, HELO, TLS und IP-Ruf", Paragraphs: []string{
					"Der sendende Server braucht einen passenden PTR-Record, einen HELO-Namen, der zur IP gehört, und eine verschlüsselte Verbindung per STARTTLS. Steht die IP auf einer Blacklist, helfen die besten Inhalte wenig.",
				}},
				{Heading: "3. Inhalt und Format", Paragraphs: []string{
					"Spamfilter bewerten Aufbau und Text. Hilfreich sind ein sauberer Plaintext-Teil neben dem HTML, ein aussagekräftiger Betreff, ein ausgewogenes Verhältnis von Text und Bildern, ausgeschriebene Links statt Kurz-URLs und bei Newslettern ein List-Unsubscribe-Header mit One-Click-Abmeldung.",
				}},
				{Heading: "So gehst du vor", Items: []string{
					"Sende eine Testmail an die Adresse, die sender.report dir anzeigt.",
					"Öffne den Bericht und arbeite die Befunde nach Wichtigkeit ab: erst Fehler, dann Warnungen.",
					"Hast du im DNS etwas geändert, klicke im Bericht auf „DNS neu abfragen & neu bewerten“. Die Testmail muss dafür nicht erneut gesendet werden.",
					"Wiederhole den Test, bis keine Fehler übrig sind und der Wert im grünen Bereich liegt.",
				}},
			},
			FAQ: []guideFAQ{
				{"Was ist ein guter Zustellbarkeits-Wert?", "Bei sender.report gelten Werte ab 9 von 10 als ausgezeichnet und ab 7,5 als gut. Wichtiger als die Zahl sind die Befunde: SPF, DKIM, DMARC und Reverse-DNS sollten bestehen."},
				{"Warum landet meine Mail im Spam, obwohl SPF und DKIM bestehen?", "Häufige Gründe sind eine schlechte IP-Reputation, Blacklist-Einträge, ein auffälliger Inhalt oder fehlende Alignment-Übereinstimmung zwischen From-Adresse und der signierenden Domain."},
				{"Muss ich für den Test ein Konto anlegen?", "Nein, der Test arbeitet mit einer temporären Mailbox. Die Berichte sind Ende-zu-Ende-verschlüsselt."},
			},
		},
		EN: guideText{
			Title:       "Improve email deliverability: a checklist for SPF, DKIM, DMARC and spam score",
			Description: "Why mail lands in spam and how to fix it: a checklist covering SPF, DKIM, DMARC, reverse DNS, blacklists, spam score and content. With a free test.",
			H1:          "Improve email deliverability",
			Lead:        "Receiving servers decide between inbox and spam folder based on three groups of signals: authentication, infrastructure and content. This checklist walks through them in order.",
			Sections: []guideSection{
				{Heading: "1. Authentication: SPF, DKIM and DMARC", Paragraphs: []string{
					"The three standards prove that a message comes from your domain and arrived unchanged. Gmail, Yahoo and Outlook expect them from anyone who sends larger volumes.",
				}, Items: []string{
					"SPF lists the servers that may send for your domain.",
					"DKIM adds a cryptographic signature to every message.",
					"DMARC tells receivers what to do when a check fails and sends you reports.",
				}},
				{Heading: "2. Infrastructure: reverse DNS, HELO, TLS and IP reputation", Paragraphs: []string{
					"The sending server needs a matching PTR record, a HELO name that belongs to its IP and an encrypted connection through STARTTLS. If the IP sits on a blacklist, even the best content helps little.",
				}},
				{Heading: "3. Content and format", Paragraphs: []string{
					"Spam filters score structure and text. A clean plain-text part next to the HTML, a meaningful subject, a balanced ratio of text to images, spelled-out links instead of short URLs and, for newsletters, a List-Unsubscribe header with one-click unsubscribe all help.",
				}},
				{Heading: "How to proceed", Items: []string{
					"Send a test message to the address sender.report shows you.",
					"Open the report and work through the findings by importance: errors first, then warnings.",
					"After you change something in DNS, click “Re-query DNS & re-score” in the report. You do not need to send the test mail again.",
					"Repeat the test until no errors remain and the score is in the green range.",
				}},
			},
			FAQ: []guideFAQ{
				{"What is a good deliverability score?", "On sender.report a score of 9 out of 10 or higher is excellent and 7.5 or higher is good. The findings matter more than the number: SPF, DKIM, DMARC and reverse DNS should pass."},
				{"Why does my mail land in spam although SPF and DKIM pass?", "Common reasons are a poor IP reputation, blacklist entries, conspicuous content or missing alignment between the From address and the signing domain."},
				{"Do I need an account for the test?", "No. The test uses a temporary mailbox, and reports are end-to-end encrypted."},
			},
		},
	},
	{
		Slug: "spf", Updated: "2026-10-16", Icon: "bi-shield-check",
		Related: []string{"dkim", "dmarc", "deliverability"},
		DE: guideText{
			Title:       "SPF prüfen und einrichten: Syntax, 10-Lookup-Limit und häufige Fehler",
			Description: "SPF-Record erklärt: Aufbau, ~all oder -all, das Limit von 10 DNS-Abfragen und die häufigsten Fehler. Mit Beispiel und kostenlosem SPF-Test.",
			H1:          "SPF prüfen und einrichten",
			Lead:        "SPF (Sender Policy Framework) ist eine Liste in deinem DNS, die festhält, welche Server E-Mails für deine Domain verschicken dürfen. Der Empfänger vergleicht die IP des einliefernden Servers mit dieser Liste.",
			Sections: []guideSection{
				{Heading: "So sieht ein SPF-Record aus", Paragraphs: []string{
					"Ein SPF-Record ist ein TXT-Eintrag auf der Domain, der mit v=spf1 beginnt. Danach folgen die erlaubten Absender und am Ende eine Regel für alle anderen.",
				}, Code: "example.org.  IN TXT  \"v=spf1 mx include:_spf.google.com ip4:203.0.113.25 -all\""},
				{Heading: "Die wichtigsten Bausteine", Items: []string{
					"mx: die Server aus den MX-Records der Domain.",
					"a: die IP-Adresse der Domain selbst.",
					"ip4: und ip6: einzelne Adressen oder Netze.",
					"include: die SPF-Liste eines Dienstes, etwa deines Mailanbieters oder Newsletter-Tools.",
					"-all lehnt alle anderen ab, ~all markiert sie als verdächtig (Softfail).",
				}},
				{Heading: "Häufige Fehler", Items: []string{
					"Zwei SPF-Records auf derselben Domain. Es darf genau einer existieren, sonst ist das Ergebnis ein Fehler.",
					"Mehr als 10 DNS-Abfragen. include, a, mx, ptr, exists und redirect zählen mit; wer das Limit überschreitet, erhält einen permanenten Fehler.",
					"Ein Versanddienst fehlt in der Liste, etwa das Newsletter-Tool oder der Kontaktformular-Server.",
					"+all am Ende erlaubt jedem Server den Versand und entwertet den Record.",
				}},
				{Heading: "~all oder -all?", Paragraphs: []string{
					"Starte mit ~all, solange du nicht sicher bist, dass alle Absender in der Liste stehen. Sobald DMARC-Berichte keine unbekannten Quellen mehr zeigen, stelle auf -all um.",
				}},
				{Heading: "Was SPF nicht leistet", Paragraphs: []string{
					"SPF prüft die Envelope-Adresse (Return-Path) und überlebt keine Weiterleitung. Für DMARC muss diese Adresse zur sichtbaren From-Domain passen (Alignment). DKIM ergänzt SPF an genau diesen Stellen.",
				}},
			},
			FAQ: []guideFAQ{
				{"Wie viele SPF-Records darf eine Domain haben?", "Genau einen. Mehrere Records führen zu einem permanenten Fehler."},
				{"Was bedeutet das Limit von 10 DNS-Abfragen?", "Ein Empfänger darf bei der Auswertung höchstens zehn DNS-Abfragen auslösen (RFC 7208). Verschachtelte include-Einträge zählen mit. Bei Überschreitung gilt der Record als ungültig."},
				{"Prüft sender.report SPF wirklich?", "Ja. sender.report wertet den Record gegen die tatsächliche IP deiner Testmail aus, statt nur das Vorhandensein zu prüfen."},
			},
		},
		EN: guideText{
			Title:       "Check and set up SPF: syntax, the 10-lookup limit and common mistakes",
			Description: "The SPF record explained: structure, ~all versus -all, the limit of 10 DNS lookups and the most common mistakes. With an example and a free SPF test.",
			H1:          "Check and set up SPF",
			Lead:        "SPF (Sender Policy Framework) is a list in your DNS that states which servers may send email for your domain. The receiver compares the IP of the delivering server with that list.",
			Sections: []guideSection{
				{Heading: "What an SPF record looks like", Paragraphs: []string{
					"An SPF record is a TXT entry on the domain that starts with v=spf1. It lists the permitted senders and ends with a rule for everyone else.",
				}, Code: "example.org.  IN TXT  \"v=spf1 mx include:_spf.google.com ip4:203.0.113.25 -all\""},
				{Heading: "The main building blocks", Items: []string{
					"mx: the servers in the domain's MX records.",
					"a: the IP address of the domain itself.",
					"ip4: and ip6: single addresses or networks.",
					"include: the SPF list of a service such as your mail provider or newsletter tool.",
					"-all rejects everyone else, ~all marks them as suspicious (softfail).",
				}},
				{Heading: "Common mistakes", Items: []string{
					"Two SPF records on the same domain. Exactly one may exist, otherwise the result is an error.",
					"More than 10 DNS lookups. include, a, mx, ptr, exists and redirect all count; exceeding the limit produces a permanent error.",
					"A sending service is missing from the list, such as the newsletter tool or the contact-form server.",
					"+all at the end allows every server to send and makes the record worthless.",
				}},
				{Heading: "~all or -all?", Paragraphs: []string{
					"Start with ~all while you are unsure that every sender is on the list. Once DMARC reports show no unknown sources, switch to -all.",
				}},
				{Heading: "What SPF cannot do", Paragraphs: []string{
					"SPF checks the envelope address (Return-Path) and breaks on forwarding. For DMARC, that address has to match the visible From domain (alignment). DKIM covers exactly those gaps.",
				}},
			},
			FAQ: []guideFAQ{
				{"How many SPF records may a domain have?", "Exactly one. Several records cause a permanent error."},
				{"What does the limit of 10 DNS lookups mean?", "A receiver may trigger at most ten DNS lookups while evaluating the record (RFC 7208). Nested include entries count. Above the limit the record is invalid."},
				{"Does sender.report really check SPF?", "Yes. sender.report evaluates the record against the actual IP of your test mail instead of only checking that a record exists."},
			},
		},
	},
	{
		Slug: "dkim", Updated: "2026-10-16", Icon: "bi-key",
		Related: []string{"spf", "dmarc", "deliverability"},
		DE: guideText{
			Title:       "DKIM prüfen und einrichten: Selector, Schlüssellänge und typische Fehler",
			Description: "DKIM erklärt: Selector, DNS-Record, 2048-Bit-Schlüssel und die häufigsten Fehler wie fehlender Schlüssel oder veränderter Inhalt. Mit kostenlosem DKIM-Test.",
			H1:          "DKIM prüfen und einrichten",
			Lead:        "DKIM (DomainKeys Identified Mail) versieht jede Mail mit einer Signatur. Den passenden öffentlichen Schlüssel hinterlegst du im DNS, und der Empfänger prüft damit, dass die Mail von deiner Domain stammt und unterwegs unverändert blieb.",
			Sections: []guideSection{
				{Heading: "Wie DKIM funktioniert", Paragraphs: []string{
					"Dein Mailserver signiert ausgehende Mails mit einem privaten Schlüssel und schreibt die Signatur in den Header DKIM-Signature. Darin stehen die Domain (d=) und der Selector (s=). Aus beiden ergibt sich der Name des DNS-Eintrags, in dem der öffentliche Schlüssel liegt.",
				}, Code: "dkim._domainkey.example.org.  IN TXT  \"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A…\""},
				{Heading: "Empfehlungen", Items: []string{
					"RSA-Schlüssel mit 2048 Bit verwenden. 1024 Bit gelten noch als gültig, Gmail und andere empfehlen 2048.",
					"Mit rsa-sha256 signieren. rsa-sha1 ist laut RFC 8301 veraltet.",
					"Die Signatur-Domain (d=) sollte zur sichtbaren From-Domain passen, damit DKIM für DMARC zählt.",
					"Schlüssel gelegentlich wechseln und dafür einen neuen Selector anlegen.",
				}},
				{Heading: "Häufige Fehler", Items: []string{
					"Der Schlüssel fehlt im DNS oder liegt unter einem anderen Selector, als die Signatur nennt.",
					"Der Record enthält mehrere TXT-Einträge, ein leeres p= (widerrufener Schlüssel) oder Zeilenumbrüche und Anführungszeichen, die beim Einfügen im DNS-Panel mitkopiert wurden.",
					"Der Inhalt wurde nach dem Signieren verändert, etwa durch einen Footer, einen Disclaimer oder eine Mailingliste. Dann stimmt der Body-Hash nicht mehr.",
					"Das Tag l= (Body-Length) lässt zu, dass Inhalt angehängt wird, und wird von strengen Prüfern abgelehnt.",
				}},
				{Heading: "So prüfst du es", Paragraphs: []string{
					"Sende eine Testmail an sender.report. Der Bericht nennt Selector, Domain und den abgefragten DNS-Namen und sagt, ob der Record fehlt, fehlerhaft ist oder der DNS-Server nicht geantwortet hat. Nach einer Änderung im DNS fragst du mit einem Klick alles neu ab.",
				}},
			},
			FAQ: []guideFAQ{
				{"Was ist ein DKIM-Selector?", "Der Selector ist ein frei gewählter Name, der den Schlüssel unter deiner Domain eindeutig macht. Er ermöglicht mehrere Schlüssel parallel, etwa beim Wechsel."},
				{"Wo trage ich den DKIM-Schlüssel ein?", "Als TXT-Record unter selector._domainkey.deine-domain.de. Der Wert beginnt mit v=DKIM1 und enthält den öffentlichen Schlüssel im Feld p=."},
				{"Warum meldet der Test, der Schlüssel sei nicht gefunden, obwohl der Record existiert?", "Ein zwischengespeicherter Negativ-Eintrag im DNS kann eine frische Änderung verdecken. sender.report fragt deshalb zusätzlich externe Resolver ab und erlaubt eine Neuabfrage per Klick."},
			},
		},
		EN: guideText{
			Title:       "Check and set up DKIM: selector, key length and typical mistakes",
			Description: "DKIM explained: selector, DNS record, 2048-bit keys and the most common mistakes such as a missing key or modified content. With a free DKIM test.",
			H1:          "Check and set up DKIM",
			Lead:        "DKIM (DomainKeys Identified Mail) adds a signature to every message. You publish the matching public key in DNS, and the receiver uses it to verify that the message came from your domain and arrived unchanged.",
			Sections: []guideSection{
				{Heading: "How DKIM works", Paragraphs: []string{
					"Your mail server signs outgoing mail with a private key and writes the signature into the DKIM-Signature header. It names the domain (d=) and the selector (s=). Together they give the name of the DNS entry that holds the public key.",
				}, Code: "dkim._domainkey.example.org.  IN TXT  \"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A…\""},
				{Heading: "Recommendations", Items: []string{
					"Use RSA keys with 2048 bits. 1024 bits are still valid, Gmail and others recommend 2048.",
					"Sign with rsa-sha256. rsa-sha1 is deprecated by RFC 8301.",
					"The signing domain (d=) should match the visible From domain so DKIM counts for DMARC.",
					"Rotate keys now and then and publish a new selector for it.",
				}},
				{Heading: "Common mistakes", Items: []string{
					"The key is missing in DNS or sits under another selector than the signature names.",
					"The record holds several TXT entries, an empty p= (a revoked key), or line breaks and quotes that were copied along when pasting into the DNS panel.",
					"The content changed after signing, for example through a footer, a disclaimer or a mailing list. The body hash no longer matches.",
					"The l= tag (body length) allows content to be appended and strict verifiers reject it.",
				}},
				{Heading: "How to check it", Paragraphs: []string{
					"Send a test mail to sender.report. The report names the selector, the domain and the DNS name it queried, and says whether the record is missing, malformed or the DNS server did not answer. After a DNS change you query everything again with one click.",
				}},
			},
			FAQ: []guideFAQ{
				{"What is a DKIM selector?", "The selector is a freely chosen name that makes the key unique under your domain. It allows several keys in parallel, for example during a rotation."},
				{"Where do I publish the DKIM key?", "As a TXT record at selector._domainkey.your-domain.com. The value starts with v=DKIM1 and carries the public key in the p= field."},
				{"Why does the test say the key was not found although the record exists?", "A cached negative answer in DNS can hide a fresh change. sender.report therefore also asks external resolvers and lets you query again with one click."},
			},
		},
	},
	{
		Slug: "dmarc", Updated: "2026-10-16", Icon: "bi-patch-check",
		Related: []string{"spf", "dkim", "deliverability"},
		DE: guideText{
			Title:       "DMARC prüfen und einrichten: Policy none, quarantine, reject und Berichte",
			Description: "DMARC erklärt: Record, Policy none, quarantine und reject, Alignment, Subdomain-Policy sp= und der sichere Weg zu p=reject. Mit kostenlosem DMARC-Test.",
			H1:          "DMARC prüfen und einrichten",
			Lead:        "DMARC sagt dem Empfänger, was mit Mails geschehen soll, die vorgeben von deiner Domain zu stammen, aber SPF und DKIM nicht bestehen. Zusätzlich schickt es dir Berichte, wer in deinem Namen sendet.",
			Sections: []guideSection{
				{Heading: "Der DMARC-Record", Paragraphs: []string{
					"DMARC liegt als TXT-Record unter _dmarc.deine-domain. Ein erster Eintrag zum Beobachten sieht so aus:",
				}, Code: "_dmarc.example.org.  IN TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@example.org\""},
				{Heading: "Die Policy p=", Items: []string{
					"p=none beobachtet nur und schützt noch nicht.",
					"p=quarantine verschiebt durchgefallene Mails in den Spam-Ordner.",
					"p=reject lehnt sie ab und bietet den stärksten Schutz vor Fälschungen deiner Domain.",
				}},
				{Heading: "Alignment", Paragraphs: []string{
					"DMARC besteht, wenn SPF oder DKIM besteht und die geprüfte Domain zur sichtbaren From-Domain passt. Mit aspf und adkim wählst du zwischen relaxed (Subdomains erlaubt) und strict (exakte Übereinstimmung).",
				}},
				{Heading: "Subdomains und pct", Paragraphs: []string{
					"Mit sp= legst du eine eigene Policy für Subdomains fest. Steht dort none, sind alle Subdomains ungeschützt, obwohl die Hauptdomain geschützt ist. Mit pct= wendest du die Policy nur auf einen Teil der Mails an. Für vollen Schutz bleibt pct unter 100 nicht dauerhaft stehen.",
				}},
				{Heading: "Der sichere Weg zu p=reject", Items: []string{
					"Mit p=none und einer rua-Adresse starten und die Berichte lesen.",
					"Alle legitimen Absender in SPF und DKIM aufnehmen, bis die Berichte keine unbekannten Quellen zeigen.",
					"Auf p=quarantine wechseln, danach auf p=reject.",
				}},
			},
			FAQ: []guideFAQ{
				{"Brauche ich DMARC wirklich?", "Gmail und Yahoo verlangen seit 2024 von Massenversendern SPF, DKIM und einen DMARC-Record. Auch für kleine Versender senkt ein DMARC-Record das Risiko, dass Dritte deine Domain fälschen."},
				{"Was bedeutet rua?", "rua ist die Adresse, an die Empfänger tägliche Zusammenfassungen senden. Sie zeigen, welche Server mit deiner Domain Mails versenden und ob SPF und DKIM bestehen."},
				{"Warum ist sp=none ein Risiko?", "Die Policy der Hauptdomain gilt dann nicht für Subdomains. Angreifer nutzen genau solche Lücken für Fälschungen."},
			},
		},
		EN: guideText{
			Title:       "Check and set up DMARC: policy none, quarantine, reject and reports",
			Description: "DMARC explained: the record, policy none, quarantine and reject, alignment, the subdomain policy sp= and the safe path to p=reject. With a free DMARC test.",
			H1:          "Check and set up DMARC",
			Lead:        "DMARC tells a receiver what to do with mail that claims to come from your domain but fails SPF and DKIM. It also sends you reports on who sends in your name.",
			Sections: []guideSection{
				{Heading: "The DMARC record", Paragraphs: []string{
					"DMARC lives in a TXT record at _dmarc.your-domain. A first entry for observing looks like this:",
				}, Code: "_dmarc.example.org.  IN TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@example.org\""},
				{Heading: "The p= policy", Items: []string{
					"p=none only observes and does not protect yet.",
					"p=quarantine moves failing mail into the spam folder.",
					"p=reject rejects it and gives the strongest protection against forgeries of your domain.",
				}},
				{Heading: "Alignment", Paragraphs: []string{
					"DMARC passes when SPF or DKIM passes and the checked domain matches the visible From domain. With aspf and adkim you choose between relaxed (subdomains allowed) and strict (exact match).",
				}},
				{Heading: "Subdomains and pct", Paragraphs: []string{
					"With sp= you set a separate policy for subdomains. If it says none, all subdomains are unprotected although the main domain is protected. With pct= you apply the policy to only a share of the mail. For full protection, do not leave pct below 100 permanently.",
				}},
				{Heading: "The safe path to p=reject", Items: []string{
					"Start with p=none and a rua address and read the reports.",
					"Add every legitimate sender to SPF and DKIM until the reports show no unknown sources.",
					"Switch to p=quarantine, then to p=reject.",
				}},
			},
			FAQ: []guideFAQ{
				{"Do I really need DMARC?", "Since 2024 Gmail and Yahoo require SPF, DKIM and a DMARC record from bulk senders. For small senders a DMARC record also lowers the risk that third parties forge your domain."},
				{"What does rua mean?", "rua is the address to which receivers send daily summaries. They show which servers send mail with your domain and whether SPF and DKIM pass."},
				{"Why is sp=none a risk?", "The policy of the main domain then does not apply to subdomains. Attackers use exactly such gaps for forgeries."},
			},
		},
	},
	{
		Slug: "spam-score", Updated: "2026-10-16", Icon: "bi-speedometer2",
		Related: []string{"deliverability", "blacklist", "dkim"},
		DE: guideText{
			Title:       "Spam-Score testen: SpamAssassin und Rspamd verstehen und senken",
			Description: "So liest du den Spam-Score von SpamAssassin und Rspamd: Schwellwerte, typische Regeln und wie du die Punkte senkst. Mit kostenlosem Spam-Test.",
			H1:          "Spam-Score testen und senken",
			Lead:        "Spamfilter zählen Punkte. Jede auffällige Eigenschaft einer Mail gibt Pluspunkte, jede vertrauenswürdige Eigenschaft Minuspunkte. Ab einer Schwelle gilt die Mail als Spam.",
			Sections: []guideSection{
				{Heading: "Wie die Schwellen aussehen", Paragraphs: []string{
					"SpamAssassin markiert Mails standardmäßig ab 5,0 Punkten als Spam. Rspamd arbeitet mit Aktionen: je nach Punktzahl wird eine Mail verzögert, markiert, im Betreff verändert oder abgelehnt, die Ablehnung liegt in der Vorgabe bei 15 Punkten. Jeder Empfänger setzt eigene Schwellen, und große Anbieter ergänzen eigene Verfahren. Ein Wert knapp unter der Schwelle ist deshalb bei manchen Empfängern schon Spam.",
				}},
				{Heading: "Typische Auslöser", Items: []string{
					"Fehlende oder auffällige Header wie Date, Message-ID, Subject oder From.",
					"Fehlgeschlagene oder fehlende Authentifizierung (SPF, DKIM, DMARC).",
					"Nur-HTML-Mails ohne Plaintext-Teil und Bilder ohne begleitenden Text.",
					"Verkürzte Links, Links auf Domains, die auf Blocklisten stehen, und Betreffzeilen in Großbuchstaben.",
					"Eine sendende IP auf einer Blacklist oder mit generischem Reverse-DNS.",
				}},
				{Heading: "Punkte senken", Items: []string{
					"Zuerst die Regeln mit dem größten Gewicht beheben. sender.report listet sie nach Punkten sortiert mit Beschreibung auf.",
					"Authentifizierung vervollständigen und Reverse-DNS prüfen.",
					"Text und HTML sauber trennen, ausgeschriebene Links verwenden und einen klaren Betreff wählen.",
				}},
			},
			FAQ: []guideFAQ{
				{"Welcher Spam-Score ist gut?", "Je niedriger, desto besser. Werte unter null sind gut, ein Wert nahe der Schwelle von 5,0 bei SpamAssassin ist riskant."},
				{"Warum zeigt sender.report zwei Spamfilter?", "SpamAssassin und Rspamd bewerten nach unterschiedlichen Regeln. Zusammen ergeben sie ein breiteres Bild als ein einzelner Filter."},
				{"Kann ich Texte testen, ohne jedes Mal eine Mail zu senden?", "Ja, der Mail-Simulator bewertet bearbeiteten Quelltext direkt."},
			},
		},
		EN: guideText{
			Title:       "Test your spam score: understand and lower SpamAssassin and Rspamd results",
			Description: "How to read the spam score of SpamAssassin and Rspamd: thresholds, typical rules and how to lower the points. With a free spam test.",
			H1:          "Test and lower your spam score",
			Lead:        "Spam filters count points. Every conspicuous property of a message adds points, every trustworthy property removes some. Above a threshold the message counts as spam.",
			Sections: []guideSection{
				{Heading: "What the thresholds look like", Paragraphs: []string{
					"SpamAssassin marks mail as spam from 5.0 points by default. Rspamd works with actions: depending on the score a message is delayed, marked, gets a rewritten subject or is rejected, and rejection defaults to 15 points. Every receiver sets its own thresholds and large providers add their own methods. A score just below the threshold can therefore already be spam for some recipients.",
				}},
				{Heading: "Typical triggers", Items: []string{
					"Missing or conspicuous headers such as Date, Message-ID, Subject or From.",
					"Failed or missing authentication (SPF, DKIM, DMARC).",
					"HTML-only mail without a plain-text part and images without accompanying text.",
					"Shortened links, links to domains on blocklists and subject lines in capital letters.",
					"A sending IP on a blacklist or with generic reverse DNS.",
				}},
				{Heading: "Lowering the points", Items: []string{
					"Fix the rules with the greatest weight first. sender.report lists them by points with a description.",
					"Complete authentication and check reverse DNS.",
					"Separate text and HTML cleanly, use spelled-out links and choose a clear subject.",
				}},
			},
			FAQ: []guideFAQ{
				{"Which spam score is good?", "The lower the better. Scores below zero are good, a score close to the SpamAssassin threshold of 5.0 is risky."},
				{"Why does sender.report show two spam filters?", "SpamAssassin and Rspamd score by different rules. Together they give a broader picture than a single filter."},
				{"Can I test text without sending a mail every time?", "Yes, the mail simulator scores edited source directly."},
			},
		},
	},
	{
		Slug: "blacklist", Updated: "2026-10-16", Icon: "bi-slash-circle",
		Related: []string{"reverse-dns", "spam-score", "deliverability"},
		DE: guideText{
			Title:       "Blacklist-Check: Ist meine Mailserver-IP gelistet? Ursachen und Delisting",
			Description: "Blacklist (DNSBL) prüfen: Spamhaus, SpamCop, Barracuda und andere, Ursachen für Einträge und Schritte zum Delisting. Mit kostenlosem Test der Absender-IP.",
			H1:          "Blacklist-Check für deine Mailserver-IP",
			Lead:        "Blacklists (DNSBL) sammeln IP-Adressen, von denen Spam oder Schadcode ausging. Steht deine sendende IP auf einer verbreiteten Liste, lehnen viele Server deine Mails ab oder sortieren sie in den Spam-Ordner.",
			Sections: []guideSection{
				{Heading: "Wie die Abfrage funktioniert", Paragraphs: []string{
					"Eine DNSBL ist eine DNS-Zone. Der Empfänger dreht die IP um, hängt den Namen der Liste an und fragt den DNS-Server. Eine Antwort im Bereich 127.0.0.x bedeutet: gelistet.",
				}, Code: "203.0.113.25  ->  25.113.0.203.zen.spamhaus.org"},
				{Heading: "Die wichtigsten Listen", Items: []string{
					"Spamhaus ZEN fasst SBL, XBL und PBL zusammen. SBL und XBL stehen für Spam-Quellen und kompromittierte Rechner, PBL für Adressbereiche, die keine Mailserver betreiben sollen.",
					"SpamCop (bl.spamcop.net) listet nach Nutzerbeschwerden.",
					"Barracuda (b.barracudacentral.org) und weitere Listen fließen in viele Filter ein.",
				}},
				{Heading: "Warum eine IP gelistet wird", Items: []string{
					"Ein kompromittiertes Postfach oder ein gehackter Server versendet Spam.",
					"Ein offenes Relay oder ein unsicheres Kontaktformular wird missbraucht.",
					"Die IP gehört zu einem Bereich für Privatkunden (dynamisch) oder hat einen schlechten Nachbarn auf einem geteilten Server.",
				}},
				{Heading: "Delisting", Items: []string{
					"Ursache finden und abstellen: Konten sperren, Passwörter ändern, Lücken schließen.",
					"Danach auf der Seite der Liste einen Antrag auf Entfernung stellen. Manche Listen entfernen Einträge nach einer Wartezeit selbst.",
					"Bei PBL-Einträgen über einen Relay des Providers senden oder die Freigabe beim Provider beantragen.",
				}},
			},
			FAQ: []guideFAQ{
				{"Warum zeigt mein Test eine Liste als nicht erreichbar?", "Spamhaus und andere beantworten Abfragen über öffentliche Resolver wie 8.8.8.8 mit Fehlercodes statt mit einem Ergebnis. Betreiber sollten einen eigenen Resolver verwenden."},
				{"Reicht es, die Blacklists zu prüfen?", "Nein, sie sind ein Teil. Reverse-DNS, Authentifizierung und Inhalt gehören ebenso zur Zustellbarkeit."},
			},
		},
		EN: guideText{
			Title:       "Blacklist check: is my mail server IP listed? Causes and delisting",
			Description: "Check blacklists (DNSBL): Spamhaus, SpamCop, Barracuda and others, causes of listings and steps to delisting. With a free test of the sender IP.",
			H1:          "Blacklist check for your mail server IP",
			Lead:        "Blacklists (DNSBL) collect IP addresses that sent spam or malware. If your sending IP sits on a common list, many servers reject your mail or move it to the spam folder.",
			Sections: []guideSection{
				{Heading: "How the lookup works", Paragraphs: []string{
					"A DNSBL is a DNS zone. The receiver reverses the IP, appends the name of the list and asks the DNS server. An answer in the range 127.0.0.x means: listed.",
				}, Code: "203.0.113.25  ->  25.113.0.203.zen.spamhaus.org"},
				{Heading: "The main lists", Items: []string{
					"Spamhaus ZEN combines SBL, XBL and PBL. SBL and XBL stand for spam sources and compromised machines, PBL for address ranges that should not run mail servers.",
					"SpamCop (bl.spamcop.net) lists based on user complaints.",
					"Barracuda (b.barracudacentral.org) and further lists feed into many filters.",
				}},
				{Heading: "Why an IP gets listed", Items: []string{
					"A compromised mailbox or hacked server sends spam.",
					"An open relay or an insecure contact form is abused.",
					"The IP belongs to a consumer (dynamic) range or has a bad neighbour on a shared server.",
				}},
				{Heading: "Delisting", Items: []string{
					"Find and fix the cause: lock accounts, change passwords, close the holes.",
					"Then file a removal request on the list's website. Some lists remove entries on their own after a waiting period.",
					"For PBL entries send through the provider's relay or request a release from the provider.",
				}},
			},
			FAQ: []guideFAQ{
				{"Why does my test show a list as unreachable?", "Spamhaus and others answer queries from public resolvers such as 8.8.8.8 with error codes instead of a result. Operators should use their own resolver."},
				{"Is checking blacklists enough?", "No, they are one part. Reverse DNS, authentication and content belong to deliverability as well."},
			},
		},
	},
	{
		Slug: "reverse-dns", Updated: "2026-10-16", Icon: "bi-hdd-network",
		Related: []string{"blacklist", "deliverability", "spf"},
		DE: guideText{
			Title:       "Reverse-DNS (PTR) und HELO prüfen: so richtest du den Mailserver korrekt ein",
			Description: "Reverse-DNS, PTR-Record und HELO für Mailserver erklärt: Forward-confirmed rDNS, typische Fehler und wo du den PTR setzt. Mit kostenlosem Test.",
			H1:          "Reverse-DNS (PTR) und HELO prüfen",
			Lead:        "Empfänger-Server fragen zur IP des Absenders den Namen ab (Reverse-DNS) und prüfen, ob dieser Name wieder auf dieselbe IP zeigt. Fehlt das oder wirkt der Name generisch, steigt der Spam-Score.",
			Sections: []guideSection{
				{Heading: "Was geprüft wird", Items: []string{
					"Die sendende IP hat einen PTR-Record.",
					"Der PTR-Name löst per A- oder AAAA-Record wieder auf dieselbe IP auf (forward-confirmed reverse DNS).",
					"Der HELO/EHLO-Name im SMTP-Dialog ist ein voll qualifizierter Hostname, der zur IP gehört.",
					"Der PTR-Name wirkt wie ein dedizierter Mailserver, etwa mail.example.org.",
				}},
				{Heading: "Typische Fehler", Items: []string{
					"Der PTR trägt den automatischen Namen des Providers wie 203-0-113-25.dyn.provider.net. Filter erkennen solche Muster als Endkunden-IP.",
					"PTR und HELO nennen verschiedene Namen, die nicht zur IP passen.",
					"Der A-Record des PTR-Namens fehlt.",
				}},
				{Heading: "Wo setzt du den PTR?", Paragraphs: []string{
					"Den PTR pflegt der Besitzer des IP-Blocks, also dein Hosting-Anbieter oder Internetprovider. Du trägst ihn im Kundenbereich ein oder bittest den Support darum. Den passenden A-Record legst du in deiner eigenen DNS-Zone an.",
				}, Code: "dig -x 203.0.113.25 +short\ndig A mail.example.org +short"},
			},
			FAQ: []guideFAQ{
				{"Brauche ich auch einen PTR für IPv6?", "Ja. Sendet dein Server über IPv6, braucht diese Adresse einen PTR und einen AAAA-Record."},
				{"Muss der HELO-Name mit dem PTR identisch sein?", "Er sollte auf dieselbe IP zeigen und im Idealfall dem PTR entsprechen. So wirkt der Server stimmig."},
			},
		},
		EN: guideText{
			Title:       "Check reverse DNS (PTR) and HELO: set up your mail server correctly",
			Description: "Reverse DNS, PTR record and HELO for mail servers explained: forward-confirmed rDNS, typical mistakes and where to set the PTR. With a free test.",
			H1:          "Check reverse DNS (PTR) and HELO",
			Lead:        "Receiving servers look up the name for the sender's IP (reverse DNS) and check that this name points back to the same IP. If it is missing or looks generic, the spam score rises.",
			Sections: []guideSection{
				{Heading: "What is checked", Items: []string{
					"The sending IP has a PTR record.",
					"The PTR name resolves through an A or AAAA record to the same IP (forward-confirmed reverse DNS).",
					"The HELO/EHLO name in the SMTP dialogue is a fully qualified hostname that belongs to the IP.",
					"The PTR name looks like a dedicated mail server, such as mail.example.org.",
				}},
				{Heading: "Typical mistakes", Items: []string{
					"The PTR carries the provider's automatic name such as 203-0-113-25.dyn.provider.net. Filters recognise such patterns as consumer IPs.",
					"PTR and HELO name different hosts that do not fit the IP.",
					"The A record for the PTR name is missing.",
				}},
				{Heading: "Where to set the PTR", Paragraphs: []string{
					"The owner of the IP block maintains the PTR, which means your hosting provider or internet provider. You enter it in the customer area or ask support to do it. You create the matching A record in your own DNS zone.",
				}, Code: "dig -x 203.0.113.25 +short\ndig A mail.example.org +short"},
			},
			FAQ: []guideFAQ{
				{"Do I need a PTR for IPv6 as well?", "Yes. If your server sends over IPv6, that address needs a PTR and an AAAA record."},
				{"Does the HELO name have to equal the PTR?", "It should point to the same IP and ideally match the PTR. That makes the server look consistent."},
			},
		},
	},
	{
		Slug: "mail-tester-alternative", Updated: "2026-10-16", Icon: "bi-shuffle",
		Related: []string{"deliverability", "spam-score", "dmarc"},
		DE: guideText{
			Title:       "Mail-Tester-Alternative: kostenloser, verschlüsselter E-Mail-Test mit 68 Checks",
			Description: "sender.report als Alternative zu Mail-Tester: kostenloser Zustellbarkeitstest mit 68 Checks, Ende-zu-Ende-verschlüsselten Berichten, Mail-Simulator und eigenem Hosting.",
			H1:          "Eine Alternative zu Mail-Tester: sender.report",
			Lead:        "Wer die Zustellbarkeit einer Mail testen will, sucht oft ein Werkzeug wie mail-tester.com. sender.report beantwortet dieselbe Frage mit eigenen Schwerpunkten: Datenschutz, Tiefe der Prüfungen und die Möglichkeit, es selbst zu betreiben.",
			Sections: []guideSection{
				{Heading: "Das macht sender.report aus", Items: []string{
					"Die Nutzung ist anonym und kostenlos. Eine temporäre Mailbox entsteht automatisch.",
					"68 Prüfungen in fünf Bereichen: Authentifizierung, DNS und Infrastruktur, Spamfilter, Format und Inhalt sowie Header und Rohdaten.",
					"SPF, DKIM und DMARC werden gegen die tatsächliche Testmail geprüft. Befunde nennen Ursache und nächsten Schritt.",
					"Berichte sind Ende-zu-Ende-verschlüsselt. Den Schlüssel trägt nur dein Link.",
					"Nach einer DNS-Änderung fragt ein Klick alles neu ab und berechnet die Bewertung neu, ohne neue Testmail.",
					"Der Mail-Simulator bewertet bearbeiteten Quelltext sofort.",
					"Das Projekt ist Open Source und läuft als Docker-Image auf eigener Infrastruktur.",
				}},
				{Heading: "So testest du", Items: []string{
					"Rufe die Startseite auf und kopiere die angezeigte Testadresse.",
					"Sende eine Mail aus dem System, dessen Zustellbarkeit du prüfen willst, an diese Adresse.",
					"Öffne den Bericht und gehe die Befunde der Reihe nach durch.",
				}},
			},
			FAQ: []guideFAQ{
				{"Was kostet sender.report?", "Die Nutzung ist kostenlos."},
				{"Werden meine Testmails an Dritte weitergegeben?", "Nein. Sie werden nur für die Analyse verarbeitet, Ende-zu-Ende-verschlüsselt gespeichert und nach Ablauf der Aufbewahrungsfrist gelöscht."},
				{"Kann ich sender.report selbst betreiben?", "Ja, als einzelnes Docker-Image mit Web-Oberfläche, SMTP-Empfang und Datenbank."},
			},
		},
		EN: guideText{
			Title:       "A Mail-Tester alternative: free, encrypted email test with 68 checks",
			Description: "sender.report as an alternative to Mail-Tester: a free deliverability test with 68 checks, end-to-end encrypted reports, a mail simulator and self-hosting.",
			H1:          "An alternative to Mail-Tester: sender.report",
			Lead:        "Anyone who wants to test the deliverability of a message often looks for a tool like mail-tester.com. sender.report answers the same question with its own emphasis: privacy, depth of the checks and the option to run it yourself.",
			Sections: []guideSection{
				{Heading: "What sets sender.report apart", Items: []string{
					"Use is anonymous and free. A temporary mailbox is created automatically.",
					"68 checks in five areas: authentication, DNS and infrastructure, spam filters, format and content, and headers and raw data.",
					"SPF, DKIM and DMARC are verified against your actual test mail. Findings name the cause and the next step.",
					"Reports are end-to-end encrypted. Only your link carries the key.",
					"After a DNS change, one click queries everything again and recalculates the score, without a new test mail.",
					"The mail simulator scores edited source immediately.",
					"The project is open source and runs as a Docker image on your own infrastructure.",
				}},
				{Heading: "How to test", Items: []string{
					"Open the start page and copy the test address it shows.",
					"Send a message from the system whose deliverability you want to check to that address.",
					"Open the report and go through the findings in order.",
				}},
			},
			FAQ: []guideFAQ{
				{"What does sender.report cost?", "Use is free."},
				{"Are my test mails shared with third parties?", "No. They are processed only for the analysis, stored end-to-end encrypted and deleted when the retention period ends."},
				{"Can I run sender.report myself?", "Yes, as a single Docker image with web interface, SMTP reception and database."},
			},
		},
	},
}
