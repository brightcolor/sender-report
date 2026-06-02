# Ende-zu-Ende-Verschlüsselung der Mailbox-Inhalte

> Status: **Phase 1 – kryptografisches Fundament** (dieses Dokument + `internal/sealedbox` + `static/crypto.js`).
> Die Verdrahtung in Schema, SMTP-Empfang und Client-Rendering folgt in Phase 2–4 (siehe [Roadmap](#roadmap)).

## Ziel

Mailbox-Inhalte (Rohmail, Header, Betreff, Body, Report-Details) sollen so gespeichert
werden, dass **der Server-Betreiber sie nicht lesen kann** – auch nicht mit vollem
Datenbank- und Dateisystemzugriff. Lesbar sind die Daten ausschließlich für den Besitzer
des Mailbox-Links.

## Warum asymmetrische Kryptografie zwingend ist

Eine Testmail trifft per **SMTP** ein. In diesem Moment ist **kein Browser des Nutzers
anwesend** – nur der Server verarbeitet die Mail. Symmetrische Verschlüsselung (ein
geheimer Schlüssel, den Server und Client teilen) scheidet damit aus: Hätte der Server den
Schlüssel zum Verschlüsseln, könnte er auch entschlüsseln – der Betreiber käme an die Daten.

Die Lösung ist **hybride Public-Key-Verschlüsselung**:

- Der Browser erzeugt ein **X25519-Schlüsselpaar**.
- Der **öffentliche Schlüssel** geht an den Server.
- Der **private Schlüssel** verlässt den Browser nie – er steckt im Mailbox-Token (URL).
- Beim Mail-Eingang verschlüsselt der Server mit dem **öffentlichen** Schlüssel. Damit kann
  er ver-, aber **nicht entschlüsseln**.
- Nur der Browser mit dem privaten Schlüssel (Token) kann die Daten wieder lesbar machen.

## Der Token ist der Schlüssel

Statt eines zufälligen Identifiers **ist der Token das geheime Schlüsselmaterial**:

```
Token  = base64url( 0x01 ‖ secret[32] )           // ~45 Zeichen, steht in der URL
secret = X25519-Privatschlüssel (32 zufällige Bytes)
public = X25519.base(secret)                       // an den Server übermittelt
ident  = base32lower( SHA-256("senderreport-id-v1" ‖ public)[:10] )   // 16 Zeichen
```

- **`ident`** ist der lokale Teil der E-Mail-Adresse (`ident@domain`) **und** der
  Datenbank-Schlüssel. Er ist ein **Hash des öffentlichen** Schlüssels – aus `ident`
  lässt sich weder der öffentliche noch der private Schlüssel zurückrechnen.
- Der Server speichert nur `ident` + `public`. Er kann beim Anlegen prüfen, dass
  `ident == H(public)` (Schutz gegen gefälschte Identifier).
- Der **`secret`-Teil existiert ausschließlich im Token** – also in der URL und im
  `localStorage` des Browsers. Geht der Link verloren, sind die Daten unwiederbringlich
  weg (das ist bei einem „kein Account"-Tool gewollt, kein Passwort-Recovery möglich).

## Verschlüsselungsverfahren (ECIES-Hybrid)

Sealed-Box-Konstruktion, identisch in Go (`internal/sealedbox`) und JS (`static/crypto.js`):

```
seal(plaintext, recipientPublic R):
  (e_sk, e_pk) = X25519-Schlüsselpaar (ephemer, pro Nachricht neu)
  shared = X25519(e_sk, R)
  key    = HKDF-SHA256(ikm=shared, salt=e_pk‖R, info="senderreport-content-v1", len=32)
  nonce  = 12 zufällige Bytes
  ct     = AES-256-GCM.seal(key, nonce, plaintext, aad=e_pk)     // enthält 16-Byte-Tag
  return  "MPE1" ‖ e_pk[32] ‖ nonce[12] ‖ ct

open(blob, recipientSecret r):
  parse  magic, e_pk, nonce, ct
  shared = X25519(r, e_pk)
  R      = X25519.base(r)
  key    = HKDF-SHA256(shared, salt=e_pk‖R, info="senderreport-content-v1", 32)
  return AES-256-GCM.open(key, nonce, ct, aad=e_pk)
```

**Eigenschaften**

- **Anonymer Absender:** Pro Nachricht wird ein ephemeres Schlüsselpaar erzeugt; der
  Server-Betreiber erfährt nicht, „wer" verschlüsselt hat (er selbst tut es, ohne Geheimnis).
- **Forward Secrecy gegenüber dem Server:** Der ephemere Privatschlüssel `e_sk` wird sofort
  verworfen. Selbst eine spätere Kompromittierung des Servers gibt die Klartexte nicht preis.
- **Integrität:** AES-GCM authentifiziert den Inhalt; `e_pk` ist als AAD gebunden.
- **Schlüsselbindung:** Salt enthält `e_pk‖R`, der gemeinsame Schlüssel ist eindeutig an
  beide Public Keys gebunden.

### Eingesetzte Primitive

| Schicht           | Go (Server)                          | Browser (Client)                         |
|-------------------|--------------------------------------|------------------------------------------|
| X25519            | `golang.org/x/crypto/curve25519`     | TweetNaCl `nacl.scalarMult[.base]`       |
| HKDF-SHA256       | `golang.org/x/crypto/hkdf`           | WebCrypto `deriveBits({name:'HKDF'})`    |
| AES-256-GCM       | `crypto/aes` + `crypto/cipher`       | WebCrypto `encrypt/decrypt('AES-GCM')`   |
| Zufall            | `crypto/rand`                        | `crypto.getRandomValues`                 |

Alle Verfahren folgen offenen Standards (RFC 7748, RFC 5869, NIST SP 800-38D); bei
identischen Eingabe-Bytes liefern beide Seiten identische Ergebnisse. Ein in Go erzeugter
**Testvektor** (`sealedbox_test.go`, `TestVector`) wird im Browser per `cryptoSelfTest()`
gegengeprüft.

## Was wird verschlüsselt, was bleibt im Klartext

| Feld                                   | Speicherung      | Begründung                                    |
|----------------------------------------|------------------|-----------------------------------------------|
| Rohmail (`raw_source`)                 | **verschlüsselt**| Der eigentliche, vollständige Mailinhalt      |
| Header-Block, Betreff, Body, Links     | **verschlüsselt**| Inhalt der Mail                               |
| Report-JSON (Checks inkl. Details)     | **verschlüsselt**| Enthält Header-Werte, Domains etc.            |
| `ident`, `public_key`                  | Klartext         | Routing/Lookup, keine Inhaltsdaten            |
| `score` (0–10)                         | Klartext         | Reine Zahl für die Mailbox-Liste              |
| Zeitstempel, Größe                     | Klartext         | Betrieb, Cleanup, Limits                      |
| `remote_ip`, `helo`                    | Klartext\*       | SMTP-Transportdaten, dem Server ohnehin bekannt |

\* Transport-Metadaten sieht der Server beim Empfang systembedingt; sie dienen Abuse-Schutz.
Optional können auch sie verschlüsselt werden (Roadmap, Phase 4).

## Roadmap

- **Phase 1 – Fundament (dieses Commit):** Krypto-Kern in Go + JS, Testvektor, Doku.
- **Phase 2 – Schema & Erstellung:** `mailboxes.public_key`, client-seitige Schlüssel- und
  Identifier-Erzeugung, neuer Create-Flow (`POST /api/mailboxes` mit `{identifier, public_key}`).
- **Phase 3 – Empfang & Speicherung:** SMTP-Pfad verschlüsselt Rohmail/Report mit dem
  Public Key; Spalten werden Ciphertext-Blobs.
- **Phase 4 – Client-Rendering:** Mailbox-Liste, Report-Seite und Rohansicht entschlüsseln
  und rendern im Browser; Server liefert nur Ciphertext + Klartext-Score.

## Grenzen / ehrliche Einordnung

- **Analyse braucht Klartext:** Zum Prüfen von SPF/DKIM/DMARC/Spam muss der Server die Mail
  beim Empfang **kurz im RAM** im Klartext verarbeiten. Verschlüsselt wird erst **bei der
  Speicherung**. Ein Angreifer mit Live-Zugriff auf den Prozessspeicher zum Empfangszeitpunkt
  ist außerhalb dieses Modells.
- **Kein Recovery:** Linkverlust = Datenverlust. Beabsichtigt.
- **Metadaten:** Existenz einer Mailbox, Zeitpunkte, Score und Transport-IP bleiben (sofern
  nicht Phase 4) sichtbar.
- **Vertrauen in den ausgelieferten Code:** Da der Server den JS-Client ausliefert, muss man
  ihm zum Zeitpunkt des Ladens vertrauen. Das ist die prinzipielle Grenze jeder
  Web-E2E-Lösung (kein TOFU/Signaturpinning im Browser).
