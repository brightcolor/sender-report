// Package tlscert erzeugt oder lädt ein selbst-signiertes TLS-Zertifikat.
// Das Zertifikat wird beim ersten Start generiert und im Data-Verzeichnis
// gespeichert. Folgestarts laden das vorhandene Cert — keine Erneuerung nötig
// (10-Jahres-Laufzeit). MTAs nutzen opportunistisches STARTTLS ohne
// Zertifikatsprüfung, daher ist ein self-signed Cert für diesen Zweck vollständig.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	certFile = "smtp.crt"
	keyFile  = "smtp.key"
)

// EnsureAndLoad stellt sicher, dass ein TLS-Zertifikat im dataDir existiert,
// erzeugt es bei Bedarf, und gibt eine fertige tls.Config zurück.
func EnsureAndLoad(dataDir, domain string, logger interface{ Printf(string, ...any) }) (*tls.Config, error) {
	certPath := filepath.Join(dataDir, certFile)
	keyPath  := filepath.Join(dataDir, keyFile)

	// Beide Dateien vorhanden → laden.
	if _, err := os.Stat(certPath); err == nil {
		if _, err2 := os.Stat(keyPath); err2 == nil {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, fmt.Errorf("tlscert: vorhandenes Zertifikat ungültig: %w", err)
			}
			logger.Printf("tlscert: vorhandenes SMTP-Zertifikat geladen (%s)", certPath)
			return tlsConfig(cert), nil
		}
	}

	// Noch nicht vorhanden → neu generieren.
	logger.Printf("tlscert: kein SMTP-Zertifikat gefunden, generiere self-signed Cert für '%s'…", domain)
	cert, err := generate(domain, certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("tlscert: Generierung fehlgeschlagen: %w", err)
	}
	logger.Printf("tlscert: SMTP-Zertifikat generiert (%s), gültig 10 Jahre", certPath)
	return tlsConfig(cert), nil
}

func tlsConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

func generate(domain, certPath, keyPath string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Sender-Report"},
		},
		DNSNames:              []string{domain},
		NotBefore:             now.Add(-time.Minute), // clock-skew-Toleranz
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// PEM-Dateien schreiben (600-Berechtigungen für den Key).
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}
