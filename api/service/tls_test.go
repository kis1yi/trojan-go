package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestTLSCertificate(t *testing.T, algorithm x509.PublicKeyAlgorithm, usage x509.ExtKeyUsage) (certPath, keyPath string) {
	t.Helper()
	var key crypto.Signer
	var err error
	switch algorithm {
	case x509.RSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case x509.ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		t.Fatalf("unsupported test key algorithm: %v", algorithm)
	}
	if err != nil {
		t.Fatalf("generate test TLS key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate test certificate serial: %v", err)
	}
	// Derive validity from the current time so fixtures cannot expire between runs.
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if algorithm == x509.RSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create test TLS certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test TLS key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "certificate.crt")
	keyPath = filepath.Join(dir, "private.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		t.Fatalf("write test TLS certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write test TLS key: %v", err)
	}
	return certPath, keyPath
}
