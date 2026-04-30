package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadKeyPairEncryptedPEM verifies that loadKeyPair can load a legacy
// RFC 1423 AES-encrypted PKCS#1 PEM key with the correct password and that
// using the wrong password produces a wrapped error. This regression test
// covers two historical bugs in loadKeyPair:
//   - the inverted "if err == nil" check that treated successful decryption
//     as failure, and
//   - the DER-vs-PEM mismatch when handing the decrypted key to
//     tls.X509KeyPair.
func TestLoadKeyPairEncryptedPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	const password = "trojan-go-test"

	// Generate a self-signed cert + matching RSA key.
	certPEM, keyDER := newSelfSignedRSA(t)
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Encrypt the key with the legacy PEM password format.
	encBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		"RSA PRIVATE KEY",
		keyDER,
		[]byte(password),
		x509.PEMCipherAES256,
	)
	if err != nil {
		t.Fatalf("EncryptPEMBlock: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(encBlock), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	t.Run("correct password", func(t *testing.T) {
		kp, err := loadKeyPair(keyPath, certPath, password)
		if err != nil {
			t.Fatalf("loadKeyPair returned error: %v", err)
		}
		if kp == nil || len(kp.Certificate) == 0 || kp.PrivateKey == nil {
			t.Fatalf("loadKeyPair returned incomplete certificate: %+v", kp)
		}
		if kp.Leaf == nil {
			t.Fatalf("loadKeyPair did not parse Leaf")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		_, err := loadKeyPair(keyPath, certPath, "wrong-password")
		if err == nil {
			t.Fatalf("expected error for wrong password")
		}
		if !strings.Contains(err.Error(), "decrypt") {
			t.Fatalf("expected decrypt error, got: %v", err)
		}
	})
}

func newSelfSignedRSA(t *testing.T) (certPEM, keyDER []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := selfSignedTemplate()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER = x509.MarshalPKCS1PrivateKey(key)
	return certPEM, keyDER
}

func selfSignedTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "trojan-go-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
}
