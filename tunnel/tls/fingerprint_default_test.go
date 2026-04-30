package tls

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestDefaultFingerprintIsChrome guards the `fingerprint` config default.
// The default has been Chrome since the feature was introduced; flipping it
// silently would change the on-the-wire ClientHello of every existing
// deployment that relies on the unset default. P1-4 of the 2026 hardening plan
// requires this test to fail loudly when the default changes.
func TestDefaultFingerprintIsChrome(t *testing.T) {
	id, err := resolveFingerprint("")
	if err != nil {
		t.Fatalf("resolveFingerprint(\"\") returned error: %v", err)
	}
	if id != utls.HelloChrome_Auto {
		t.Fatalf("default fingerprint changed: got %v, want HelloChrome_Auto", id)
	}
}

// TestResolveFingerprintKnownNames documents the full set of accepted
// fingerprint names. Adding or removing a value here must be reflected in
// docs/content/advance/tls.md.
func TestResolveFingerprintKnownNames(t *testing.T) {
	cases := map[string]utls.ClientHelloID{
		"chrome":     utls.HelloChrome_Auto,
		"CHROME":     utls.HelloChrome_Auto, // case-insensitive
		"ios":        utls.HelloIOS_Auto,
		"firefox":    utls.HelloFirefox_Auto,
		"edge":       utls.HelloEdge_Auto,
		"safari":     utls.HelloSafari_Auto,
		"360browser": utls.Hello360_Auto,
		"qqbrowser":  utls.HelloQQ_Auto,
	}
	for name, want := range cases {
		got, err := resolveFingerprint(name)
		if err != nil {
			t.Errorf("resolveFingerprint(%q) error: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("resolveFingerprint(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestResolveFingerprintRejectsUnknown(t *testing.T) {
	if _, err := resolveFingerprint("netscape"); err == nil {
		t.Fatal("expected error for unknown fingerprint, got nil")
	}
}
