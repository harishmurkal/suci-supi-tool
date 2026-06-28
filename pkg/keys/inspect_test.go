package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

func TestInferCompositeProfileFromFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		scheme   suciutil.SchemeID
		profile  string
		ok       bool
	}{
		{
			name:     "profile d",
			filename: "hn-key-1-profile-d-mlkem.pem",
			scheme:   suciutil.SchemeProfileD,
			profile:  "D (Hybrid ML-KEM-768+X25519)",
			ok:       true,
		},
		{
			name:     "profile e",
			filename: "hn-key-2-profile-e-x25519.pem",
			scheme:   suciutil.SchemeProfileE,
			profile:  "E (Nested Hybrid ML-KEM-768+X25519)",
			ok:       true,
		},
		{
			name:     "profile f",
			filename: "hn-key-3-profile-f-mlkem.pub.pem",
			scheme:   suciutil.SchemeProfileF,
			profile:  "F (Wrapper Hybrid ML-KEM-768+X25519)",
			ok:       true,
		},
		{
			name:     "non composite",
			filename: "hn-key-4-profile-a.pem",
			scheme:   suciutil.SchemeNullScheme,
			profile:  "",
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScheme, gotProfile, gotOK := inferCompositeProfileFromFilename(tt.filename)
			if gotOK != tt.ok {
				t.Fatalf("ok mismatch: got %v want %v", gotOK, tt.ok)
			}
			if gotScheme != tt.scheme {
				t.Fatalf("scheme mismatch: got %v want %v", gotScheme, tt.scheme)
			}
			if gotProfile != tt.profile {
				t.Fatalf("profile mismatch: got %q want %q", gotProfile, tt.profile)
			}
		})
	}
}

func TestExtractKeyIDFromFilenameSupportsCompositeProfiles(t *testing.T) {
	tests := []struct {
		filename string
		wantID   int
	}{
		{filename: "hn-key-1-profile-a.pem", wantID: 1},
		{filename: "hn-key-7-profile-d-mlkem.pem", wantID: 7},
		{filename: "hn-key-8-profile-e-x25519.pem", wantID: 8},
		{filename: "hn-key-9-profile-f-mlkem.pub.pem", wantID: 9},
		{filename: "hn-key-10-profile-f-x25519.pub.pem", wantID: 10},
		{filename: "not-a-key-file.pem", wantID: -1},
	}

	for _, tt := range tests {
		got := extractKeyIDFromFilename(tt.filename)
		if got != tt.wantID {
			t.Fatalf("extractKeyIDFromFilename(%q) = %d, want %d", tt.filename, got, tt.wantID)
		}
	}
}

func TestInspectKeyCompositeFilenameHints(t *testing.T) {
	tmpDir := t.TempDir()

	x25519File := filepath.Join(tmpDir, "hn-key-5-profile-e-x25519.pem")
	if err := os.WriteFile(x25519File, makePEMBlock(t, "X25519 PRIVATE KEY", 32), 0600); err != nil {
		t.Fatalf("failed to write x25519 composite file: %v", err)
	}

	xInfo, err := InspectKey(&InspectConfig{
		KeyFile:      x25519File,
		ShowPublic:   true,
		ShowPrivate:  false,
		OutputFormat: "text",
	})
	if err != nil {
		t.Fatalf("InspectKey x25519 failed: %v", err)
	}
	if xInfo.Error != "" {
		t.Fatalf("unexpected x25519 inspect error: %s", xInfo.Error)
	}
	if xInfo.Scheme != suciutil.SchemeProfileE {
		t.Fatalf("unexpected scheme for x25519 file: got %v want %v", xInfo.Scheme, suciutil.SchemeProfileE)
	}
	if xInfo.KeyID != 5 {
		t.Fatalf("unexpected key id for x25519 file: got %d want 5", xInfo.KeyID)
	}
	if !strings.Contains(xInfo.Profile, "Nested Hybrid") {
		t.Fatalf("unexpected profile label: %q", xInfo.Profile)
	}
	if xInfo.Fingerprint == "" || xInfo.PublicKeyHex == "" {
		t.Fatalf("expected derived public key data for x25519 private key")
	}

	mlkemFile := filepath.Join(tmpDir, "hn-key-3-profile-f-mlkem.pem")
	if err := os.WriteFile(mlkemFile, makePEMBlock(t, "ML-KEM-768 PRIVATE KEY", 2400), 0600); err != nil {
		t.Fatalf("failed to write mlkem composite file: %v", err)
	}

	mlInfo, err := InspectKey(&InspectConfig{
		KeyFile:      mlkemFile,
		ShowPublic:   true,
		ShowPrivate:  false,
		OutputFormat: "text",
	})
	if err != nil {
		t.Fatalf("InspectKey mlkem failed: %v", err)
	}
	if mlInfo.Error != "" {
		t.Fatalf("unexpected mlkem inspect error: %s", mlInfo.Error)
	}
	if mlInfo.Scheme != suciutil.SchemeProfileF {
		t.Fatalf("unexpected scheme for mlkem file: got %v want %v", mlInfo.Scheme, suciutil.SchemeProfileF)
	}
	if mlInfo.KeyID != 3 {
		t.Fatalf("unexpected key id for mlkem file: got %d want 3", mlInfo.KeyID)
	}
	if !strings.Contains(mlInfo.Profile, "Wrapper Hybrid") {
		t.Fatalf("unexpected profile label: %q", mlInfo.Profile)
	}
	if mlInfo.PublicKeyHex != "" {
		t.Fatalf("did not expect derived public key for ML-KEM private component")
	}
}

func TestInferCompositeProfileFromFilename_ProfileG(t *testing.T) {
	gotScheme, gotProfile, gotOK := inferCompositeProfileFromFilename("hn-key-1-profile-g.json")
	if !gotOK {
		t.Fatalf("expected profile-g inference to match")
	}
	if gotScheme != suciutil.SchemeProfileG {
		t.Fatalf("scheme mismatch: got %v want %v", gotScheme, suciutil.SchemeProfileG)
	}
	if !strings.Contains(gotProfile, "Symmetric") {
		t.Fatalf("unexpected profile label: %q", gotProfile)
	}
}

func TestInspectKey_ProfileG_JSON_MainAndSubscribers(t *testing.T) {
	tmpDir := t.TempDir()
	mainFile := filepath.Join(tmpDir, "hn-key-12-profile-g.json")
	subsFile := filepath.Join(tmpDir, "hn-key-12-profile-g-subscribers.json")

	if err := os.WriteFile(mainFile, []byte(`{"profile":"g","security_level":3,"hn_symmetric_key_hex":"00112233445566778899aabbccddeeff","window_size_seconds":3600}`), 0600); err != nil {
		t.Fatalf("write main profile-g json: %v", err)
	}
	if err := os.WriteFile(subsFile, []byte(`{"subscribers":{"0011223344":"00112233445566778899aabbccddeeff"}}`), 0600); err != nil {
		t.Fatalf("write subscribers profile-g json: %v", err)
	}

	mainInfo, err := InspectKey(&InspectConfig{
		KeyFile:      mainFile,
		ShowPublic:   false,
		ShowPrivate:  true,
		OutputFormat: "text",
	})
	if err != nil {
		t.Fatalf("InspectKey profile-g main failed: %v", err)
	}
	if mainInfo.Error != "" {
		t.Fatalf("unexpected profile-g main inspect error: %s", mainInfo.Error)
	}
	if mainInfo.Scheme != suciutil.SchemeProfileG {
		t.Fatalf("unexpected scheme for profile-g main: got %v want %v", mainInfo.Scheme, suciutil.SchemeProfileG)
	}
	if mainInfo.KeyID != 12 {
		t.Fatalf("unexpected key id for profile-g main: got %d want 12", mainInfo.KeyID)
	}
	if !strings.Contains(mainInfo.Profile, "Symmetric") {
		t.Fatalf("unexpected profile label for profile-g main: %q", mainInfo.Profile)
	}
	if mainInfo.PrivateKeyHex == "" {
		t.Fatalf("expected private key hex for profile-g main with --show-private")
	}

	subsInfo, err := InspectKey(&InspectConfig{
		KeyFile:      subsFile,
		ShowPublic:   false,
		ShowPrivate:  false,
		OutputFormat: "text",
	})
	if err != nil {
		t.Fatalf("InspectKey profile-g subscribers failed: %v", err)
	}
	if subsInfo.Error != "" {
		t.Fatalf("unexpected profile-g subscribers inspect error: %s", subsInfo.Error)
	}
	if subsInfo.Scheme != suciutil.SchemeProfileG {
		t.Fatalf("unexpected scheme for profile-g subscribers: got %v want %v", subsInfo.Scheme, suciutil.SchemeProfileG)
	}
	if subsInfo.KeyID != 12 {
		t.Fatalf("unexpected key id for profile-g subscribers: got %d want 12", subsInfo.KeyID)
	}
	if !strings.Contains(subsInfo.Algorithm, "Subscriber Kmaster Map") {
		t.Fatalf("unexpected algorithm label for profile-g subscribers: %q", subsInfo.Algorithm)
	}
}
